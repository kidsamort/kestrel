//! Paged listing, counters and the plaintext search projection.
//!
//! Listing at vault scale cannot decrypt every row per keystroke, so `items`
//! carries a small plaintext projection beside the ciphertext:
//!
//! * `search_text` — case-folded title, tags, urls, notes and the label/value
//!   of every **non-sensitive** field, joined by newlines;
//! * `category` — the bounded [`Category`] label, needed for per-category counts
//!   and filtering;
//! * `favorite` — a single boolean flag, needed for the favourite filter and
//!   count.
//!
//! Nothing else leaves the blob. [`search_text`] is the only builder of the
//! searchable column and it drops every field marked `sensitive` as well as
//! every secret field kind, so a password can never become searchable even if a
//! caller clears the flag. The `data` column stays the source of truth: the
//! projection is rebuilt from it on every save and can be discarded at any
//! time.
//!
//! Legacy rows written before the projection existed have `search_text IS
//! NULL`; [`Store::backfill_search_index`] indexes them on unlock, when the
//! master key is available to read the labels.

use super::{Store, StoreError, VaultMeta};
use crate::crypto::{self, SymKey};
use crate::model::{Item, ItemSummary};
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter};
use serde::Serialize;
use std::collections::BTreeMap;

/// Field kinds that are secret by construction. The `sensitive` flag is the
/// first gate; this list catches data whose flag was lost in a foreign import.
const SECRET_KINDS: &[&str] = &[
    "password",
    "apiSecret",
    "cvv",
    "pin",
    "creditCardNumber",
    "sshPrivateKey",
    "totpSecret",
    // A seed phrase is a kind, not just a flag: an imported item could carry
    // the value with `sensitive` cleared, and the projection must still refuse
    // to index a wallet's recovery words.
    "seedPhrase",
];

/// A page of live item summaries plus the total number of rows the same filter
/// matches, so the caller can render a pager without a second query.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub items: Vec<ItemSummary>,
    pub total: usize,
}

/// Vault-wide counters from one grouped query: live items (per category, and
/// overall), live favourites and trashed rows.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    /// Live items in the vault.
    pub total: i64,
    /// Live items flagged favourite.
    pub favorites: i64,
    /// Items in the trash.
    pub trash: i64,
    /// Live items per category, keyed by `Category::as_str`.
    pub categories: BTreeMap<String, i64>,
}

/// Plaintext search projection of one item.
///
/// This is the single gate between item content and the `items.search_text`
/// column: it takes the title, the tags, the urls, the notes and the label and
/// value of non-sensitive fields, and nothing else. Sensitive fields and
/// password-like kinds are skipped before their value is ever read, and
/// `totp_secret` is never consulted.
pub fn search_text(item: &Item) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(4 + item.fields.len() * 2);
    parts.push(item.title.as_str());
    parts.extend(item.tags.iter().map(String::as_str));
    parts.extend(item.urls.iter().map(String::as_str));
    parts.push(item.notes.as_str());
    for field in &item.fields {
        if field.sensitive || SECRET_KINDS.contains(&field.kind.as_str()) {
            continue;
        }
        parts.push(field.label.as_str());
        parts.push(field.value.as_str());
    }
    parts.join("\n").to_lowercase()
}

/// Escape the `LIKE` wildcards so a needle of `100%` searches for the literal
/// text instead of matching everything.
fn escape_like(needle: &str) -> String {
    let mut escaped = String::with_capacity(needle.len());
    for ch in needle.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

fn bound(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl Store {
    /// One page of live items with the total matching count.
    ///
    /// `query` is matched against the plaintext projection, so an empty search
    /// decrypts only the requested page. Filtering, ordering, `LIMIT`/`OFFSET`
    /// and the `COUNT(*)` all run in SQLite; no row outside the page is read.
    ///
    /// The seven arguments mirror the filter surface one-to-one; folding them
    /// into a struct would only move the same list to every call site.
    #[allow(clippy::too_many_arguments)]
    pub fn list_page(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        query: &str,
        category: Option<&str>,
        favorites_only: bool,
        limit: usize,
        offset: usize,
    ) -> Result<Page, StoreError> {
        let keys = self.item_keys(master, meta)?;
        let needle = query.to_lowercase();

        let mut filter = String::from("vault_uuid = ? AND deleted_at IS NULL");
        let mut args: Vec<Value> = vec![meta.vault_uuid.clone().into()];
        if let Some(category) = category {
            filter.push_str(" AND category = ?");
            args.push(category.to_string().into());
        }
        if favorites_only {
            filter.push_str(" AND favorite = 1");
        }
        if !needle.is_empty() {
            filter.push_str(" AND search_text LIKE ? ESCAPE '\\'");
            args.push(format!("%{}%", escape_like(&needle)).into());
        }

        let total: i64 = self.conn.query_row(
            &format!("SELECT COUNT(*) FROM items WHERE {filter}"),
            params_from_iter(args.iter()),
            |row| row.get(0),
        )?;

        // Ordering matches the unpaged `list`: favourites first, then the
        // case-folded title. `search_text` starts with the folded title, so
        // this is the old title order without decrypting a single row.
        let sql = format!(
            "SELECT item_uuid, version, data FROM items WHERE {filter}
             ORDER BY favorite DESC, COALESCE(search_text, '') ASC, item_uuid ASC
             LIMIT ? OFFSET ?"
        );
        let mut page_args = args;
        page_args.push(bound(limit).into());
        page_args.push(bound(offset).into());

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(page_args.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut items = Vec::new();
        for row in rows {
            let (id, version, blob) = row?;
            let aad = Self::version_aad(meta, &id, version);
            let plain = crypto::decrypt(keys.for_item(&id), &aad, &blob)?;
            items.push(serde_json::from_slice::<Item>(&plain)?.summary());
        }
        Ok(Page {
            items,
            total: usize::try_from(total).unwrap_or(0),
        })
    }

    /// Per-category live totals, live favourites and the trash size in one
    /// grouped query against the projection. No blob is read.
    pub fn counts(&self, meta: &VaultMeta) -> Result<Counts, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT category,
                    SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END),
                    SUM(CASE WHEN deleted_at IS NULL AND favorite = 1 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN deleted_at IS NOT NULL THEN 1 ELSE 0 END)
             FROM items WHERE vault_uuid = ?1 GROUP BY category",
        )?;
        let rows = stmt.query_map(params![meta.vault_uuid], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut counts = Counts::default();
        for row in rows {
            let (category, live, favorites, trash) = row?;
            counts.total += live;
            counts.favorites += favorites;
            counts.trash += trash;
            // A category whose rows are all in the trash has no live bucket, and
            // a legacy row that was never backfilled has no label yet; neither
            // should create a zero entry.
            if live > 0 {
                if let Some(category) = category.filter(|label| !label.is_empty()) {
                    *counts.categories.entry(category).or_insert(0) += live;
                }
            }
        }
        Ok(counts)
    }

    /// Index every row that predates the projection, across every vault of the
    /// account, then leave indexed rows alone. Runs on unlock: the blobs can
    /// only be read with the master key, and a row written by a current build
    /// always has a `search_text`.
    pub(crate) fn backfill_search_index(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
    ) -> Result<usize, StoreError> {
        let vault_uuids: Vec<String> = {
            let mut stmt = self.conn.prepare(
                "SELECT DISTINCT vault_uuid FROM items
                 WHERE account_uuid = ?1 AND search_text IS NULL
                 ORDER BY vault_uuid",
            )?;
            let rows = stmt.query_map(params![meta.account_uuid], |row| row.get::<_, String>(0))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            out
        };
        if vault_uuids.is_empty() {
            return Ok(0);
        }

        let tx = self.conn.unchecked_transaction()?;
        let mut indexed = 0usize;
        for vault_uuid in vault_uuids {
            let scope = VaultMeta {
                vault_uuid,
                ..meta.clone()
            };
            let keys = self.item_keys(master, &scope)?;
            let rows: Vec<(String, i64, Vec<u8>)> = {
                let mut stmt = self.conn.prepare(
                    "SELECT item_uuid, version, data FROM items
                     WHERE vault_uuid = ?1 AND search_text IS NULL ORDER BY item_uuid",
                )?;
                let mapped = stmt.query_map(params![scope.vault_uuid], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })?;
                let mut out = Vec::new();
                for row in mapped {
                    out.push(row?);
                }
                out
            };
            for (item_uuid, version, blob) in rows {
                let aad = Self::version_aad(&scope, &item_uuid, version);
                let plain = crypto::decrypt(keys.for_item(&item_uuid), &aad, &blob)?;
                let item: Item = serde_json::from_slice(&plain)?;
                self.conn.execute(
                    "UPDATE items SET search_text = ?3, category = ?4, favorite = ?5
                     WHERE vault_uuid = ?1 AND item_uuid = ?2",
                    params![
                        scope.vault_uuid,
                        item_uuid,
                        search_text(&item),
                        item.category.as_str(),
                        if item.favorite { 1i64 } else { 0i64 },
                    ],
                )?;
                indexed += 1;
            }
        }
        tx.commit()?;
        Ok(indexed)
    }
}
