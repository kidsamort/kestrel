//! Item history: list archived versions, read one back, and restore it.
//!
//! Versions are the ciphertext blobs `Store::save_item` supersedes on every
//! save. Archiving re-seals the blob with a history-specific AAD (same item,
//! same version), so reading one proves it is exactly what was archived and a
//! history blob can never be replayed as the live item. Restoring never
//! rewrites history in place — it saves the old content as a brand-new
//! version, archiving the current one.

use crate::crypto;
use crate::crypto::SymKey;
use crate::model::Item;
use crate::session::{VaultError, VaultState};
use crate::store::{Store, StoreError, VaultMeta};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionSummary {
    pub version: i64,
    pub archived_at: i64,
    pub title: String,
    pub field_count: usize,
}

fn decrypt_version(
    store: &Store,
    master: &SymKey,
    meta: &VaultMeta,
    item_id: &str,
    version: i64,
    blob: &[u8],
) -> Result<Item, VaultError> {
    let key = store.sealing_key(master, meta, item_id)?;
    let aad = Store::history_aad(meta, item_id, version);
    let plain = crypto::decrypt(&key, &aad, blob).map_err(StoreError::from)?;
    let item = serde_json::from_slice::<Item>(&plain).map_err(StoreError::from)?;
    Ok(item)
}

fn item_exists(store: &Store, meta: &VaultMeta, item_id: &str) -> Result<bool, VaultError> {
    let exists: bool = store
        .conn()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM items WHERE vault_uuid = ?1 AND item_uuid = ?2)",
            params![meta.vault_uuid, item_id],
            |r| r.get(0),
        )
        .map_err(StoreError::from)?;
    Ok(exists)
}

impl VaultState {
    pub fn history_list(&self, item_id: &str) -> Result<Vec<VersionSummary>, VaultError> {
        self.touch();
        self.with_session(|store, master, meta| {
            if !item_exists(store, meta, item_id)? {
                return Err(VaultError::NotFound);
            }
            let mut stmt = store
                .conn()
                .prepare(
                    "SELECT version, archived_at, data FROM item_versions
                     WHERE item_uuid = ?1 AND vault_uuid = ?2
                     ORDER BY version DESC",
                )
                .map_err(StoreError::from)?;
            let rows = stmt
                .query_map(params![item_id, meta.vault_uuid], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                })
                .map_err(StoreError::from)?;
            let mut versions = Vec::new();
            for row in rows {
                let (version, archived_at, blob) = row.map_err(StoreError::from)?;
                let item = decrypt_version(store, master, meta, item_id, version, &blob)?;
                versions.push(VersionSummary {
                    version,
                    archived_at,
                    title: item.title,
                    field_count: item.fields.len(),
                });
            }
            Ok(versions)
        })
    }

    pub fn history_get(&self, item_id: &str, version: i64) -> Result<Item, VaultError> {
        self.touch();
        self.with_session(|store, master, meta| {
            let row: Option<Vec<u8>> = store
                .conn()
                .query_row(
                    "SELECT data FROM item_versions
                     WHERE item_uuid = ?1 AND vault_uuid = ?2 AND version = ?3",
                    params![item_id, meta.vault_uuid, version],
                    |r| r.get(0),
                )
                .optional()
                .map_err(StoreError::from)?;
            let blob = row.ok_or(VaultError::NotFound)?;
            decrypt_version(store, master, meta, item_id, version, &blob)
        })
    }

    /// Save an archived version as the new current item. The save archives the
    /// version it supersedes, so history grows rather than being rewritten.
    pub fn history_restore(&self, item_id: &str, version: i64) -> Result<Item, VaultError> {
        self.touch();
        let mut item = self.history_get(item_id, version)?;
        item.id = item_id.to_string();
        self.save(item)
    }
}
