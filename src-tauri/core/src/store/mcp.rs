//! Field grants and the read audit.
//!
//! `grants` answers "may this principal read this field of this item";
//! `mcp_audit` records every read that actually happened. Both are plaintext
//! bookkeeping — the principal, the item, the field id — while the value itself
//! never leaves the encrypted blob except through a granted read.
//!
//! Table shapes are in [`super::migrate`] (schema v12). The module keeps its
//! historical name because the MCP path was its first caller; the table and the
//! functions now cover every principal kind ([`super::GRANT_KIND_MCP`],
//! [`super::GRANT_KIND_CLI`]).
//!
//! Rules that keep this module honest:
//!
//! * A grant set is replaced as a whole for one principal. Re-pairing is the
//!   moment its allowlist is decided, so there is no "add one more field"
//!   operation that could drift from what the user reviewed. The one exception
//!   is the per-item editor ([`Store::set_item_grants`]), whose unit of consent
//!   is the item: it replaces every principal's rows for that item.
//! * A deadline in the past means *not granted*. Expired rows are not deleted
//!   on read — the check is the authority — but they are never reported as live
//!   access and re-pairing drops them.
//! * A one-shot grant is deleted by the read it authorizes, after the value has
//!   been resolved and before the audit row is written.
//! * The audit row is written by the caller *before* it answers with a value.
//!   A read that cannot be recorded is a read that does not happen.

use super::{Store, StoreError, GRANT_KIND_MCP};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

/// One row of `grants`: this principal may read this field of this item.
///
/// `pub(crate)`: the core exposes grants through [`crate::session::VaultState`]
/// as [`crate::session::AccessGrant`]; nothing outside the crate names this row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GrantRow {
    pub(crate) principal_kind: String,
    pub(crate) principal_id: String,
    pub(crate) item_id: String,
    pub(crate) field: String,
    pub(crate) created_at: i64,
    pub(crate) expires_at: Option<i64>,
    pub(crate) one_shot: bool,
}

/// One row of `mcp_audit`: a value was handed to this principal at `at`.
///
/// `client` is the audit label: the MCP client name, `cli:<client>` for a CLI
/// token, or `browser:<origin>` for the browser bridge. The audit stays one
/// table so a read is recorded once regardless of who performed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct McpAuditRow {
    pub(crate) client: String,
    pub(crate) item_id: String,
    pub(crate) field: String,
    pub(crate) at: i64,
}

/// Newest audit rows returned in one read. The list is a recent history, not
/// an export: a client that reads a field in a loop must not make the card
/// allocate for every past read.
const AUDIT_LIMIT_MAX: usize = 500;

impl Store {
    /// Replace every grant held by one principal, in one transaction.
    ///
    /// `grants` is `(item uuid, field id)`; the caller has already checked both
    /// exist in the vault. An empty list leaves the principal with no read
    /// access rather than deleting it implicitly — the token is what keeps it
    /// alive. `expires_at` is a unix timestamp or `None` for no deadline.
    pub(crate) fn set_grants(
        &self,
        principal_kind: &str,
        principal_id: &str,
        grants: &[(String, String)],
        expires_at: Option<i64>,
        one_shot: bool,
    ) -> Result<(), StoreError> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute(
            "DELETE FROM grants WHERE principal_kind = ?1 AND principal_id = ?2",
            params![principal_kind, principal_id],
        )?;
        let now = chrono::Utc::now().timestamp();
        {
            let mut insert = tx.prepare(
                "INSERT OR IGNORE INTO grants(
                    principal_kind, principal_id, item_uuid, field,
                    created_at, expires_at, one_shot
                 )
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for (item_id, field) in grants {
                insert.execute(params![
                    principal_kind,
                    principal_id,
                    item_id,
                    field,
                    now,
                    expires_at,
                    one_shot
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Replace the whole grant set of one item, across principals.
    ///
    /// The per-item access editor decides "who may read what" for the item in
    /// one save; a stale row for a principal the person removed would be
    /// access the editor does not show. Each entry is
    /// `(principal kind, principal id, field)`; existing rows for the item are
    /// dropped even when the new list is empty.
    pub(crate) fn set_item_grants(
        &self,
        item_id: &str,
        grants: &[(String, String, String)],
    ) -> Result<(), StoreError> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute("DELETE FROM grants WHERE item_uuid = ?1", params![item_id])?;
        let now = chrono::Utc::now().timestamp();
        {
            let mut insert = tx.prepare(
                "INSERT OR IGNORE INTO grants(
                    principal_kind, principal_id, item_uuid, field,
                    created_at, expires_at, one_shot
                 )
                 VALUES(?1, ?2, ?3, ?4, ?5, NULL, 0)",
            )?;
            for (kind, principal_id, field) in grants {
                insert.execute(params![kind, principal_id, item_id, field, now])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Every grant held by one principal, ordered by item then field.
    pub(crate) fn grants_for(
        &self,
        principal_kind: &str,
        principal_id: &str,
    ) -> Result<Vec<GrantRow>, StoreError> {
        self.query_grants(
            "SELECT principal_kind, principal_id, item_uuid, field,
                    created_at, expires_at, one_shot
             FROM grants
             WHERE principal_kind = ?1 AND principal_id = ?2
             ORDER BY item_uuid, field",
            params![principal_kind, principal_id],
        )
    }

    /// Every grant that names `item_id`, across principals, for the item editor.
    pub(crate) fn grants_for_item(&self, item_id: &str) -> Result<Vec<GrantRow>, StoreError> {
        self.query_grants(
            "SELECT principal_kind, principal_id, item_uuid, field,
                    created_at, expires_at, one_shot
             FROM grants
             WHERE item_uuid = ?1
             ORDER BY principal_kind, principal_id, field",
            params![item_id],
        )
    }

    /// Every live grant's item id for one principal. This is what makes
    /// `items.list` show only what was handed out, without decrypting a grant
    /// per row.
    pub(crate) fn granted_item_ids(
        &self,
        principal_kind: &str,
        principal_id: &str,
        now: i64,
    ) -> Result<Vec<String>, StoreError> {
        let mut statement = self.conn().prepare(
            "SELECT DISTINCT item_uuid FROM grants
             WHERE principal_kind = ?1 AND principal_id = ?2
               AND (expires_at IS NULL OR expires_at > ?3)
             ORDER BY item_uuid",
        )?;
        let rows = statement.query_map(params![principal_kind, principal_id, now], |row| {
            row.get::<_, String>(0)
        })?;
        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    /// Whether this exact triple is allowed right now. The read path calls
    /// this; the primary key on the table makes it an index probe. An expired
    /// row is not allowed even though it is still on disk.
    pub(crate) fn grant_allows(
        &self,
        principal_kind: &str,
        principal_id: &str,
        item_id: &str,
        field: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let found: Option<i64> = self
            .conn()
            .query_row(
                "SELECT 1 FROM grants
                 WHERE principal_kind = ?1 AND principal_id = ?2
                   AND item_uuid = ?3 AND field = ?4
                   AND (expires_at IS NULL OR expires_at > ?5)",
                params![principal_kind, principal_id, item_id, field, now],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Spend a one-shot grant. Called by the read path after the value has been
    /// resolved, so a failed lookup does not burn the grant. A grant that is
    /// not one-shot is left alone; deleting zero rows is not an error.
    pub(crate) fn consume_one_shot_grant(
        &self,
        principal_kind: &str,
        principal_id: &str,
        item_id: &str,
        field: &str,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "DELETE FROM grants
             WHERE principal_kind = ?1 AND principal_id = ?2
               AND item_uuid = ?3 AND field = ?4 AND one_shot = 1",
            params![principal_kind, principal_id, item_id, field],
        )?;
        Ok(())
    }

    /// Drop one principal's grants. Returns how many rows went away, so a card
    /// that revokes a client can say whether it was paired at all.
    pub(crate) fn clear_grants(
        &self,
        principal_kind: &str,
        principal_id: &str,
    ) -> Result<usize, StoreError> {
        Ok(self.conn().execute(
            "DELETE FROM grants WHERE principal_kind = ?1 AND principal_id = ?2",
            params![principal_kind, principal_id],
        )?)
    }

    /* ------------------------------------------------------ MCP path (v6 API) */

    /// Replace one MCP client's allowlist. Kept as the MCP path's entry point;
    /// it is the `mcp` principal with no deadline and no one-shot flag.
    pub(crate) fn replace_mcp_grants(
        &self,
        client: &str,
        grants: &[(String, String)],
    ) -> Result<(), StoreError> {
        self.set_grants(GRANT_KIND_MCP, client, grants, None, false)
    }

    /// Every MCP grant, grouped by client then item, for the settings card.
    pub(crate) fn mcp_grants(&self) -> Result<Vec<GrantRow>, StoreError> {
        self.query_grants(
            "SELECT principal_kind, principal_id, item_uuid, field,
                    created_at, expires_at, one_shot
             FROM grants
             WHERE principal_kind = ?1
             ORDER BY principal_id, item_uuid, field",
            params![GRANT_KIND_MCP],
        )
    }

    /// Whether this exact triple is allowed for an MCP client.
    pub(crate) fn mcp_granted(
        &self,
        client: &str,
        item_id: &str,
        field: &str,
    ) -> Result<bool, StoreError> {
        self.grant_allows(
            GRANT_KIND_MCP,
            client,
            item_id,
            field,
            chrono::Utc::now().timestamp(),
        )
    }

    /// Drop one MCP client's grants.
    pub(crate) fn clear_mcp_grants(&self, client: &str) -> Result<usize, StoreError> {
        self.clear_grants(GRANT_KIND_MCP, client)
    }

    /* ---------------------------------------------------------------- audit */

    /// Record one read. Returns the timestamp written, which is also what the
    /// in-memory response carries, so the card and the database agree.
    pub(crate) fn append_mcp_audit(
        &self,
        client: &str,
        item_id: &str,
        field: &str,
    ) -> Result<i64, StoreError> {
        let at = chrono::Utc::now().timestamp();
        self.conn().execute(
            "INSERT INTO mcp_audit(client, item_uuid, field, at) VALUES(?1, ?2, ?3, ?4)",
            params![client, item_id, field, at],
        )?;
        Ok(at)
    }

    /// Newest-first audit history, capped at [`AUDIT_LIMIT_MAX`].
    pub(crate) fn mcp_audit(&self, limit: usize) -> Result<Vec<McpAuditRow>, StoreError> {
        self.query_audit(
            "SELECT client, item_uuid, field, at FROM mcp_audit
             ORDER BY at DESC, id DESC LIMIT ?1",
            params![audit_limit(limit)],
        )
    }

    /// One item's history, newest first. Backs the access editor's audit line;
    /// the cap is the same recent-history limit as the global list.
    pub(crate) fn audit_for_item(&self, item_id: &str) -> Result<Vec<McpAuditRow>, StoreError> {
        self.query_audit(
            "SELECT client, item_uuid, field, at FROM mcp_audit
             WHERE item_uuid = ?1
             ORDER BY at DESC, id DESC LIMIT ?2",
            params![item_id, AUDIT_LIMIT_MAX as i64],
        )
    }

    fn query_grants(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<Vec<GrantRow>, StoreError> {
        let mut statement = self.conn().prepare(sql)?;
        let rows = statement.query_map(params, |row| {
            Ok(GrantRow {
                principal_kind: row.get(0)?,
                principal_id: row.get(1)?,
                item_id: row.get(2)?,
                field: row.get(3)?,
                created_at: row.get(4)?,
                expires_at: row.get(5)?,
                one_shot: row.get(6)?,
            })
        })?;
        let mut grants = Vec::new();
        for row in rows {
            grants.push(row?);
        }
        Ok(grants)
    }

    fn query_audit(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<Vec<McpAuditRow>, StoreError> {
        let mut statement = self.conn().prepare(sql)?;
        let rows = statement.query_map(params, |row| {
            Ok(McpAuditRow {
                client: row.get(0)?,
                item_id: row.get(1)?,
                field: row.get(2)?,
                at: row.get(3)?,
            })
        })?;
        let mut audit = Vec::new();
        for row in rows {
            audit.push(row?);
        }
        Ok(audit)
    }
}

/// A zero limit is a caller bug, not a way to ask for everything.
fn audit_limit(limit: usize) -> i64 {
    limit.clamp(1, AUDIT_LIMIT_MAX) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{GRANT_KIND_CLI, GRANT_KIND_MCP};

    fn store(tag: &str) -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(dir.path().join(format!("{tag}.db"))).expect("store opens");
        (store, dir)
    }

    fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
        values
            .iter()
            .map(|(item, field)| (item.to_string(), field.to_string()))
            .collect()
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn allows(store: &Store, kind: &str, id: &str, item: &str, field: &str) -> bool {
        store.grant_allows(kind, id, item, field, now()).unwrap()
    }

    #[test]
    fn a_grant_is_an_exact_triple() {
        let (store, _dir) = store("grant");
        store
            .replace_mcp_grants("editor", &pairs(&[("item-1", "field-1")]))
            .expect("grants write");

        assert!(allows(
            &store,
            GRANT_KIND_MCP,
            "editor",
            "item-1",
            "field-1"
        ));
        // Every part of the triple is significant.
        assert!(!allows(
            &store,
            GRANT_KIND_MCP,
            "editor",
            "item-1",
            "field-2"
        ));
        assert!(!allows(
            &store,
            GRANT_KIND_MCP,
            "editor",
            "item-2",
            "field-1"
        ));
        assert!(!allows(
            &store,
            GRANT_KIND_MCP,
            "other",
            "item-1",
            "field-1"
        ));
        // The same id under another principal kind is a different principal.
        assert!(!allows(
            &store,
            GRANT_KIND_CLI,
            "editor",
            "item-1",
            "field-1"
        ));
    }

    #[test]
    fn re_pairing_replaces_the_whole_allowlist() {
        let (store, _dir) = store("replace");
        store
            .replace_mcp_grants(
                "editor",
                &pairs(&[("item-1", "field-1"), ("item-1", "field-2")]),
            )
            .expect("first pair");
        store
            .replace_mcp_grants("editor", &pairs(&[("item-2", "field-9")]))
            .expect("second pair");

        let grants = store.mcp_grants().expect("grants");
        assert_eq!(grants.len(), 1, "the first allowlist is gone: {grants:?}");
        assert_eq!(grants[0].item_id, "item-2");
        assert_eq!(grants[0].expires_at, None);
        assert!(!grants[0].one_shot);
        assert!(!allows(
            &store,
            GRANT_KIND_MCP,
            "editor",
            "item-1",
            "field-1"
        ));
        assert!(allows(
            &store,
            GRANT_KIND_MCP,
            "editor",
            "item-2",
            "field-9"
        ));

        // An empty list means no access, not "keep what was there".
        store.replace_mcp_grants("editor", &[]).expect("clear");
        assert!(store.mcp_grants().unwrap().is_empty());
    }

    #[test]
    fn principals_are_independent_and_clearing_counts_rows() {
        let (store, _dir) = store("clients");
        store
            .replace_mcp_grants("editor", &pairs(&[("item-1", "field-1")]))
            .expect("editor");
        store
            .set_grants(
                GRANT_KIND_CLI,
                "editor",
                &pairs(&[("item-1", "field-1")]),
                None,
                false,
            )
            .expect("cli");
        assert_eq!(
            store
                .granted_item_ids(GRANT_KIND_MCP, "editor", now())
                .unwrap(),
            vec!["item-1".to_string()]
        );
        assert_eq!(store.clear_mcp_grants("editor").expect("clear"), 1);
        assert!(!allows(
            &store,
            GRANT_KIND_MCP,
            "editor",
            "item-1",
            "field-1"
        ));
        // The CLI principal with the same id is untouched by the MCP revoke.
        assert!(allows(
            &store,
            GRANT_KIND_CLI,
            "editor",
            "item-1",
            "field-1"
        ));
        assert_eq!(store.clear_mcp_grants("editor").expect("idempotent"), 0);
    }

    #[test]
    fn a_deadline_in_the_past_refuses_the_grant() {
        let (store, _dir) = store("expiry");
        let past = now() - 60;
        let future = now() + 3600;
        store
            .set_grants(
                GRANT_KIND_CLI,
                "old",
                &pairs(&[("item-1", "field-1")]),
                Some(past),
                false,
            )
            .expect("expired pair");
        store
            .set_grants(
                GRANT_KIND_CLI,
                "new",
                &pairs(&[("item-1", "field-1")]),
                Some(future),
                false,
            )
            .expect("live pair");

        assert!(!allows(&store, GRANT_KIND_CLI, "old", "item-1", "field-1"));
        assert!(allows(&store, GRANT_KIND_CLI, "new", "item-1", "field-1"));
        // The list filter uses the same rule: an expired row is not a title the
        // token may see.
        assert!(store
            .granted_item_ids(GRANT_KIND_CLI, "old", now())
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .granted_item_ids(GRANT_KIND_CLI, "new", now())
                .unwrap(),
            vec!["item-1".to_string()]
        );
    }

    #[test]
    fn a_one_shot_grant_is_spent_by_its_read() {
        let (store, _dir) = store("one-shot");
        store
            .set_grants(
                GRANT_KIND_CLI,
                "once",
                &pairs(&[("item-1", "field-1")]),
                None,
                true,
            )
            .expect("one-shot pair");

        assert!(allows(&store, GRANT_KIND_CLI, "once", "item-1", "field-1"));
        store
            .consume_one_shot_grant(GRANT_KIND_CLI, "once", "item-1", "field-1")
            .expect("consume");
        assert!(
            !allows(&store, GRANT_KIND_CLI, "once", "item-1", "field-1"),
            "a spent grant is gone"
        );
        assert!(store.grants_for(GRANT_KIND_CLI, "once").unwrap().is_empty());

        // A permanent grant is left alone by the same call.
        store
            .set_grants(
                GRANT_KIND_CLI,
                "always",
                &pairs(&[("item-1", "field-1")]),
                None,
                false,
            )
            .expect("permanent pair");
        store
            .consume_one_shot_grant(GRANT_KIND_CLI, "always", "item-1", "field-1")
            .expect("no-op");
        assert!(allows(
            &store,
            GRANT_KIND_CLI,
            "always",
            "item-1",
            "field-1"
        ));
    }

    #[test]
    fn item_grants_replace_the_whole_item_and_are_listed_per_item() {
        let (store, _dir) = store("item-grants");
        store
            .replace_mcp_grants("editor", &pairs(&[("item-1", "field-1")]))
            .expect("mcp row");
        store
            .set_grants(
                GRANT_KIND_CLI,
                "terminal",
                &pairs(&[("item-1", "field-2")]),
                None,
                false,
            )
            .expect("cli row");

        store
            .set_item_grants(
                "item-1",
                &[(
                    GRANT_KIND_CLI.to_string(),
                    "terminal".to_string(),
                    "field-1".to_string(),
                )],
            )
            .expect("item editor save");
        let rows = store.grants_for_item("item-1").expect("item grants");
        assert_eq!(rows.len(), 1, "the MCP row was replaced too: {rows:?}");
        assert_eq!(rows[0].principal_kind, GRANT_KIND_CLI);
        assert_eq!(rows[0].field, "field-1");
        assert!(!allows(
            &store,
            GRANT_KIND_MCP,
            "editor",
            "item-1",
            "field-1"
        ));

        // Clearing the item's access removes the rows rather than keeping the
        // ones the editor no longer shows.
        store.set_item_grants("item-1", &[]).expect("item clear");
        assert!(store.grants_for_item("item-1").unwrap().is_empty());
    }

    #[test]
    fn the_audit_is_newest_first_bounded_and_readable_per_item() {
        let (store, _dir) = store("audit");
        store
            .append_mcp_audit("editor", "item-1", "field-1")
            .expect("first");
        // The schema stores whole seconds, so the order must not depend on the
        // clock advancing between two writes in the same second.
        store
            .append_mcp_audit("cli:terminal", "item-2", "field-2")
            .expect("second");
        store
            .append_mcp_audit("editor", "item-1", "field-1")
            .expect("third");

        let rows = store.mcp_audit(10).expect("audit");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].item_id, "item-1", "newest first: {rows:?}");
        assert_eq!(rows[1].item_id, "item-2");
        assert!(rows[0].at > 0);

        assert_eq!(store.mcp_audit(1).expect("limited").len(), 1);
        // A zero limit is a caller bug, not a way to ask for everything.
        assert_eq!(store.mcp_audit(0).expect("clamped").len(), 1);

        let item = store.audit_for_item("item-1").expect("item audit");
        assert_eq!(item.len(), 2, "only this item's reads: {item:?}");
        assert!(item.iter().all(|row| row.item_id == "item-1"));
        assert_eq!(item[0].client, "editor");
    }
}
