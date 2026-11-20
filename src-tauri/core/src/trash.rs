//! Trash: soft delete, restore, permanent purge.
//!
//! Deleting an item from the vault only stamps `items.deleted_at`; the row and
//! its ciphertext stay in place, so the item can still be decrypted and
//! restored. Purging is the destructive half: it removes the item row together
//! with its archived versions and attachments. Live items can never be purged
//! by accident — the caller has to move them to the trash first.

use crate::model::ItemSummary;
use crate::session::{VaultError, VaultState};
use crate::store::StoreError;
use rusqlite::{params, OptionalExtension};

fn db_err(error: rusqlite::Error) -> VaultError {
    VaultError::Store(StoreError::Db(error))
}

impl VaultState {
    /// Every trashed item as a summary, newest deletion first. The summaries
    /// carry `deleted_at` so the view can say when the item went.
    pub fn trash_list(&self) -> Result<Vec<ItemSummary>, VaultError> {
        self.touch();
        self.with_session(|store, master, meta| {
            let mut rows: Vec<(ItemSummary, i64)> = store
                .load_rows(master, meta)?
                .into_iter()
                .filter_map(|(item, deleted_at)| deleted_at.map(|at| (item.summary(), at)))
                .collect();
            rows.sort_by(|a, b| {
                b.1.cmp(&a.1)
                    .then_with(|| a.0.title.to_lowercase().cmp(&b.0.title.to_lowercase()))
            });
            Ok(rows
                .into_iter()
                .map(|(mut summary, deleted_at)| {
                    summary.deleted_at = Some(deleted_at);
                    summary
                })
                .collect())
        })
    }

    /// How many items the trash currently holds.
    pub fn trash_count(&self) -> Result<i64, VaultError> {
        self.touch();
        self.with_session(|store, _, meta| {
            let count = store
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM items
                     WHERE vault_uuid = ?1 AND deleted_at IS NOT NULL",
                    params![meta.vault_uuid],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(db_err)?;
            Ok(count)
        })
    }

    /// Move an item to the trash. Idempotent: trashing an already-trashed item
    /// keeps the original deletion time.
    pub fn trash_item(&self, id: &str) -> Result<(), VaultError> {
        self.touch();
        self.with_session(|store, _, meta| {
            store.set_trashed(meta, id, true).map_err(VaultError::Store)
        })
    }

    /// Bring a trashed item back into the vault. Restoring a live item is a
    /// harmless no-op.
    pub fn restore_item(&self, id: &str) -> Result<(), VaultError> {
        self.touch();
        self.with_session(|store, _, meta| {
            store
                .set_trashed(meta, id, false)
                .map_err(VaultError::Store)
        })
    }

    /// Permanently delete one trashed item, its archived versions and its
    /// attachments. Refuses to touch a live item.
    pub fn purge_item(&self, id: &str) -> Result<(), VaultError> {
        self.touch();
        self.with_session(|store, _, meta| {
            let conn = store.conn();
            let row: Option<Option<i64>> = conn
                .query_row(
                    "SELECT deleted_at FROM items WHERE vault_uuid = ?1 AND item_uuid = ?2",
                    params![meta.vault_uuid, id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(db_err)?;
            match row {
                None => Err(VaultError::NotFound),
                Some(None) => Err(VaultError::Invalid(
                    "restore or delete it from the vault first".to_string(),
                )),
                Some(Some(_)) => {
                    let tx = conn.unchecked_transaction().map_err(db_err)?;
                    tx.execute(
                        "DELETE FROM item_versions WHERE vault_uuid = ?1 AND item_uuid = ?2",
                        params![meta.vault_uuid, id],
                    )
                    .map_err(db_err)?;
                    tx.execute(
                        "DELETE FROM attachments WHERE vault_uuid = ?1 AND item_uuid = ?2",
                        params![meta.vault_uuid, id],
                    )
                    .map_err(db_err)?;
                    store
                        .passkeys_purge_item(meta, id)
                        .map_err(VaultError::Store)?;
                    tx.execute(
                        "DELETE FROM item_keys WHERE vault_uuid = ?1 AND item_uuid = ?2",
                        params![meta.vault_uuid, id],
                    )
                    .map_err(db_err)?;
                    tx.execute(
                        "DELETE FROM items
                         WHERE vault_uuid = ?1 AND item_uuid = ?2 AND deleted_at IS NOT NULL",
                        params![meta.vault_uuid, id],
                    )
                    .map_err(db_err)?;
                    tx.commit().map_err(db_err)?;
                    Ok(())
                }
            }
        })
    }

    /// Purge every trashed item in one transaction. Returns the number of item
    /// rows removed; live items are never touched.
    pub fn empty_trash(&self) -> Result<u64, VaultError> {
        self.touch();
        self.with_session(|store, _, meta| {
            let conn = store.conn();
            let tx = conn.unchecked_transaction().map_err(db_err)?;
            tx.execute(
                "DELETE FROM item_versions
                 WHERE vault_uuid = ?1 AND item_uuid IN (
                     SELECT item_uuid FROM items
                     WHERE vault_uuid = ?1 AND deleted_at IS NOT NULL)",
                params![meta.vault_uuid],
            )
            .map_err(db_err)?;
            tx.execute(
                "DELETE FROM attachments
                 WHERE vault_uuid = ?1 AND item_uuid IN (
                     SELECT item_uuid FROM items
                     WHERE vault_uuid = ?1 AND deleted_at IS NOT NULL)",
                params![meta.vault_uuid],
            )
            .map_err(db_err)?;
            store
                .passkeys_purge_trash(meta)
                .map_err(VaultError::Store)?;
            tx.execute(
                "DELETE FROM item_keys
                 WHERE vault_uuid = ?1 AND item_uuid IN (
                     SELECT item_uuid FROM items
                     WHERE vault_uuid = ?1 AND deleted_at IS NOT NULL)",
                params![meta.vault_uuid],
            )
            .map_err(db_err)?;
            let purged = tx
                .execute(
                    "DELETE FROM items WHERE vault_uuid = ?1 AND deleted_at IS NOT NULL",
                    params![meta.vault_uuid],
                )
                .map_err(db_err)?;
            tx.commit().map_err(db_err)?;
            Ok(purged as u64)
        })
    }
}
