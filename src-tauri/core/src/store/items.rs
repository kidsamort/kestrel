//! Item rows: live items, archived versions and their AAD bindings.

use super::{Store, StoreError, VaultMeta, ITEM_PURPOSE};
use crate::crypto::{self, object_aad, SymKey};
use crate::model::{Item, ItemSummary};
use rusqlite::{params, OptionalExtension};

/// An archived version as re-keying needs it: identity plus the decrypted JSON.
pub(crate) struct StoredVersion {
    pub(crate) item_uuid: String,
    pub(crate) version: i64,
    pub(crate) archived_at: i64,
    pub(crate) plain: Vec<u8>,
}

impl Store {
    /// AAD binding for a **live** item row. Binding the version means an
    /// archived blob can never be replayed as the current item.
    pub(crate) fn version_aad(meta: &VaultMeta, item_id: &str, version: i64) -> Vec<u8> {
        object_aad(
            "item",
            &meta.account_uuid,
            &meta.vault_uuid,
            item_id,
            version,
        )
    }

    /// AAD binding for an archived version. The distinct `kind` is what stops
    /// the same ciphertext from being replayed into `items` at the same
    /// version, which a version-only binding could not prevent.
    pub(crate) fn history_aad(meta: &VaultMeta, item_id: &str, version: i64) -> Vec<u8> {
        object_aad(
            "item-history",
            &meta.account_uuid,
            &meta.vault_uuid,
            item_id,
            version,
        )
    }

    /// The vault's item key is now a **key-encryption key**: every item owns a
    /// random key wrapped under it ([`super::item_keys`]), and the item's blobs
    /// are sealed with that one. Rows written before schema v9 are still sealed
    /// with this key directly; `ItemKeys::for_item` is the fallback for them.
    pub(crate) fn item_key(master: &SymKey, meta: &VaultMeta) -> Result<SymKey, StoreError> {
        Ok(master.derive(meta.vault_uuid.as_bytes(), ITEM_PURPOSE)?)
    }

    pub fn load_all(&self, master: &SymKey, meta: &VaultMeta) -> Result<Vec<Item>, StoreError> {
        Ok(self
            .load_rows(master, meta)?
            .into_iter()
            .map(|(item, _)| item)
            .collect())
    }

    /// Every row with its trash marker; `None` means the item is live.
    pub(crate) fn load_rows(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
    ) -> Result<Vec<(Item, Option<i64>)>, StoreError> {
        let keys = self.item_keys(master, meta)?;
        let mut stmt = self.conn.prepare(
            "SELECT item_uuid, version, deleted_at, data FROM items
             WHERE vault_uuid = ?1 ORDER BY item_uuid",
        )?;
        let rows = stmt.query_map(params![meta.vault_uuid], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Option<i64>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut items = Vec::new();
        for row in rows {
            let (id, version, deleted_at, blob) = row?;
            let aad = Self::version_aad(meta, &id, version);
            let plain = crypto::decrypt(keys.for_item(&id), &aad, &blob)?;
            items.push((serde_json::from_slice::<Item>(&plain)?, deleted_at));
        }
        Ok(items)
    }

    /// Every live summary matching `needle`, favourites first then title.
    ///
    /// The paged surface is [`Store::list_page`]; this keeps the original
    /// unpaged API for existing callers and tests.
    pub fn list(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        needle: &str,
    ) -> Result<Vec<ItemSummary>, StoreError> {
        Ok(self
            .list_page(master, meta, needle, None, false, usize::MAX, 0)?
            .items)
    }

    /// One item, decrypted from its own row only.
    ///
    /// The row carries the version the blob's AAD is bound to, so a single
    /// `WHERE item_uuid = ?` is enough: opening an item must not depend on how
    /// many other items the vault holds. Trashed rows stay readable here — the
    /// trash surface is what hides them from the list, not this read.
    pub fn get(&self, master: &SymKey, meta: &VaultMeta, id: &str) -> Result<Item, StoreError> {
        let key = self.sealing_key(master, meta, id)?;
        let mut stmt = self.conn.prepare(
            "SELECT version, data FROM items WHERE vault_uuid = ?1 AND item_uuid = ?2",
        )?;
        let row = stmt.query_row(params![meta.vault_uuid, id], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
        });
        match row {
            Ok((version, blob)) => {
                let plain = crypto::decrypt(&key, &Self::version_aad(meta, id, version), &blob)?;
                Ok(serde_json::from_slice::<Item>(&plain)?)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(StoreError::NotFound),
            Err(error) => Err(StoreError::Db(error)),
        }
    }

    /// Insert or replace an item, bumping its version and binding the new
    /// version into the AAD so an old blob cannot be replayed.
    pub fn save_item(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        mut item: Item,
    ) -> Result<Item, StoreError> {
        // Archiving the superseded version and writing the new one must be
        // atomic: a crash between them would leave a history row for a save
        // that never happened.
        let tx = self.conn.unchecked_transaction()?;
        // The item's key must exist before the superseded blob is read: the
        // archive re-seals that blob with the same key the new version uses, and
        // `ensure_item_key` migrates an item that predates per-item keys in this
        // same transaction.
        self.ensure_item_key(master, meta, &item.id)?;
        let previous: Option<(i64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT version, data FROM items WHERE vault_uuid = ?1 AND item_uuid = ?2",
                params![meta.vault_uuid, item.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((prev_version, prev_blob)) = previous.as_ref() {
            self.archive_version(master, meta, &item.id, *prev_version, prev_blob)?;
        }
        let version = previous.map(|(v, _)| v).unwrap_or(0) + 1;
        item.updated_at = chrono::Utc::now().timestamp();
        if version == 1 && item.created_at == 0 {
            item.created_at = item.updated_at;
        }
        let saved = self.write_item(master, meta, &item, version)?;
        // The save is the change: bump this device's counter in the item's sync
        // clock inside the same transaction, so a crash cannot leave a saved
        // item the engine believes is already on the server.
        self.mark_sync_dirty(&meta.vault_uuid, &item.id)?;
        tx.commit()?;
        Ok(saved)
    }

    /// Encrypt and store one item at an explicit version. Re-keying uses this
    /// so a password change does not renumber history.
    pub(crate) fn write_item(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        item: &Item,
        version: i64,
    ) -> Result<Item, StoreError> {
        let key = self.ensure_item_key(master, meta, &item.id)?;
        let plain = serde_json::to_vec(item)?;
        let aad = Self::version_aad(meta, &item.id, version);
        let blob = crypto::encrypt(&key, &aad, &plain)?;
        // The plaintext projection is derived from the same item that produced
        // the blob, never from caller-supplied text.
        let search = super::query::search_text(item);
        self.conn.execute(
            "INSERT INTO items(account_uuid, vault_uuid, item_uuid, local_edit_count, version, data,
                               search_text, category, favorite)
             VALUES(?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(vault_uuid, item_uuid) DO UPDATE SET
                 version = excluded.version,
                 local_edit_count = items.local_edit_count + 1,
                 data = excluded.data,
                 search_text = excluded.search_text,
                 category = excluded.category,
                 favorite = excluded.favorite",
            params![
                meta.account_uuid,
                meta.vault_uuid,
                item.id,
                version,
                blob,
                search,
                item.category.as_str(),
                if item.favorite { 1i64 } else { 0i64 },
            ],
        )?;
        Ok(item.clone())
    }

    /// Items with the version they are stored at; used by re-keying.
    pub(crate) fn load_versioned(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
    ) -> Result<Vec<(Item, i64, Option<i64>)>, StoreError> {
        let keys = self.item_keys(master, meta)?;
        let mut stmt = self.conn.prepare(
            "SELECT item_uuid, version, data, deleted_at FROM items WHERE vault_uuid = ?1",
        )?;
        let rows = stmt.query_map(params![meta.vault_uuid], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Option<i64>>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, version, blob, deleted_at) = row?;
            let plain = crypto::decrypt(
                keys.for_item(&id),
                &Self::version_aad(meta, &id, version),
                &blob,
            )?;
            out.push((serde_json::from_slice::<Item>(&plain)?, version, deleted_at));
        }
        Ok(out)
    }

    /// Archived versions of one vault, decrypted; used by re-keying.
    pub(crate) fn load_versions(
        &self,
        keys: &super::item_keys::ItemKeys,
        meta: &VaultMeta,
    ) -> Result<Vec<StoredVersion>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT item_uuid, version, archived_at, data FROM item_versions
             WHERE vault_uuid = ?1",
        )?;
        let rows = stmt.query_map(params![meta.vault_uuid], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (item_uuid, version, archived_at, blob) = row?;
            let plain = crypto::decrypt(
                keys.for_item(&item_uuid),
                &Self::history_aad(meta, &item_uuid, version),
                &blob,
            )?;
            out.push(StoredVersion {
                item_uuid,
                version,
                archived_at,
                plain,
            });
        }
        Ok(out)
    }

    /// Keep the superseded version so History can show what changed. The live
    /// blob is sealed with `item` AAD; before it is archived it is re-sealed
    /// with `item-history` AAD, so the two stores can never exchange a blob
    /// even at the same item uuid and version.
    fn archive_version(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        item_id: &str,
        version: i64,
        blob: &[u8],
    ) -> Result<(), StoreError> {
        let key = self.sealing_key(master, meta, item_id)?;
        let plain = crypto::decrypt(&key, &Self::version_aad(meta, item_id, version), blob)?;
        let archived = crypto::encrypt(&key, &Self::history_aad(meta, item_id, version), &plain)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO item_versions(vault_uuid, item_uuid, version, archived_at, data)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                meta.vault_uuid,
                item_id,
                version,
                chrono::Utc::now().timestamp(),
                archived
            ],
        )?;
        self.conn.execute(
            "DELETE FROM item_versions WHERE vault_uuid = ?1 AND item_uuid = ?2 AND version NOT IN (
                 SELECT version FROM item_versions WHERE vault_uuid = ?1 AND item_uuid = ?2
                 ORDER BY version DESC LIMIT 50)",
            params![meta.vault_uuid, item_id],
        )?;
        Ok(())
    }

    /// Permanent removal from one vault. Archived versions and sealed
    /// attachments belong to that vault's item, so they go with it; the same
    /// item uuid in another vault is a different item and stays untouched.
    /// Whether one item row is in the trash. `NotFound` for an unknown item, so
    /// a caller cannot mistake "no row" for "live".
    pub fn is_trashed(&self, meta: &VaultMeta, id: &str) -> Result<bool, StoreError> {
        let row: Option<Option<i64>> = self
            .conn()
            .query_row(
                "SELECT deleted_at FROM items WHERE vault_uuid = ?1 AND item_uuid = ?2",
                params![meta.vault_uuid, id],
                |r| r.get(0),
            )
            .optional()?;
        match row {
            None => Err(StoreError::NotFound),
            Some(deleted_at) => Ok(deleted_at.is_some()),
        }
    }

    /// Stamp or clear the trash marker on one item.
    ///
    /// Soft delete is a column, not a row removal, so the ciphertext stays
    /// readable: restore works, and a sync tombstone can be applied without
    /// destroying the only copy of an item a concurrent edit is still arguing
    /// about. Trashing an already-trashed item keeps the first deletion time;
    /// restoring a live item is a no-op. An unknown item is [`StoreError::NotFound`].
    pub fn set_trashed(
        &self,
        meta: &VaultMeta,
        id: &str,
        trashed: bool,
    ) -> Result<(), StoreError> {
        let stamp = if trashed {
            Some(chrono::Utc::now().timestamp())
        } else {
            None
        };
        // One transaction: a crash between the two statements would leave an
        // item trashed but not queued, and the deletion would never reach the
        // server.
        let tx = self.conn().unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE items SET deleted_at = CASE
                 WHEN ?3 THEN COALESCE(deleted_at, ?4)
                 ELSE NULL
             END
             WHERE vault_uuid = ?1 AND item_uuid = ?2",
            params![meta.vault_uuid, id, trashed as i64, stamp],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        // Trashing and restoring are changes like any other: the engine turns a
        // trashed row into a tombstone, so it has to know.
        self.mark_sync_dirty(&meta.vault_uuid, id)?;
        tx.commit()?;
        Ok(())
    }

    pub fn delete_item(&self, meta: &VaultMeta, id: &str) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM item_versions WHERE vault_uuid = ?1 AND item_uuid = ?2",
            params![meta.vault_uuid, id],
        )?;
        tx.execute(
            "DELETE FROM attachments WHERE vault_uuid = ?1 AND item_uuid = ?2",
            params![meta.vault_uuid, id],
        )?;
        self.passkeys_purge_item(meta, id)?;
        tx.execute(
            "DELETE FROM item_keys WHERE vault_uuid = ?1 AND item_uuid = ?2",
            params![meta.vault_uuid, id],
        )?;
        tx.execute(
            "DELETE FROM items WHERE vault_uuid = ?1 AND item_uuid = ?2",
            params![meta.vault_uuid, id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Items in one vault that are not in the trash. The UI counter must match
    /// what `list` shows, so it is scoped to the active vault and ignores
    /// soft-deleted rows.
    pub fn live_count(&self, meta: &VaultMeta) -> Result<i64, StoreError> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM items WHERE vault_uuid = ?1 AND deleted_at IS NULL",
            params![meta.vault_uuid],
            |r| r.get(0),
        )?)
    }
}
