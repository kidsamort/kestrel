//! Per-item keys: one random key per item, wrapped by the vault item key.
//!
//! Before schema v9 a vault had one item key (`HKDF(master, vault uuid)`), so
//! every item, archived version, attachment and passkey blob in a vault shared
//! it. That key is still derived and still used — as a **key-encryption key**.
//! Each item now owns a random 32-byte key, sealed under it with the
//! `item-key` AAD, and the item's blobs are sealed with *that* key.
//!
//! The AAD bindings are unchanged: a live blob is still
//! `kestrel/v1|item|account|vault|item|version`, a history blob still uses the
//! `item-history` kind, an attachment still binds `item:attachment`, and a
//! passkey still binds its credential id. Only the key underneath changes, so
//! replay between rows, versions and vaults is still refused exactly as before.
//!
//! **Migration is lazy and non-destructive.** A row with no `item_keys` entry is
//! opened with the legacy vault key ([`ItemKeys::for_item`] falls back to it), so
//! a vault from an older build keeps working the moment it is opened. The
//! upgrade itself ([`Store::backfill_item_keys`]) runs at unlock, next to the
//! search-index backfill, because it needs the master key to decrypt each row
//! before re-sealing it: at `Store::open` time there is no master key yet, and a
//! locked vault must never be rewritten. It is idempotent (only items without a
//! key row are touched) and commits one vault at a time, so a crash resumes on
//! the next unlock.
//!
//! Key rows are scoped by `vault_uuid`: the store keeps item identities
//! vault-scoped, so the same uuid may exist in two vaults and each copy owns a
//! different key.

use super::{Store, StoreError, VaultMeta};
use crate::crypto::{self, object_aad, SymKey, KEY_LEN};
use rusqlite::{params, OptionalExtension};
use std::collections::HashMap;

/// `object_aad` kind for a wrapped per-item key.
const ITEM_KEY_KIND: &str = "item-key";

/// Every item key of one vault, unwrapped once per call, plus the legacy vault
/// key that opens rows written before schema v9.
pub(crate) struct ItemKeys {
    legacy: SymKey,
    keys: HashMap<String, SymKey>,
}

impl ItemKeys {
    /// The key one item's blobs are sealed with: the per-item key when it
    /// exists, the legacy vault key otherwise. The fallback is what makes the
    /// migration readable before it has run.
    pub(crate) fn for_item(&self, item_uuid: &str) -> &SymKey {
        self.keys.get(item_uuid).unwrap_or(&self.legacy)
    }

    /// The per-item key when this item has one, without the legacy fallback.
    /// Rotation uses it to carry existing keys across a password change.
    pub(crate) fn get(&self, item_uuid: &str) -> Option<&SymKey> {
        self.keys.get(item_uuid)
    }
}

impl Store {
    /// AAD binding for one wrapped item key. `item-key` is a distinct kind, so a
    /// wrapped key cannot be replayed as an item body or another object.
    pub(crate) fn item_key_aad(meta: &VaultMeta, item_uuid: &str) -> Vec<u8> {
        object_aad(
            ITEM_KEY_KIND,
            &meta.account_uuid,
            &meta.vault_uuid,
            item_uuid,
            1,
        )
    }

    /// Every key of one vault, unwrapped. The query is scoped by `vault_uuid`, so
    /// a key wrapped for another vault is never even attempted here.
    pub(crate) fn item_keys(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
    ) -> Result<ItemKeys, StoreError> {
        let legacy = Self::item_key(master, meta)?;
        let mut stmt = self
            .conn()
            .prepare("SELECT item_uuid, wrapped FROM item_keys WHERE vault_uuid = ?1")?;
        let rows = stmt.query_map(params![meta.vault_uuid], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut keys = HashMap::new();
        for row in rows {
            let (item_uuid, wrapped) = row?;
            let aad = Self::item_key_aad(meta, &item_uuid);
            let plain = crypto::decrypt(&legacy, &aad, &wrapped)?;
            keys.insert(item_uuid, SymKey::from_slice(&plain)?);
        }
        Ok(ItemKeys { legacy, keys })
    }

    /// The key one item is sealed with, for a single-object read.
    pub(crate) fn sealing_key(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        item_uuid: &str,
    ) -> Result<SymKey, StoreError> {
        let legacy = Self::item_key(master, meta)?;
        match self.read_item_key(&legacy, meta, item_uuid)? {
            Some(key) => Ok(key),
            None => Ok(legacy),
        }
    }

    fn read_item_key(
        &self,
        legacy: &SymKey,
        meta: &VaultMeta,
        item_uuid: &str,
    ) -> Result<Option<SymKey>, StoreError> {
        let wrapped: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT wrapped FROM item_keys WHERE vault_uuid = ?1 AND item_uuid = ?2",
                params![meta.vault_uuid, item_uuid],
                |row| row.get(0),
            )
            .optional()?;
        let Some(wrapped) = wrapped else {
            return Ok(None);
        };
        let plain = crypto::decrypt(legacy, &Self::item_key_aad(meta, item_uuid), &wrapped)?;
        Ok(Some(SymKey::from_slice(&plain)?))
    }

    fn mint_item_key(
        &self,
        legacy: &SymKey,
        meta: &VaultMeta,
        item_uuid: &str,
    ) -> Result<SymKey, StoreError> {
        let key = SymKey::from_slice(&crypto::random_bytes::<KEY_LEN>())?;
        self.wrap_item_key(legacy, meta, item_uuid, &key)?;
        Ok(key)
    }

    /// Seal `key` under the vault item key and store the row. Used when minting
    /// a key and when a rotation re-wraps the key an item already has, so a
    /// password change never re-keys an item.
    fn wrap_item_key(
        &self,
        vault_key: &SymKey,
        meta: &VaultMeta,
        item_uuid: &str,
        key: &SymKey,
    ) -> Result<(), StoreError> {
        let wrapped = crypto::encrypt(
            vault_key,
            &Self::item_key_aad(meta, item_uuid),
            &key.to_bytes()[..],
        )?;
        self.conn().execute(
            "INSERT INTO item_keys(vault_uuid, item_uuid, wrapped, created_at)
             VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(vault_uuid, item_uuid) DO UPDATE SET wrapped = excluded.wrapped",
            params![
                meta.vault_uuid,
                item_uuid,
                wrapped,
                chrono::Utc::now().timestamp_millis()
            ],
        )?;
        Ok(())
    }

    /// Re-wrap an existing item key under a new vault key, inside a rotation
    /// transaction. The key value is unchanged on purpose.
    pub(crate) fn rewrap_item_key(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        item_uuid: &str,
        key: &SymKey,
    ) -> Result<(), StoreError> {
        let vault_key = Self::item_key(master, meta)?;
        self.wrap_item_key(&vault_key, meta, item_uuid, key)
    }

    /// The key to seal `item_uuid` with, minting one when the item predates
    /// per-item keys.
    ///
    /// Minting also re-seals every blob the item already owns, in the same
    /// caller transaction, so the item is never half-migrated: the key row
    /// exists exactly when the blobs are sealed with it. Callers that already
    /// hold an open transaction use this directly; it never opens its own.
    pub(crate) fn ensure_item_key(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        item_uuid: &str,
    ) -> Result<SymKey, StoreError> {
        let legacy = Self::item_key(master, meta)?;
        if let Some(key) = self.read_item_key(&legacy, meta, item_uuid)? {
            return Ok(key);
        }
        let key = self.mint_item_key(&legacy, meta, item_uuid)?;
        self.reseal_item_blobs(meta, item_uuid, &legacy, &key)?;
        Ok(key)
    }

    /// Re-seal one item's live row, archived versions, attachments and passkey
    /// blobs from `old` to `key`. Every AAD is the one the row already carries,
    /// so the identity binding is untouched. Called only immediately after
    /// minting the item's key, when the blobs are still under the legacy key.
    fn reseal_item_blobs(
        &self,
        meta: &VaultMeta,
        item_uuid: &str,
        old: &SymKey,
        key: &SymKey,
    ) -> Result<(), StoreError> {
        let live: Option<(i64, Vec<u8>)> = self
            .conn()
            .query_row(
                "SELECT version, data FROM items WHERE vault_uuid = ?1 AND item_uuid = ?2",
                params![meta.vault_uuid, item_uuid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((version, blob)) = live {
            let aad = Self::version_aad(meta, item_uuid, version);
            let plain = crypto::decrypt(old, &aad, &blob)?;
            let resealed = crypto::encrypt(key, &aad, &plain)?;
            self.conn().execute(
                "UPDATE items SET data = ?3 WHERE vault_uuid = ?1 AND item_uuid = ?2",
                params![meta.vault_uuid, item_uuid, resealed],
            )?;
        }

        let versions: Vec<(i64, Vec<u8>)> = {
            let mut stmt = self.conn().prepare(
                "SELECT version, data FROM item_versions
                 WHERE vault_uuid = ?1 AND item_uuid = ?2",
            )?;
            let rows = stmt.query_map(params![meta.vault_uuid, item_uuid], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            out
        };
        for (version, blob) in versions {
            let aad = Self::history_aad(meta, item_uuid, version);
            let plain = crypto::decrypt(old, &aad, &blob)?;
            let resealed = crypto::encrypt(key, &aad, &plain)?;
            self.conn().execute(
                "UPDATE item_versions SET data = ?4
                 WHERE vault_uuid = ?1 AND item_uuid = ?2 AND version = ?3",
                params![meta.vault_uuid, item_uuid, version, resealed],
            )?;
        }

        let attachments: Vec<(String, Vec<u8>)> = {
            let mut stmt = self.conn().prepare(
                "SELECT attachment_uuid, data FROM attachments
                 WHERE vault_uuid = ?1 AND item_uuid = ?2",
            )?;
            let rows = stmt.query_map(params![meta.vault_uuid, item_uuid], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            out
        };
        for (attachment_uuid, blob) in attachments {
            let aad = Self::attachment_aad(meta, item_uuid, &attachment_uuid);
            let plain = crypto::decrypt(old, &aad, &blob)?;
            let resealed = crypto::encrypt(key, &aad, &plain)?;
            self.conn().execute(
                "UPDATE attachments SET data = ?4
                 WHERE vault_uuid = ?1 AND item_uuid = ?2 AND attachment_uuid = ?3",
                params![meta.vault_uuid, item_uuid, attachment_uuid, resealed],
            )?;
        }

        let passkeys: Vec<(Vec<u8>, Vec<u8>)> = {
            let mut stmt = self.conn().prepare(
                "SELECT credential_id, key_blob FROM passkeys
                     WHERE item_uuid = ?2
                       AND EXISTS (SELECT 1 FROM items i
                                   WHERE i.item_uuid = ?2 AND i.vault_uuid = ?1)",
            )?;
            let rows = stmt.query_map(params![meta.vault_uuid, item_uuid], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            out
        };
        for (credential_id, blob) in passkeys {
            let aad = Self::passkey_aad(meta, &credential_id);
            let plain = crypto::decrypt(old, &aad, &blob)?;
            let resealed = crypto::encrypt(key, &aad, &plain)?;
            self.conn().execute(
                "UPDATE passkeys SET key_blob = ?2 WHERE credential_id = ?1",
                params![credential_id, resealed],
            )?;
        }
        Ok(())
    }

    /// Mint the missing per-item keys and re-seal the items that predate them.
    ///
    /// Runs on unlock, next to [`Store::backfill_search_index`]: both need the
    /// master key, and neither can run at [`Store::open`] time, before a password
    /// has produced one. One transaction per vault, stopping at the first
    /// failure, so a crash leaves the vault either migrated or untouched and the
    /// next unlock resumes. Returns how many items were given a key.
    pub fn backfill_item_keys(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
    ) -> Result<usize, StoreError> {
        let vault_uuids: Vec<String> = {
            let mut stmt = self
                .conn()
                .prepare("SELECT vault_uuid FROM vaults WHERE account_uuid = ?1 ORDER BY rowid")?;
            let rows = stmt.query_map(params![meta.account_uuid], |row| row.get::<_, String>(0))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            out
        };
        let mut migrated = 0usize;
        for vault_uuid in vault_uuids {
            let scope = VaultMeta {
                vault_uuid,
                ..meta.clone()
            };
            let pending: Vec<String> = {
                let mut stmt = self.conn().prepare(
                    "SELECT i.item_uuid FROM items i
                     LEFT JOIN item_keys k
                         ON k.vault_uuid = i.vault_uuid AND k.item_uuid = i.item_uuid
                     WHERE i.vault_uuid = ?1 AND k.item_uuid IS NULL
                     ORDER BY i.item_uuid",
                )?;
                let rows =
                    stmt.query_map(params![scope.vault_uuid], |row| row.get::<_, String>(0))?;
                let mut out = Vec::new();
                for row in rows {
                    out.push(row?);
                }
                out
            };
            if pending.is_empty() {
                continue;
            }
            let tx = self.conn().unchecked_transaction()?;
            for item_uuid in pending {
                self.ensure_item_key(master, &scope, &item_uuid)?;
                migrated += 1;
            }
            tx.commit()?;
        }
        Ok(migrated)
    }
}
