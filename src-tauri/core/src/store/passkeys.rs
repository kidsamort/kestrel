//! WebAuthn credential rows.
//!
//! `credential_id` and `rp_id` are public identifiers; the private key is
//! sealed under the item's key in `key_blob` and only the core can open it.
//! A credential belongs to one item, so locking the vault revokes every
//! passkey with the rest of the session.
//!
//! Table shape is in [`super::migrate`] (schema v7). The table deliberately has
//! no `vault_uuid`: every lookup joins `items` on `item_uuid`, which both scopes
//! the row to the active vault and drops a credential whose item is gone.
//!
//! The sealed payload is `version || private-scalar(32) || signCount(u32 BE)`.
//! The counter lives inside the seal because schema v7 has no column for it and
//! a signature counter that can be reset by editing an unprotected column is
//! worse than no counter at all.

use super::{Store, StoreError, VaultMeta};
use crate::crypto::{self, object_aad, SymKey};
use crate::model::{PasskeyRow, PasskeySecret};
use rusqlite::{params, OptionalExtension, Transaction};
use std::fmt::Write;
use zeroize::Zeroizing;

/// Current sealed-payload version. A future layout can reject v1 instead of
/// guessing at its bytes.
pub const SEAL_VERSION: u8 = 1;
const SEAL_LEN: usize = 1 + 32 + 4;

/// A credential as re-keying needs it: metadata plus the decrypted payload.
pub(crate) struct StoredPasskey {
    pub credential_id: Vec<u8>,
    pub item_uuid: String,
    pub rp_id: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    /// `version || scalar || signCount`, already decrypted.
    pub plain: Vec<u8>,
}

impl Drop for StoredPasskey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.plain.zeroize();
    }
}

/// Lower-case hex for the AAD and for command payloads. The credential id is
/// public, but keeping it as text in AAD makes a truncated blob obvious when
/// debugging.
pub fn credential_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

impl Store {
    /// AAD binding for a sealed passkey private key. The credential id is the
    /// object identity, so a blob cannot be replayed under another credential,
    /// item or vault.
    pub(crate) fn passkey_aad(meta: &VaultMeta, credential_id: &[u8]) -> Vec<u8> {
        object_aad(
            "passkey",
            &meta.account_uuid,
            &meta.vault_uuid,
            &credential_hex(credential_id),
            1,
        )
    }

    fn seal_passkey(private_key: &[u8], sign_count: u32) -> Result<Vec<u8>, StoreError> {
        if private_key.len() != 32 {
            return Err(StoreError::Invalid(
                "passkey private key must be 32 bytes".into(),
            ));
        }
        let mut out = Vec::with_capacity(SEAL_LEN);
        out.push(SEAL_VERSION);
        out.extend_from_slice(private_key);
        out.extend_from_slice(&sign_count.to_be_bytes());
        Ok(out)
    }

    fn open_seal(plain: &[u8]) -> Result<(Zeroizing<Vec<u8>>, u32), StoreError> {
        if plain.len() != SEAL_LEN || plain[0] != SEAL_VERSION {
            return Err(StoreError::Invalid("malformed passkey seal".into()));
        }
        let mut count = [0u8; 4];
        count.copy_from_slice(&plain[33..]);
        Ok((
            Zeroizing::new(plain[1..33].to_vec()),
            u32::from_be_bytes(count),
        ))
    }

    fn passkey_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PasskeyRow> {
        Ok(PasskeyRow {
            credential_id: row.get(0)?,
            item_uuid: row.get(1)?,
            rp_id: row.get(2)?,
            created_at: row.get(3)?,
            last_used_at: row.get(4)?,
        })
    }

    /// Credentials attached to one item, oldest first, scoped to the vault the
    /// item actually lives in. Returns metadata only — no key material.
    pub fn passkeys_for_item(
        &self,
        meta: &VaultMeta,
        item_uuid: &str,
    ) -> Result<Vec<PasskeyRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT p.credential_id, p.item_uuid, p.rp_id, p.created_at, p.last_used_at
             FROM passkeys p
             JOIN items i ON i.item_uuid = p.item_uuid AND i.vault_uuid = ?1
             WHERE p.item_uuid = ?2
             ORDER BY p.created_at, p.credential_id",
        )?;
        let rows = stmt.query_map(params![meta.vault_uuid, item_uuid], Self::passkey_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Every credential for one relying party in this vault, for a discoverable
    /// (allow-list-free) assertion.
    pub fn passkeys_for_rp(
        &self,
        meta: &VaultMeta,
        rp_id: &str,
    ) -> Result<Vec<PasskeyRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT p.credential_id, p.item_uuid, p.rp_id, p.created_at, p.last_used_at
             FROM passkeys p
             JOIN items i ON i.item_uuid = p.item_uuid AND i.vault_uuid = ?1
             WHERE p.rp_id = ?2
             ORDER BY p.created_at, p.credential_id",
        )?;
        let rows = stmt.query_map(params![meta.vault_uuid, rp_id], Self::passkey_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Whether a credential id is already registered in this vault. Used for
    /// the CTAP2 exclude list without opening a seal.
    pub fn passkey_exists(
        &self,
        meta: &VaultMeta,
        credential_id: &[u8],
    ) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM passkeys p
                 JOIN items i ON i.item_uuid = p.item_uuid AND i.vault_uuid = ?1
                 WHERE p.credential_id = ?2",
                params![meta.vault_uuid, credential_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Open one credential by id. `rp_id` is checked against the row, so a
    /// credential issued for one origin cannot answer for another.
    pub fn passkey_open(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        credential_id: &[u8],
        rp_id: &str,
    ) -> Result<Option<PasskeySecret>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT p.credential_id, p.item_uuid, p.rp_id, p.created_at, p.last_used_at, p.key_blob
             FROM passkeys p
             JOIN items i ON i.item_uuid = p.item_uuid AND i.vault_uuid = ?1
             WHERE p.credential_id = ?2 AND p.rp_id = ?3",
        )?;
        let found = stmt
            .query_row(
                params![meta.vault_uuid, credential_id, rp_id],
                |row| Ok((Self::passkey_row(row)?, row.get::<_, Vec<u8>>(5)?)),
            )
            .optional()?;
        let Some((row, blob)) = found else {
            return Ok(None);
        };
        let item_key = self.sealing_key(master, meta, &row.item_uuid)?;
        let aad = Self::passkey_aad(meta, &row.credential_id);
        let plain = crypto::decrypt(&item_key, &aad, &blob)?;
        let (private_key, sign_count) = Self::open_seal(&plain)?;
        Ok(Some(PasskeySecret {
            row,
            private_key: private_key.to_vec(),
            sign_count,
        }))
    }

    /// Open the first credential that can answer this assertion: an allow-list
    /// entry first, otherwise the oldest discoverable credential for the RP.
    pub fn passkey_open_for_assertion(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        rp_id: &str,
        allow_list: &[Vec<u8>],
    ) -> Result<Option<PasskeySecret>, StoreError> {
        for candidate in allow_list {
            if let Some(found) = self.passkey_open(master, meta, candidate, rp_id)? {
                return Ok(Some(found));
            }
        }
        if !allow_list.is_empty() {
            return Ok(None);
        }
        let rows = self.passkeys_for_rp(meta, rp_id)?;
        for row in rows {
            if let Some(found) = self.passkey_open(master, meta, &row.credential_id, rp_id)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    /// Store a freshly created credential. The seal is written under the item
    /// key, so an attacker with the database file alone has ciphertext.
    pub fn passkey_insert(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        row: &PasskeyRow,
        private_key: &[u8],
        sign_count: u32,
    ) -> Result<(), StoreError> {
        let plain = Zeroizing::new(Self::seal_passkey(private_key, sign_count)?);
        // One transaction: `ensure_item_key` commits the wrapped key before it
        // re-seals the item's blobs, so a failure between the two would leave a
        // key row the backfill never revisits (it selects items with *no* key)
        // and an item that can never be opened again.
        let tx = self.conn.unchecked_transaction()?;
        let item_key = self.ensure_item_key(master, meta, &row.item_uuid)?;
        let aad = Self::passkey_aad(meta, &row.credential_id);
        let blob = crypto::encrypt(&item_key, &aad, plain.as_slice())?;
        self.conn.execute(
            "INSERT INTO passkeys(credential_id, item_uuid, rp_id, created_at, last_used_at, key_blob)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                row.credential_id,
                row.item_uuid,
                row.rp_id,
                row.created_at,
                row.last_used_at,
                blob
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Replace the seal with a higher signature counter and stamp `last_used_at`.
    /// The caller passes the same private key back; a mismatch would produce a
    /// blob that no longer verifies against the stored public key.
    pub fn passkey_record_use(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        credential_id: &[u8],
        private_key: &[u8],
        sign_count: u32,
        at: i64,
    ) -> Result<(), StoreError> {
        let plain = Zeroizing::new(Self::seal_passkey(private_key, sign_count)?);
        // The row's item decides the key; a credential from another vault is not
        // visible here, exactly as the UPDATE's scope check demands.
        let item_uuid: String = self
            .conn
            .query_row(
                "SELECT p.item_uuid FROM passkeys p
                 JOIN items i ON i.item_uuid = p.item_uuid AND i.vault_uuid = ?2
                 WHERE p.credential_id = ?1",
                params![credential_id, meta.vault_uuid],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let item_key = self.sealing_key(master, meta, &item_uuid)?;
        let aad = Self::passkey_aad(meta, credential_id);
        let blob = crypto::encrypt(&item_key, &aad, plain.as_slice())?;
        let changed = self.conn.execute(
            "UPDATE passkeys SET key_blob = ?1, last_used_at = ?2
             WHERE credential_id = ?3
               AND EXISTS (
                 SELECT 1 FROM items i
                 WHERE i.item_uuid = passkeys.item_uuid AND i.vault_uuid = ?4
               )",
            params![blob, at, credential_id, meta.vault_uuid],
        )?;
        if changed != 1 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Remove one credential from one item. Returns whether a row went away.
    pub fn passkey_delete(
        &self,
        meta: &VaultMeta,
        item_uuid: &str,
        credential_id: &[u8],
    ) -> Result<bool, StoreError> {
        let changed = self.conn.execute(
            "DELETE FROM passkeys
             WHERE credential_id = ?1 AND item_uuid = ?2
               AND EXISTS (
                 SELECT 1 FROM items i
                 WHERE i.item_uuid = passkeys.item_uuid AND i.vault_uuid = ?3
               )",
            params![credential_id, item_uuid, meta.vault_uuid],
        )?;
        Ok(changed == 1)
    }

    /// Drop every credential attached to one item, scoped to the vault that
    /// owns it. Called by the permanent-delete paths so a purged login does not
    /// leave an unreachable sealed scalar behind.
    pub(crate) fn passkeys_purge_item(
        &self,
        meta: &VaultMeta,
        item_uuid: &str,
    ) -> Result<usize, StoreError> {
        Ok(self.conn.execute(
            "DELETE FROM passkeys
             WHERE item_uuid = ?2
               AND EXISTS (
                 SELECT 1 FROM items i
                 WHERE i.item_uuid = ?2 AND i.vault_uuid = ?1
               )",
            params![meta.vault_uuid, item_uuid],
        )?)
    }

    /// Drop credentials for every trashed item in this vault, before the trash
    /// is emptied. Live items are untouched.
    pub(crate) fn passkeys_purge_trash(&self, meta: &VaultMeta) -> Result<usize, StoreError> {
        Ok(self.conn.execute(
            "DELETE FROM passkeys
             WHERE item_uuid IN (
                 SELECT item_uuid FROM items
                 WHERE vault_uuid = ?1 AND deleted_at IS NOT NULL)",
            params![meta.vault_uuid],
        )?)
    }

    /// Every credential sealed for one vault; re-keying decrypts and writes it
    /// back under the new master key.
    pub(crate) fn load_passkeys(
        &self,
        keys: &super::item_keys::ItemKeys,
        meta: &VaultMeta,
    ) -> Result<Vec<StoredPasskey>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT p.credential_id, p.item_uuid, p.rp_id, p.created_at, p.last_used_at, p.key_blob
             FROM passkeys p
             JOIN items i ON i.item_uuid = p.item_uuid AND i.vault_uuid = ?1",
        )?;
        let rows = stmt.query_map(params![meta.vault_uuid], |row| {
            Ok((
                Self::passkey_row(row)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (row, blob) = row?;
            let aad = Self::passkey_aad(meta, &row.credential_id);
            let plain = crypto::decrypt(keys.for_item(&row.item_uuid), &aad, &blob)?;
            out.push(StoredPasskey {
                credential_id: row.credential_id,
                item_uuid: row.item_uuid,
                rp_id: row.rp_id,
                created_at: row.created_at,
                last_used_at: row.last_used_at,
                plain,
            });
        }
        Ok(out)
    }

    /// Write one re-keyed credential inside the rotation transaction.
    pub(crate) fn insert_stored_passkey(
        &self,
        tx: &Transaction<'_>,
        meta: &VaultMeta,
        item_key: &SymKey,
        stored: StoredPasskey,
    ) -> Result<(), StoreError> {
        let aad = Self::passkey_aad(meta, &stored.credential_id);
        let blob = crypto::encrypt(item_key, &aad, &stored.plain)?;
        tx.execute(
            "INSERT INTO passkeys(credential_id, item_uuid, rp_id, created_at, last_used_at, key_blob)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &stored.credential_id,
                &stored.item_uuid,
                &stored.rp_id,
                stored.created_at,
                stored.last_used_at,
                blob
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SymKey;

    fn scratch() -> (Store, SymKey, VaultMeta) {
        let store = Store::open(":memory:").unwrap();
        let master = SymKey::from_slice(&[0x5au8; 32]).unwrap();
        let meta = VaultMeta {
            account_uuid: "account".into(),
            vault_uuid: "vault".into(),
            salt: vec![0u8; 16],
            verifier: Vec::new(),
        };
        (store, master, meta)
    }

    fn ensure_item(store: &Store, master: &SymKey, meta: &VaultMeta, id: u8) {
        let mut item = crate::model::Item::new(crate::model::Category::Login, "login".into());
        item.id = format!("item-{id}");
        store.save_item(master, meta, item).unwrap();
    }

    fn row(id: u8) -> PasskeyRow {
        PasskeyRow {
            credential_id: vec![id; 32],
            item_uuid: format!("item-{id}"),
            rp_id: "example.com".into(),
            created_at: 1_700_000_000,
            last_used_at: None,
        }
    }

    #[test]
    fn sealed_key_round_trips_and_counter_advances() {
        let (store, master, meta) = scratch();
        let key = [7u8; 32];
        let entry = row(1);
        ensure_item(&store, &master, &meta, 1);
        store.passkey_insert(&master, &meta, &entry, &key, 0).unwrap();

        let opened = store
            .passkey_open(&master, &meta, &entry.credential_id, "example.com")
            .unwrap()
            .unwrap();
        assert_eq!(opened.private_key.as_slice(), &key);
        assert_eq!(opened.sign_count, 0);
        assert_eq!(opened.row.last_used_at, None);

        store
            .passkey_record_use(&master, &meta, &entry.credential_id, &key, 1, 42)
            .unwrap();
        let opened = store
            .passkey_open(&master, &meta, &entry.credential_id, "example.com")
            .unwrap()
            .unwrap();
        assert_eq!(opened.sign_count, 1);
        assert_eq!(opened.row.last_used_at, Some(42));
    }

    #[test]
    fn a_credential_only_answers_for_its_own_rp() {
        let (store, master, meta) = scratch();
        let entry = row(2);
        ensure_item(&store, &master, &meta, 2);
        store
            .passkey_insert(&master, &meta, &entry, &[9u8; 32], 0)
            .unwrap();
        assert!(store
            .passkey_open(&master, &meta, &entry.credential_id, "other.example")
            .unwrap()
            .is_none());
    }

    #[test]
    fn deleting_an_item_scopes_the_removal() {
        let (store, master, meta) = scratch();
        let entry = row(3);
        ensure_item(&store, &master, &meta, 3);
        store
            .passkey_insert(&master, &meta, &entry, &[3u8; 32], 0)
            .unwrap();
        assert!(!store
            .passkey_delete(&meta, "different-item", &entry.credential_id)
            .unwrap());
        assert!(store
            .passkey_delete(&meta, &entry.item_uuid, &entry.credential_id)
            .unwrap());
        assert!(store.passkeys_for_item(&meta, &entry.item_uuid).unwrap().is_empty());
    }

    #[test]
    fn purging_an_item_removes_its_sealed_rows() {
        let (store, master, meta) = scratch();
        ensure_item(&store, &master, &meta, 4);
        store
            .passkey_insert(&master, &meta, &row(4), &[4u8; 32], 0)
            .unwrap();
        assert_eq!(store.passkeys_purge_item(&meta, "item-4").unwrap(), 1);
        let remaining: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM passkeys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 0, "no orphan ciphertext after a purge");
    }

    #[test]
    fn seal_rejects_a_wrong_length_and_a_foreign_version() {
        assert!(Store::seal_passkey(&[0u8; 31], 0).is_err());
        let mut payload = Store::seal_passkey(&[1u8; 32], 0).unwrap();
        payload[0] = 9;
        assert!(Store::open_seal(&payload).is_err());
    }
}
