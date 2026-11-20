//! Account access: identity metadata, unlock and password rotation.

use super::attachments::StoredAttachment;
use super::items::StoredVersion;
use super::passkeys::StoredPasskey;
use super::{
    Store, StoreError, VaultMeta, ENC_VERSION_HISTORY_AAD, ENC_VERSION_KEY, VERIFIER_PLAINTEXT,
};
use crate::crypto::{self, SymKey, SALT_LEN};
use crate::model::Item;
use rusqlite::{params, Transaction};
use std::collections::HashMap;

/// One vault's decrypted contents, held only for the duration of a rotation.
struct VaultPayload {
    uuid: String,
    name_plain: Vec<u8>,
    items: Vec<(Item, i64, Option<i64>)>,
    /// The keys the items already owned. A password change re-wraps them and
    /// keeps the values, so a synced device's copy is never orphaned.
    item_keys: Vec<(String, SymKey)>,
    versions: Vec<StoredVersion>,
    attachments: Vec<StoredAttachment>,
    passkeys: Vec<StoredPasskey>,
}

impl Store {
    pub fn meta_identity(&self) -> Result<VaultMeta, StoreError> {
        let salt = self.meta("kdf_salt")?.ok_or(StoreError::NotInitialised)?;
        let account_uuid = self
            .meta("account_uuid")?
            .ok_or(StoreError::NotInitialised)?;
        let vault_uuid = self
            .meta("default_vault_uuid")?
            .ok_or(StoreError::NotInitialised)?;
        let verifier = self.meta("verifier")?.ok_or(StoreError::NotInitialised)?;
        Ok(VaultMeta {
            account_uuid: String::from_utf8_lossy(&account_uuid).into_owned(),
            vault_uuid: String::from_utf8_lossy(&vault_uuid).into_owned(),
            salt,
            verifier,
        })
    }

    /// Verify the password and return the master key.
    pub fn unlock(&self, password: &str) -> Result<(SymKey, VaultMeta), StoreError> {
        let meta = self.meta_identity()?;
        let master = crypto::derive_master_key(password, &meta.salt)?;
        let vault_key = Self::vault_key(&master, &meta.vault_uuid)?;
        let plain = crypto::decrypt(&vault_key, b"kestrel/verifier", &meta.verifier)
            .map_err(|_| crypto::CryptoError::Decrypt)?;
        if plain != VERIFIER_PLAINTEXT {
            return Err(StoreError::Crypto(crypto::CryptoError::Decrypt));
        }
        // Rows written before the plaintext projection existed are indexed now,
        // while the master key is in hand; current-build rows are skipped.
        self.backfill_search_index(&master, &meta)?;
        Ok((master, meta))
    }

    /// Re-key the whole account: the KDF salt and verifier, every vault's name
    /// blob, and every item, archived version and attachment in every vault.
    /// A rotation that skipped a vault would leave it unreadable, so the loop is
    /// over vaults, not over the active one.
    pub fn change_password(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        new: &str,
    ) -> Result<(SymKey, VaultMeta), StoreError> {
        let payloads = self.collect_payloads(master, meta)?;

        // The verifier is always bound to the account's default vault, not to
        // whichever vault the session happens to be scoped to right now.
        let default_vault = self.meta_identity()?.vault_uuid;
        let salt = crypto::random_bytes::<SALT_LEN>().to_vec();
        let new_master = crypto::derive_master_key(new, &salt)?;
        let default_key = Self::vault_key(&new_master, &default_vault)?;
        let verifier = crypto::encrypt(&default_key, b"kestrel/verifier", VERIFIER_PLAINTEXT)?;
        let new_meta = VaultMeta {
            account_uuid: meta.account_uuid.clone(),
            vault_uuid: meta.vault_uuid.clone(),
            salt: salt.clone(),
            verifier: verifier.clone(),
        };

        // One transaction covers the salt/verifier swap, the wipe and every
        // rewritten row. If any step fails the whole rotation rolls back, so
        // the database is still openable with the *old* password and holds the
        // old data rather than a half-rotated mixture.
        let tx = self.conn.unchecked_transaction()?;
        self.install_new_key(&tx, &salt, &verifier)?;
        // The account key and the Secret Key are sealed under the master key, so
        // the rotation re-seals them with the new one. The account key itself is
        // carried over unchanged: re-deriving it would change the value every
        // enrolled device already holds.
        self.rotate_account(master, &new_master)?;
        self.reinsert_payloads(&tx, &new_master, &new_meta, payloads)?;
        tx.commit()?;
        Ok((new_master, new_meta))
    }

    /// Decrypt every vault's contents under the *old* master key, before
    /// anything is rewritten.
    fn collect_payloads(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
    ) -> Result<Vec<VaultPayload>, StoreError> {
        let mut payloads: Vec<VaultPayload> = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT vault_uuid, data, key_version FROM vaults
             WHERE account_uuid = ?1 ORDER BY rowid",
        )?;
        let rows = stmt.query_map(params![meta.account_uuid], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (uuid, blob, key_version) = row?;
            let name_plain =
                self.open_vault_name(master, &meta.account_uuid, &uuid, key_version, &blob)?;
            let scope = VaultMeta {
                vault_uuid: uuid.clone(),
                ..meta.clone()
            };
            let keys = self.item_keys(master, &scope)?;
            let items = self.load_versioned(master, &scope)?;
            let item_keys = items
                .iter()
                .filter_map(|(item, _, _)| {
                    keys.get(&item.id).map(|key| (item.id.clone(), key.clone()))
                })
                .collect();
            payloads.push(VaultPayload {
                uuid,
                name_plain,
                items,
                item_keys,
                versions: self.load_versions(&keys, &scope)?,
                attachments: self.load_attachments(&keys, &scope)?,
                passkeys: self.load_passkeys(&keys, &scope)?,
            });
        }
        Ok(payloads)
    }

    /// Swap the account's salt and verifier and wipe the old ciphertext. Runs
    /// inside the caller's transaction so the wipe cannot outlive a failure.
    fn install_new_key(
        &self,
        tx: &Transaction<'_>,
        salt: &[u8],
        verifier: &[u8],
    ) -> Result<(), StoreError> {
        self.set_meta("kdf_salt", salt)?;
        self.set_meta("verifier", verifier)?;
        self.set_meta(ENC_VERSION_KEY, ENC_VERSION_HISTORY_AAD)?;
        tx.execute("DELETE FROM items", [])?;
        tx.execute("DELETE FROM item_versions", [])?;
        tx.execute("DELETE FROM attachments", [])?;
        tx.execute("DELETE FROM passkeys", [])?;
        tx.execute("DELETE FROM item_keys", [])?;
        tx.execute("DELETE FROM vaults", [])?;
        Ok(())
    }

    /// Re-seal every collected payload under the new master key. Versions and
    /// attachment identities are carried over verbatim, so history never
    /// renumbers and replay bindings survive the rotation.
    fn reinsert_payloads(
        &self,
        tx: &Transaction<'_>,
        new_master: &SymKey,
        new_meta: &VaultMeta,
        payloads: Vec<VaultPayload>,
    ) -> Result<(), StoreError> {
        for payload in payloads {
            self.reinsert_vault(tx, new_master, new_meta, payload)?;
        }
        Ok(())
    }

    fn reinsert_vault(
        &self,
        tx: &Transaction<'_>,
        new_master: &SymKey,
        new_meta: &VaultMeta,
        payload: VaultPayload,
    ) -> Result<(), StoreError> {
        let vault_key = Self::vault_key(new_master, &payload.uuid)?;
        let vault_blob = crypto::encrypt(
            &vault_key,
            &Self::vault_aad(&new_meta.account_uuid, &payload.uuid),
            &payload.name_plain,
        )?;
        tx.execute(
            "INSERT INTO vaults(account_uuid, vault_uuid, data, key_version)
             VALUES(?1, ?2, ?3, 2)",
            params![new_meta.account_uuid, payload.uuid, vault_blob],
        )?;

        let scope = VaultMeta {
            vault_uuid: payload.uuid.clone(),
            ..new_meta.clone()
        };
        // Keys the items already owned are re-wrapped, never re-minted: their
        // values are the ones enrolled devices will see. Items that predate
        // per-item keys get one minted here, since every blob is rewritten
        // anyway.
        for (item_uuid, key) in &payload.item_keys {
            self.rewrap_item_key(new_master, &scope, item_uuid, key)?;
        }
        let mut item_keys: HashMap<String, SymKey> = payload.item_keys.into_iter().collect();
        for (item, version, deleted_at) in payload.items {
            let key = self.ensure_item_key(new_master, &scope, &item.id)?;
            item_keys.insert(item.id.clone(), key);
            self.write_item(new_master, &scope, &item, version)?;
            // The projection columns are rebuilt by `write_item`; the trash
            // marker lives outside it and would otherwise come back as live.
            if let Some(at) = deleted_at {
                tx.execute(
                    "UPDATE items SET deleted_at = ?3
                     WHERE vault_uuid = ?1 AND item_uuid = ?2",
                    params![scope.vault_uuid, item.id, at],
                )?;
            }
        }
        for row in payload.versions {
            let key = self.item_key_for(new_master, &scope, &mut item_keys, &row.item_uuid)?;
            insert_version(tx, &scope, &key, row)?;
        }
        for row in payload.attachments {
            let key = self.item_key_for(new_master, &scope, &mut item_keys, &row.item_uuid)?;
            insert_attachment(tx, &scope, &key, row)?;
        }
        for row in payload.passkeys {
            let key = self.item_key_for(new_master, &scope, &mut item_keys, &row.item_uuid)?;
            self.insert_stored_passkey(tx, &scope, &key, row)?;
        }
        Ok(())
    }

    /// The key for one item during a rotation, minted and cached when the item
    /// has none yet (a history or attachment row whose item was already gone).
    fn item_key_for(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        cache: &mut HashMap<String, SymKey>,
        item_uuid: &str,
    ) -> Result<SymKey, StoreError> {
        if let Some(key) = cache.get(item_uuid) {
            return Ok(key.clone());
        }
        let key = self.ensure_item_key(master, meta, item_uuid)?;
        cache.insert(item_uuid.to_string(), key.clone());
        Ok(key)
    }

    /// Re-seal every archived version with the history AAD. Databases written
    /// before the split stored history blobs with the live-item AAD, which made
    /// them interchangeable with `items`; rewriting them needs the master key,
    /// so this runs at unlock, in one transaction, and is a no-op afterwards
    /// (the `enc_version` flag is written in the same transaction).
    pub fn migrate_encrypted(&self, master: &SymKey, meta: &VaultMeta) -> Result<(), StoreError> {
        if self.meta(ENC_VERSION_KEY)?.as_deref() == Some(ENC_VERSION_HISTORY_AAD) {
            return Ok(());
        }
        let tx = self.conn.unchecked_transaction()?;
        let vault_uuids: Vec<String> = {
            let mut stmt = self
                .conn
                .prepare("SELECT vault_uuid FROM vaults WHERE account_uuid = ?1 ORDER BY rowid")?;
            let rows = stmt.query_map(params![meta.account_uuid], |r| r.get::<_, String>(0))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            out
        };
        for uuid in vault_uuids {
            let scope = VaultMeta {
                vault_uuid: uuid,
                ..meta.clone()
            };
            let rows: Vec<(String, i64, Vec<u8>)> = {
                let mut stmt = self.conn.prepare(
                    "SELECT item_uuid, version, data FROM item_versions WHERE vault_uuid = ?1",
                )?;
                let mapped = stmt.query_map(params![scope.vault_uuid], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                })?;
                let mut out = Vec::new();
                for row in mapped {
                    out.push(row?);
                }
                out
            };
            for (item_uuid, version, blob) in rows {
                let key = self.sealing_key(master, &scope, &item_uuid)?;
                let plain =
                    crypto::decrypt(&key, &Self::version_aad(&scope, &item_uuid, version), &blob)?;
                let resealed = crypto::encrypt(
                    &key,
                    &Self::history_aad(&scope, &item_uuid, version),
                    &plain,
                )?;
                tx.execute(
                    "UPDATE item_versions SET data = ?1
                     WHERE vault_uuid = ?2 AND item_uuid = ?3 AND version = ?4",
                    params![resealed, scope.vault_uuid, item_uuid, version],
                )?;
            }
        }
        self.set_meta(ENC_VERSION_KEY, ENC_VERSION_HISTORY_AAD)?;
        tx.commit()?;
        Ok(())
    }
}

fn insert_version(
    tx: &Transaction<'_>,
    meta: &VaultMeta,
    key: &SymKey,
    row: StoredVersion,
) -> Result<(), StoreError> {
    let aad = Store::history_aad(meta, &row.item_uuid, row.version);
    let blob = crypto::encrypt(key, &aad, &row.plain)?;
    tx.execute(
        "INSERT INTO item_versions(vault_uuid, item_uuid, version, archived_at, data)
         VALUES(?1, ?2, ?3, ?4, ?5)",
        params![
            meta.vault_uuid,
            row.item_uuid,
            row.version,
            row.archived_at,
            blob
        ],
    )?;
    Ok(())
}

fn insert_attachment(
    tx: &Transaction<'_>,
    meta: &VaultMeta,
    key: &SymKey,
    row: StoredAttachment,
) -> Result<(), StoreError> {
    let aad = Store::attachment_aad(meta, &row.item_uuid, &row.attachment_uuid);
    let blob = crypto::encrypt(key, &aad, &row.plain)?;
    tx.execute(
        "INSERT INTO attachments(vault_uuid, item_uuid, attachment_uuid, name, mime, size, digest, created_at, data)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            meta.vault_uuid,
            row.item_uuid,
            row.attachment_uuid,
            row.name,
            row.mime,
            row.size,
            row.digest,
            row.created_at,
            blob
        ],
    )?;
    Ok(())
}
