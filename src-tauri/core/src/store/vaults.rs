//! Vault lifecycle: creation, renaming, listing and name-blob decryption.
//!
//! Each vault's display name is sealed under a key derived from that vault's
//! uuid, so one master key opens every vault while no vault can decrypt
//! another's name blob. `key_version` records which key sealed a row; `2` is
//! the derived key, the only shape current builds write.

use super::{Store, StoreError, VaultMeta, VaultSummary, VAULT_PURPOSE};
use crate::crypto::{self, object_aad, SymKey};
use rusqlite::{params, OptionalExtension};

impl Store {
    /// How many vaults this file holds. Sync is one vault per account, so the
    /// engine refuses to run when this is more than one: a pulled item has no
    /// way to say which vault it belongs to.
    pub fn vault_count(&self) -> Result<u64, StoreError> {
        let count: i64 = self
            .conn()
            .query_row("SELECT COUNT(*) FROM vaults", [], |row| row.get(0))?;
        Ok(count.max(0) as u64)
    }

    /// AAD that binds a vault's name blob to its account and uuid.
    pub(crate) fn vault_aad(account: &str, vault_uuid: &str) -> Vec<u8> {
        object_aad("vault", account, vault_uuid, vault_uuid, 1)
    }

    pub(crate) fn vault_key(master: &SymKey, vault_uuid: &str) -> Result<SymKey, StoreError> {
        Ok(master.derive(vault_uuid.as_bytes(), VAULT_PURPOSE)?)
    }

    pub(crate) fn vault_name_plain(name: &str) -> Result<Vec<u8>, StoreError> {
        Ok(serde_json::to_vec(&serde_json::json!({
            "name": name,
            "icon": "shield"
        }))?)
    }

    fn decode_vault_name(plain: &[u8]) -> Result<String, StoreError> {
        let value: serde_json::Value = serde_json::from_slice(plain)?;
        Ok(value
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Vault")
            .to_string())
    }

    /// Decrypt a vault's name blob.
    ///
    /// `key_version = 2` rows are only ever sealed with the per-vault derived
    /// key and fail closed. Rows without a version predate the column and may be
    /// sealed either way — the first build used the master key, the multi-vault
    /// build already used the derived key — so both are tried once and the row
    /// is rewritten with the derived key and marked 2.
    pub(crate) fn open_vault_name(
        &self,
        master: &SymKey,
        account: &str,
        uuid: &str,
        key_version: i64,
        blob: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        let key = Self::vault_key(master, uuid)?;
        let aad = Self::vault_aad(account, uuid);
        if key_version >= 2 {
            return Ok(crypto::decrypt(&key, &aad, blob)?);
        }
        let plain = match crypto::decrypt(&key, &aad, blob) {
            Ok(plain) => plain,
            Err(_) => crypto::decrypt(master, &aad, blob)?,
        };
        let migrated = crypto::encrypt(&key, &aad, &plain)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE vaults SET data = ?1, key_version = 2
             WHERE account_uuid = ?2 AND vault_uuid = ?3 AND key_version < 2",
            params![migrated, account, uuid],
        )?;
        tx.commit()?;
        Ok(plain)
    }

    /// Every vault in this account with its live item count, in creation order.
    /// Requires the master key: the names are encrypted like everything else.
    pub fn list_vaults(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
    ) -> Result<Vec<VaultSummary>, StoreError> {
        let mut counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        let mut count_stmt = self.conn.prepare(
            "SELECT vault_uuid, COUNT(*) FROM items
             WHERE deleted_at IS NULL GROUP BY vault_uuid",
        )?;
        let rows =
            count_stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        for row in rows {
            let (uuid, count) = row?;
            counts.insert(uuid, count);
        }

        let mut stmt = self.conn.prepare(
            "SELECT vault_uuid, data, key_version FROM vaults WHERE account_uuid = ?1 ORDER BY rowid",
        )?;
        let rows = stmt.query_map(params![meta.account_uuid], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (uuid, blob, key_version) = row?;
            let plain =
                self.open_vault_name(master, &meta.account_uuid, &uuid, key_version, &blob)?;
            out.push(VaultSummary {
                name: Self::decode_vault_name(&plain)?,
                item_count: counts.get(&uuid).copied().unwrap_or(0),
                uuid,
            });
        }
        Ok(out)
    }

    /// Create a vault under the current master key. The key is derived from the
    /// vault uuid, so every vault has its own key while one password opens all.
    pub fn create_vault(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        name: &str,
    ) -> Result<VaultSummary, StoreError> {
        let name = Self::clean_vault_name(name)?;
        let uuid = uuid::Uuid::new_v4().to_string();
        let key = Self::vault_key(master, &uuid)?;
        let blob = crypto::encrypt(
            &key,
            &Self::vault_aad(&meta.account_uuid, &uuid),
            &Self::vault_name_plain(&name)?,
        )?;
        self.conn.execute(
            "INSERT INTO vaults(account_uuid, vault_uuid, data, key_version) VALUES(?1, ?2, ?3, 2)",
            params![meta.account_uuid, uuid, blob],
        )?;
        Ok(VaultSummary {
            uuid,
            name,
            item_count: 0,
        })
    }

    pub fn rename_vault(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        uuid: &str,
        name: &str,
    ) -> Result<(), StoreError> {
        let name = Self::clean_vault_name(name)?;
        let key = Self::vault_key(master, uuid)?;
        let aad = Self::vault_aad(&meta.account_uuid, uuid);
        let (existing, key_version): (Vec<u8>, i64) = self
            .conn
            .query_row(
                "SELECT data, key_version FROM vaults WHERE account_uuid = ?1 AND vault_uuid = ?2",
                params![meta.account_uuid, uuid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        // Decrypt first: proves the row belongs to this account before writing.
        self.open_vault_name(master, &meta.account_uuid, uuid, key_version, &existing)?;
        let blob = crypto::encrypt(&key, &aad, &Self::vault_name_plain(&name)?)?;
        self.conn.execute(
            "UPDATE vaults SET data = ?1, key_version = 2
             WHERE account_uuid = ?2 AND vault_uuid = ?3",
            params![blob, meta.account_uuid, uuid],
        )?;
        Ok(())
    }

    /// True when this account has a vault with that uuid that decrypts under the
    /// current master key.
    pub fn vault_exists(
        &self,
        master: &SymKey,
        meta: &VaultMeta,
        uuid: &str,
    ) -> Result<bool, StoreError> {
        let row: Option<(Vec<u8>, i64)> = self
            .conn
            .query_row(
                "SELECT data, key_version FROM vaults WHERE account_uuid = ?1 AND vault_uuid = ?2",
                params![meta.account_uuid, uuid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((blob, key_version)) = row else {
            return Ok(false);
        };
        Ok(self
            .open_vault_name(master, &meta.account_uuid, uuid, key_version, &blob)
            .is_ok())
    }

    fn clean_vault_name(name: &str) -> Result<String, StoreError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(StoreError::Invalid("a vault needs a name".into()));
        }
        if name.chars().count() > 48 {
            return Err(StoreError::Invalid(
                "vault names are limited to 48 characters".into(),
            ));
        }
        Ok(name.to_string())
    }
}
