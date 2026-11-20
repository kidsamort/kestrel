//! Encrypted local store.
//!
//! A SQLite database whose rows carry opaque ciphertext (`data BLOB`) plus
//! non-secret identity columns (`account_uuid`, `vault_uuid`, `item_uuid`,
//! `version`). Everything sensitive lives inside the blob; the surrounding
//! columns only support indexing, ordering and conflict bookkeeping.
//!
//! The module is split by responsibility: schema upgrades live in [`migrate`],
//! vault lifecycle in [`vaults`], account re-keying in [`rotation`], item rows
//! in [`items`], paging/counts/search in [`query`], attachment row helpers in
//! [`attachments`], the sync account and its envelopes in [`account`], this
//! device's keypairs in [`devices`] and the per-item sync bookkeeping (clocks,
//! dirty flags, conflicts) in [`sync`]. This file owns the connection, the
//! shared constants and the item-independent metadata.

mod account;
mod agent;
mod attachments;
mod autofill;
mod browser;
mod devices;
mod item_keys;
mod items;
mod mcp;
mod migrate;
mod passkeys;
mod prefs;
mod query;
mod recovery;
mod rotation;
pub mod sync;
mod vaults;

pub use account::{
    open_sealed_account, seal_account_key, AccountClaimed, AccountCreated, AccountDevice,
    AccountSecretKey, AccountStatus, EnrolCode, OpenedEnrolment, SealedEnrolment,
};
pub use devices::{agreement_public, agreement_secret, DeviceIdentity, DeviceSecretKeys};
pub(crate) use mcp::GrantRow;
pub use query::{search_text, Counts, Page};
pub use recovery::{RecoveryKit, RecoveryStatus};

use crate::crypto::{self, SymKey, SALT_LEN};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: i64 = 13;

/// The `grants.principal_kind` values. A grant names a principal — who may
/// read — and these are the only two kinds the store writes: an MCP client and
/// a CLI token. The column is text so a future principal needs no table
/// rebuild, but an unknown kind must be refused before it reaches a row.
pub(crate) const GRANT_KIND_MCP: &str = "mcp";
pub(crate) const GRANT_KIND_CLI: &str = "cli";
const VERIFIER_PLAINTEXT: &[u8] = b"kestrel/verifier/v1";
/// Marks that archived versions are sealed with the version-distinguishing
/// AAD (`item-history`). Written by `initialise`, by `change_password` and by
/// `migrate_encrypted`; its presence is what makes the latter a no-op.
const ENC_VERSION_KEY: &str = "enc_version";
const ENC_VERSION_HISTORY_AAD: &[u8] = b"2";
/// The user-written hint that stands in for the master password on the lock
/// screen. Deliberately **unsealed**: it has to be readable before any key
/// exists, and it lives inside the vault file so renaming or moving the file
/// carries it along. The user decides what it reveals.
const PASSWORD_HINT_KEY: &str = "password_hint";
const ITEM_PURPOSE: &[u8] = b"kestrel/v1/items";
const VAULT_PURPOSE: &[u8] = b"kestrel/v1/vault";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("vault is not initialised")]
    NotInitialised,
    #[error("vault is already initialised")]
    AlreadyInitialised,
    #[error("item not found")]
    NotFound,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Invalid(String),
}

pub struct Store {
    conn: Connection,
    path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct VaultMeta {
    pub account_uuid: String,
    pub vault_uuid: String,
    pub salt: Vec<u8>,
    pub verifier: Vec<u8>,
}

/// One vault as the UI sees it: identity, display name, live item count.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSummary {
    pub uuid: String,
    pub name: String,
    pub item_count: i64,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Store, StoreError> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path.as_ref())?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Store {
            conn,
            path: path.as_ref().to_path_buf(),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Raw handle for feature modules that own their own tables. Kept crate
    /// private: nothing outside the core ever touches SQL.
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    fn meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()?)
    }

    fn set_meta(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn is_initialised(&self) -> Result<bool, StoreError> {
        Ok(self.meta("kdf_salt")?.is_some())
    }

    /// The optional, user-written hint. Not encrypted on purpose: the lock
    /// screen must show it before the master password exists, and it travels
    /// with the file because it lives in the vault's own `meta` table.
    pub fn password_hint(&self) -> Result<Option<String>, StoreError> {
        match self.meta(PASSWORD_HINT_KEY)? {
            Some(bytes) => String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| StoreError::Invalid("password hint is not utf-8".to_string())),
            None => Ok(None),
        }
    }

    /// Create the vault for a brand-new master password.
    pub fn initialise(&self, password: &str) -> Result<(SymKey, VaultMeta), StoreError> {
        self.initialise_with_hint(password, None)
    }

    /// [`Store::initialise`] plus an optional password hint, written in the same
    /// pass as the rest of the identity so the hint and the vault it describes
    /// are never out of step.
    pub fn initialise_with_hint(
        &self,
        password: &str,
        hint: Option<&str>,
    ) -> Result<(SymKey, VaultMeta), StoreError> {
        if self.is_initialised()? {
            return Err(StoreError::AlreadyInitialised);
        }
        let salt = crypto::random_bytes::<SALT_LEN>().to_vec();
        let master = crypto::derive_master_key(password, &salt)?;
        let account_uuid = uuid::Uuid::new_v4().to_string();
        let vault_uuid = uuid::Uuid::new_v4().to_string();
        let vault_key = Self::vault_key(&master, &vault_uuid)?;
        let verifier = crypto::encrypt(&vault_key, b"kestrel/verifier", VERIFIER_PLAINTEXT)?;
        self.set_meta("kdf_salt", &salt)?;
        self.set_meta("account_uuid", account_uuid.as_bytes())?;
        self.set_meta("default_vault_uuid", vault_uuid.as_bytes())?;
        self.set_meta("verifier", &verifier)?;
        if let Some(hint) = hint.map(str::trim).filter(|hint| !hint.is_empty()) {
            self.set_meta(PASSWORD_HINT_KEY, hint.as_bytes())?;
        }
        // A brand-new database starts on the current on-disk formats: the
        // per-vault derived key and the history AAD. No legacy fallback runs.
        self.set_meta(ENC_VERSION_KEY, ENC_VERSION_HISTORY_AAD)?;
        let vault_data = crypto::encrypt(
            &vault_key,
            &Self::vault_aad(&account_uuid, &vault_uuid),
            &Self::vault_name_plain("Personal")?,
        )?;
        self.conn.execute(
            "INSERT INTO vaults(account_uuid, vault_uuid, data, key_version) VALUES(?1, ?2, ?3, 2)",
            params![account_uuid, vault_uuid, vault_data],
        )?;
        Ok((
            master,
            VaultMeta {
                account_uuid,
                vault_uuid,
                salt,
                verifier,
            },
        ))
    }
}
