//! Windows Hello unlock: open the vault without typing the master password.
//!
//! Enrolment wraps the 32-byte master key with a CNG key. The key lives in the
//! TPM-backed `Microsoft Platform Crypto Provider`, carries the
//! `NCRYPT_UI_PROTECT_KEY_FLAG` UI policy, and the provider refuses every
//! private-key operation until Windows Hello has verified the user. The prompt
//! therefore happens *inside* `NCryptDecrypt`: the wrapped blob on disk is
//! useless to a process that cannot produce that gesture, and the key never
//! leaves the TPM.
//!
//! What is stored: `hello(vault_uuid, mechanism, wrapped, created_at)`, where
//! `wrapped` is RSA-PKCS#1 ciphertext of the master key. No password hash, no
//! biometric data, nothing secret in the clear. The master password remains the
//! fallback and the only credential: `disable` deletes the row and the CNG key.
//!
//! Measured on this machine before choosing (2026-11-14, throwaway probe; the
//! output is quoted in the change report):
//! * `Microsoft Passport Key Storage Provider` opens and lists RSA, but
//!   `NCryptCreatePersistedKey` fails with 0x80090027 (NTE_INVALID_PARAMETER):
//!   Passport keys exist only with a Windows Hello for Business container.
//! * `Microsoft Platform Crypto Provider` (TPM) creates a persisted RSA key,
//!   accepts the protect UI policy, and `NCryptFinalizeKey` spawns
//!   `CredentialUIBroker.exe` and blocks on the Hello prompt.
//! * DPAPI (`CryptProtectData`/`CryptUnprotectData`) round-trips. It is *not*
//!   shipped: DPAPI answers any process running as the same user, so a consent
//!   prompt would be the only gate and would not be enforced by the crypto.
//!
//! Platform-specific code is behind `#[cfg(windows)]` and reached through the
//! [`Protector`] trait, so the enrolment/storage logic is testable with an
//! in-memory protector. That protector lives in `tests/hello.rs`, i.e. in a
//! separate test binary: this library ships no mock and no fallback.

use crate::crypto::SymKey;
use crate::store::{Store, StoreError, VaultMeta};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// How the master key is wrapped. Persisted per vault in `hello.mechanism`, so
/// the state the user sees is the mechanism that actually wrapped the key;
/// there is no silent runtime fallback between mechanisms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// Persisted RSA key in the TPM-backed CNG provider, UI-protected.
    TpmKey,
}

impl Mechanism {
    /// Stable identifier written to `hello.mechanism`.
    pub fn id(self) -> &'static str {
        match self {
            Mechanism::TpmKey => "tpm-key",
        }
    }

    /// Sentence shown in Settings when this mechanism is enrolled.
    pub fn label(self) -> &'static str {
        match self {
            Mechanism::TpmKey => "Windows Hello (TPM-backed key)",
        }
    }

    /// Read back a `hello.mechanism` value. `None` means a row written by a
    /// build this one does not understand — reported, never guessed at.
    pub fn from_id(raw: &str) -> Option<Mechanism> {
        match raw {
            "tpm-key" => Some(Mechanism::TpmKey),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HelloError {
    #[error("{0}")]
    Store(#[from] StoreError),
    /// This machine cannot offer the mechanism right now (no TPM, provider
    /// missing, provider refuses RSA). The text says which.
    #[error("Windows Hello unlock is not available: {0}")]
    Unavailable(String),
    /// This build has no Windows implementation at all.
    #[error("Windows Hello unlock is only available on Windows")]
    Unsupported,
    #[error("Windows Hello unlock is not set up for this vault")]
    NotEnrolled,
    /// The row exists but the CNG key behind it does not (TPM cleared, key
    /// removed by another tool). Re-enrolling fixes it.
    #[error("the Windows Hello key for this vault is missing — enable it again in Settings")]
    MissingKey,
    #[error("Windows Hello was cancelled")]
    Cancelled,
    #[error("Windows Hello could not unwrap the vault key: {0}")]
    Platform(String),
    /// The unwrapped bytes do not open this vault (swapped blob, wrong vault).
    #[error("the Windows Hello key does not open this vault")]
    WrongKey,
    #[error("this vault is enrolled with {0}, which this build cannot use")]
    UnknownMechanism(String),
}

/// Enrolment state for one vault, as the UI needs it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HelloStatus {
    /// This build and this machine can use Hello: the button may be offered.
    pub available: bool,
    /// A wrapped key exists for this vault.
    pub enrolled: bool,
    /// `""` while not enrolled, else [`Mechanism::id`].
    pub mechanism: String,
    /// `""` while not enrolled, else [`Mechanism::label`].
    pub label: String,
    /// Unix milliseconds of the enrolment row, `None` while not enrolled.
    pub created_at: Option<u64>,
    /// Why `available` is false, when that is known; otherwise `None`.
    pub detail: Option<String>,
}

/// Wraps and unwraps the master key behind a user gesture.
///
/// Implemented by the Windows CNG protector in production and by an in-memory
/// protector in tests (never compiled into the shipped binary). Nothing above
/// this trait knows how the wrapping is done.
pub trait Protector: Send + Sync {
    /// Which mechanism this protector uses and whether it works right now.
    /// `Err(Unavailable | Unsupported)` means the UI must not offer enrolment.
    fn probe(&self) -> Result<Mechanism, HelloError>;
    /// Wrap `secret` under the gesture-protected key named `name`, replacing
    /// any key of that name left behind by an earlier enrolment.
    fn protect(&self, name: &str, secret: &[u8]) -> Result<Vec<u8>, HelloError>;
    /// Unwrap. Prompts the user; `Cancelled` when they decline.
    fn unprotect(&self, name: &str, blob: &[u8]) -> Result<SymKey, HelloError>;
    /// Delete the wrapping key. `MissingKey` when it is already gone.
    fn forget(&self, name: &str) -> Result<(), HelloError>;
    /// Whether the wrapping key still exists. Never prompts: a key deleted by a
    /// TPM reset must be reported as gone, not discovered at unlock time.
    fn has_key(&self, name: &str) -> bool;
}

/// The protector this build uses. Injected into [`crate::session::VaultState`]
/// so tests can substitute one; production always calls this.
pub fn platform_protector() -> Box<dyn Protector> {
    #[cfg(windows)]
    {
        Box::new(windows::TpmProtector)
    }
    #[cfg(not(windows))]
    {
        Box::new(unsupported::NoHello)
    }
}

/// The CNG key is named after the vault: one key per vault, no shared secret,
/// and the name is derived rather than stored so a reset database cannot
/// silently point at the wrong key.
fn key_name(vault_uuid: &str) -> String {
    format!("kestrel-hello-v1-{vault_uuid}")
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0)
}

struct Row {
    mechanism: String,
    wrapped: Vec<u8>,
    created_at: i64,
}

fn read_row(store: &Store, vault_uuid: &str) -> Result<Option<Row>, HelloError> {
    Ok(store
        .conn()
        .query_row(
            "SELECT mechanism, wrapped, created_at FROM hello WHERE vault_uuid = ?1",
            params![vault_uuid],
            |row| {
                Ok(Row {
                    mechanism: row.get(0)?,
                    wrapped: row.get(1)?,
                    created_at: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(StoreError::from)?)
}

fn write_row(
    store: &Store,
    vault_uuid: &str,
    mechanism: Mechanism,
    wrapped: &[u8],
) -> Result<(), HelloError> {
    let changed = store.conn().execute(
        "INSERT INTO hello(vault_uuid, mechanism, wrapped, created_at)
         VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(vault_uuid) DO UPDATE SET
             mechanism  = excluded.mechanism,
             wrapped    = excluded.wrapped,
             created_at = excluded.created_at",
        params![vault_uuid, mechanism.id(), wrapped, now_millis() as i64],
    );
    changed.map_err(StoreError::from)?;
    Ok(())
}

fn delete_row(store: &Store, vault_uuid: &str) -> Result<(), HelloError> {
    store
        .conn()
        .execute("DELETE FROM hello WHERE vault_uuid = ?1", params![vault_uuid])
        .map_err(StoreError::from)?;
    Ok(())
}

/// Current state for this vault. Safe to call while locked: it reads one row
/// plus the provider's availability, never a secret.
pub fn status(
    store: &Store,
    meta: &VaultMeta,
    protector: &dyn Protector,
) -> Result<HelloStatus, HelloError> {
    let row = read_row(store, &meta.vault_uuid)?;
    let probe = protector.probe();
    // A row without its key is not an enrolment: the button it would offer can
    // only fail. Reporting it as absent is what makes "enable" repair the state
    // (enrolment replaces both the row and the key).
    let key_present = row.is_some() && protector.has_key(&key_name(&meta.vault_uuid));
    let mut status = HelloStatus {
        available: probe.is_ok(),
        enrolled: key_present,
        mechanism: String::new(),
        label: String::new(),
        created_at: None,
        detail: probe.err().map(|error| error.to_string()),
    };
    if let Some(row) = row {
        if !key_present {
            status.detail.get_or_insert_with(|| {
                "the Windows Hello key for this vault is gone; enable it again to replace it"
                    .to_string()
            });
            return Ok(status);
        }
        match Mechanism::from_id(&row.mechanism) {
            Some(mechanism) => {
                status.mechanism = mechanism.id().to_string();
                status.label = mechanism.label().to_string();
            }
            // A row written by a newer build is reported, never guessed at.
            None => {
                status.available = false;
                status.detail = Some(format!(
                    "this vault is enrolled with an unknown mechanism ({})",
                    row.mechanism
                ));
            }
        }
        status.created_at = Some(row.created_at.max(0) as u64);
    }
    Ok(status)
}

/// Wrap the master key and store the row. Only meaningful for an unlocked
/// vault, which is enforced by the caller ([`crate::session::VaultState`]).
/// Re-enrolling replaces the previous key, so a stale TPM state is recoverable
/// by pressing the button again.
pub fn enroll(
    store: &Store,
    master: &SymKey,
    meta: &VaultMeta,
    protector: &dyn Protector,
) -> Result<HelloStatus, HelloError> {
    let mechanism = protector.probe()?;
    let name = key_name(&meta.vault_uuid);
    let secret = master.to_bytes();
    // `protect` replaces any key already under this name, which is what makes a
    // second enrolment work after a TPM reset or a crash mid-enrolment.
    let wrapped = protector.protect(&name, &secret[..])?;
    if let Err(error) = write_row(store, &meta.vault_uuid, mechanism, &wrapped) {
        // No row means the key would be unreachable; do not leave it behind.
        let _ = protector.forget(&name);
        return Err(error);
    }
    status(store, meta, protector)
}

/// Unwrap the master key and prove it opens this vault. The returned key is
/// only handed to the session after the authenticated check in [`verify`].
pub fn unlock(
    store: &Store,
    meta: &VaultMeta,
    protector: &dyn Protector,
) -> Result<SymKey, HelloError> {
    let row = read_row(store, &meta.vault_uuid)?.ok_or(HelloError::NotEnrolled)?;
    let mechanism = Mechanism::from_id(&row.mechanism)
        .ok_or_else(|| HelloError::UnknownMechanism(row.mechanism.clone()))?;
    if mechanism != protector.probe()? {
        return Err(HelloError::UnknownMechanism(mechanism.id().to_string()));
    }
    let master = protector.unprotect(&key_name(&meta.vault_uuid), &row.wrapped)?;
    verify(store, &master, meta)?;
    Ok(master)
}

/// Drop the enrolment. The CNG key goes first: if that fails the row stays, so
/// the user can retry rather than being left with an invisible TPM key. A key
/// that is already gone is not an error.
pub fn disable(
    store: &Store,
    meta: &VaultMeta,
    protector: &dyn Protector,
) -> Result<HelloStatus, HelloError> {
    match protector.forget(&key_name(&meta.vault_uuid)) {
        Ok(()) | Err(HelloError::MissingKey) | Err(HelloError::Unsupported) => {}
        Err(error) => return Err(error),
    }
    delete_row(store, &meta.vault_uuid)?;
    status(store, meta, protector)
}

/// Drop an enrolment whose wrapped key is known to be stale.
///
/// A password change re-keys the master key, so a row that survived it could
/// only offer an unlock that fails the verifier. The row is authoritative: it
/// is deleted even if the key store refuses to remove the CNG key (which then
/// holds ciphertext of a key that no longer opens anything).
pub fn invalidate(store: &Store, protector: &dyn Protector) -> Result<(), HelloError> {
    // The master key is account-wide: a re-key invalidates every vault's
    // wrapped copy, not just the one that was active.
    let uuids: Vec<String> = {
        let mut stmt = store
            .conn()
            .prepare("SELECT vault_uuid FROM hello")
            .map_err(StoreError::from)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(StoreError::from)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::from)?
    };
    for uuid in &uuids {
        let _ = protector.forget(&key_name(uuid));
    }
    store
        .conn()
        .execute("DELETE FROM hello", [])
        .map_err(StoreError::from)?;
    Ok(())
}

/// A wrong key fails here: decrypting a real object under a derived subkey is
/// authenticated, so this is the same proof `Store::unlock` gets from the
/// password. Legacy rows are re-sealed exactly as they are after a password
/// unlock, so both entry paths leave the database in the same shape.
fn verify(store: &Store, master: &SymKey, meta: &VaultMeta) -> Result<(), HelloError> {
    let vaults = store.list_vaults(master, meta).map_err(|error| match error {
        // A key that cannot authenticate a vault name is the wrong key. Saying
        // "authentication failed" would reach the UI as a master-password
        // error, which is not what the user did.
        StoreError::Crypto(_) => HelloError::WrongKey,
        other => HelloError::Store(other),
    })?;
    if vaults.is_empty() {
        return Err(HelloError::WrongKey);
    }
    store.backfill_search_index(master, meta)?;
    store.migrate_encrypted(master, meta)?;
    Ok(())
}

#[cfg(not(windows))]
mod unsupported {
    use super::{HelloError, Mechanism, Protector, SymKey};

    /// Non-Windows builds have no Hello at all; every call says so instead of
    /// pretending. This is the shipped implementation on macOS/Linux, not a
    /// test double.
    pub(super) struct NoHello;

    impl Protector for NoHello {
        fn probe(&self) -> Result<Mechanism, HelloError> {
            Err(HelloError::Unsupported)
        }
        fn protect(&self, _name: &str, _secret: &[u8]) -> Result<Vec<u8>, HelloError> {
            Err(HelloError::Unsupported)
        }
        fn unprotect(&self, _name: &str, _blob: &[u8]) -> Result<SymKey, HelloError> {
            Err(HelloError::Unsupported)
        }
        fn forget(&self, _name: &str) -> Result<(), HelloError> {
            Err(HelloError::Unsupported)
        }
        fn has_key(&self, _name: &str) -> bool {
            false
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::{HelloError, Mechanism, Protector};
    use crate::crypto::SymKey;
    use windows_sys::Win32::Security::Cryptography::{
        NCryptCreatePersistedKey, NCryptDeleteKey, NCryptDecrypt, NCryptEncrypt,
        NCryptFinalizeKey, NCryptFreeObject, NCryptIsAlgSupported, NCryptOpenKey,
        NCryptOpenStorageProvider, NCryptSetProperty, NCRYPT_FLAGS, NCRYPT_HANDLE,
        NCRYPT_KEY_HANDLE, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_RSA_ALGORITHM,
        NCRYPT_UI_POLICY, NCRYPT_UI_POLICY_PROPERTY, NCRYPT_UI_PROTECT_KEY_FLAG,
    };

    /// The TPM-backed key store. Passport is *not* used: it refuses to create
    /// keys without a Windows Hello for Business container (NTE_INVALID_PARAMETER),
    /// and the key must exist for a local account too.
    const PROVIDER: &str = "Microsoft Platform Crypto Provider";

    // HRESULTs observed on this machine and named after `certutil -error`.
    const NTE_NOT_FOUND: i32 = 0x8009_0011_u32 as i32;
    const NTE_KEYSET_NOT_DEF: i32 = 0x8009_0019_u32 as i32;
    const NTE_INVALID_HANDLE: i32 = 0x8009_0026_u32 as i32;
    const NTE_INVALID_PARAMETER: i32 = 0x8009_0027_u32 as i32;
    const NTE_DEVICE_NOT_READY: i32 = 0x8009_0030_u32 as i32;
    const NTE_AUTHENTICATION_IGNORED: i32 = 0x8009_0031_u32 as i32;
    const NTE_USER_CANCELLED: i32 = 0x8009_0045_u32 as i32;
    const ERROR_CANCELLED: i32 = 0x8007_046D_u32 as i32;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Turn a CNG status into a typed error. Cancellation and a missing key are
    /// the two the UI reacts to; everything else keeps its numeric code so a
    /// report can be acted on instead of being flattened into "failed".
    fn check(status: i32, context: &str) -> Result<(), HelloError> {
        match status {
            0 => Ok(()),
            ERROR_CANCELLED | NTE_USER_CANCELLED | NTE_AUTHENTICATION_IGNORED => {
                Err(HelloError::Cancelled)
            }
            NTE_NOT_FOUND | NTE_KEYSET_NOT_DEF | NTE_INVALID_HANDLE => {
                Err(HelloError::MissingKey)
            }
            NTE_DEVICE_NOT_READY => Err(HelloError::Unavailable(
                "the TPM is not ready (disabled, cleared or still starting)".to_string(),
            )),
            other => Err(HelloError::Platform(format!(
                "{context}: 0x{:08X}",
                other as u32
            ))),
        }
    }

    struct Provider(NCRYPT_PROV_HANDLE);

    impl Provider {
        fn open() -> Result<Self, HelloError> {
            let mut handle: NCRYPT_PROV_HANDLE = 0;
            let status = unsafe {
                NCryptOpenStorageProvider(&mut handle, wide(PROVIDER).as_ptr(), 0)
            };
            match check(status, "opening the TPM key store") {
                Ok(()) => Ok(Provider(handle)),
                // Neither of these can describe a working provider, and both
                // mean the same thing to a user: no TPM key store here.
                Err(HelloError::MissingKey) | Err(HelloError::Platform(_))
                    if status == NTE_INVALID_PARAMETER =>
                {
                    Err(HelloError::Unavailable(format!(
                        "the {PROVIDER} is not installed"
                    )))
                }
                Err(error) => Err(error),
            }
        }

        fn supports_rsa(&self) -> bool {
            unsafe { NCryptIsAlgSupported(self.0, NCRYPT_RSA_ALGORITHM, 0) == 0 }
        }

        fn open_key(&self, name: &str) -> Result<Key, HelloError> {
            let mut handle: NCRYPT_KEY_HANDLE = 0;
            let status = unsafe {
                NCryptOpenKey(self.0, &mut handle, wide(name).as_ptr(), 0, 0)
            };
            check(status, "opening the Hello key")?;
            Ok(Key(handle))
        }

        fn create_key(&self, name: &str) -> Result<Key, HelloError> {
            let mut handle: NCRYPT_KEY_HANDLE = 0;
            let status = unsafe {
                NCryptCreatePersistedKey(
                    self.0,
                    &mut handle,
                    NCRYPT_RSA_ALGORITHM,
                    wide(name).as_ptr(),
                    0,
                    0,
                )
            };
            check(status, "creating the Hello key")?;
            Ok(Key(handle))
        }
    }

    impl Drop for Provider {
        fn drop(&mut self) {
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }

    struct Key(NCRYPT_KEY_HANDLE);

    impl Key {
        /// The UI policy is what makes the key answer only after a gesture.
        /// `NCRYPT_UI_PROTECT_KEY_FLAG` means "Windows Hello on creation and on
        /// every use"; the strings are what the prompt shows.
        fn protect_with_hello(&self) -> Result<(), HelloError> {
            let title = wide("Kestrel");
            let friendly = wide("Unlock Kestrel");
            let description = wide("Unlocks your local Kestrel vault");
            let policy = NCRYPT_UI_POLICY {
                dwVersion: 1,
                dwFlags: NCRYPT_UI_PROTECT_KEY_FLAG,
                pszCreationTitle: title.as_ptr(),
                pszFriendlyName: friendly.as_ptr(),
                pszDescription: description.as_ptr(),
            };
            let status = unsafe {
                NCryptSetProperty(
                    self.0,
                    NCRYPT_UI_POLICY_PROPERTY,
                    &policy as *const NCRYPT_UI_POLICY as *const u8,
                    std::mem::size_of::<NCRYPT_UI_POLICY>() as u32,
                    0,
                )
            };
            check(status, "setting the Hello UI policy")
        }

        /// Commits the key and raises the enrolment prompt.
        fn finalize(&self) -> Result<(), HelloError> {
            check(unsafe { NCryptFinalizeKey(self.0, 0) }, "finalizing the Hello key")
        }

        fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, HelloError> {
            let flags: NCRYPT_FLAGS = NCRYPT_PAD_PKCS1_FLAG;
            let mut needed = 0u32;
            let status = unsafe {
                NCryptEncrypt(
                    self.0,
                    plaintext.as_ptr(),
                    plaintext.len() as u32,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    0,
                    &mut needed,
                    flags,
                )
            };
            // The size query is expected to report "buffer too small".
            if status != 0 && needed == 0 {
                return Err(HelloError::Platform(format!(
                    "sizing the Hello ciphertext: 0x{:08X}",
                    status as u32
                )));
            }
            let mut sealed = vec![0u8; needed as usize];
            let mut written = 0u32;
            let status = unsafe {
                NCryptEncrypt(
                    self.0,
                    plaintext.as_ptr(),
                    plaintext.len() as u32,
                    std::ptr::null(),
                    sealed.as_mut_ptr(),
                    sealed.len() as u32,
                    &mut written,
                    flags,
                )
            };
            check(status, "wrapping the vault key")?;
            sealed.truncate(written as usize);
            Ok(sealed)
        }

        fn decrypt(&self, sealed: &[u8]) -> Result<SymKey, HelloError> {
            let flags: NCRYPT_FLAGS = NCRYPT_PAD_PKCS1_FLAG;
            let mut needed = 0u32;
            let status = unsafe {
                NCryptDecrypt(
                    self.0,
                    sealed.as_ptr(),
                    sealed.len() as u32,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    0,
                    &mut needed,
                    flags,
                )
            };
            if status != 0 && needed == 0 {
                return Err(HelloError::Platform(format!(
                    "sizing the Hello plaintext: 0x{:08X}",
                    status as u32
                )));
            }
            let mut plain = zeroize::Zeroizing::new(vec![0u8; needed as usize]);
            let mut written = 0u32;
            let status = unsafe {
                NCryptDecrypt(
                    self.0,
                    sealed.as_ptr(),
                    sealed.len() as u32,
                    std::ptr::null(),
                    plain.as_mut_ptr(),
                    plain.len() as u32,
                    &mut written,
                    flags,
                )
            };
            check(status, "unwrapping the vault key")?;
            plain.truncate(written as usize);
            SymKey::from_slice(&plain).map_err(|_| {
                HelloError::Platform("the unwrapped key material is not 32 bytes".to_string())
            })
        }

        /// `NCryptDeleteKey` frees the handle whether or not it succeeds, so the
        /// destructor must not run afterwards.
        fn delete(self) -> Result<(), HelloError> {
            let status = unsafe { NCryptDeleteKey(self.0, 0) };
            std::mem::forget(self);
            check(status, "deleting the Hello key")
        }
    }

    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                NCryptFreeObject(self.0 as NCRYPT_HANDLE);
            }
        }
    }

    pub(super) struct TpmProtector;

    impl Protector for TpmProtector {
        /// Deliberately side-effect free: `status` is called on the locked
        /// Gate, and a TPM write there would be wrong (and slow). What this
        /// proves is that the key store exists and offers RSA; whether a key
        /// can actually be created is answered at enrolment by the provider's
        /// own code (`NTE_DEVICE_NOT_READY` maps to `Unavailable`).
        fn probe(&self) -> Result<Mechanism, HelloError> {
            let provider = Provider::open()?;
            if !provider.supports_rsa() {
                return Err(HelloError::Unavailable(
                    "the TPM key store does not offer RSA".to_string(),
                ));
            }
            Ok(Mechanism::TpmKey)
        }

        fn protect(&self, name: &str, secret: &[u8]) -> Result<Vec<u8>, HelloError> {
            let provider = Provider::open()?;
            // A key of this name can survive a re-enrolment or a crash mid-way;
            // CNG refuses a duplicate name, so clear it first.
            if let Ok(existing) = provider.open_key(name) {
                existing.delete()?;
            }
            let key = provider.create_key(name)?;
            key.protect_with_hello()?;
            key.finalize()?;
            let sealed = key.encrypt(secret)?;
            // Best effort: the key stays in the TPM for `unprotect`.
            Ok(sealed)
        }

        fn unprotect(&self, name: &str, blob: &[u8]) -> Result<SymKey, HelloError> {
            let provider = Provider::open()?;
            let key = provider.open_key(name)?;
            key.decrypt(blob)
        }

        /// Opening the key does not prompt: only finalize and decrypt do.
        fn has_key(&self, name: &str) -> bool {
            Provider::open()
                .ok()
                .and_then(|provider| provider.open_key(name).ok())
                .is_some()
        }

        fn forget(&self, name: &str) -> Result<(), HelloError> {
            let provider = Provider::open()?;
            match provider.open_key(name) {
                Ok(key) => key.delete(),
                // Nothing of that name: already disabled, or the TPM was
                // cleared, which also removed the key.
                Err(HelloError::MissingKey) => Ok(()),
                Err(error) => Err(error),
            }
        }
    }

}
