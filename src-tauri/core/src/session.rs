//! Session lifecycle: unlocking, auto-lock, clipboard hygiene.
//!
//! Keys live only inside this process; nothing derived from the master password
//! is ever serialized to the frontend or written to disk in the clear.

use crate::crypto::SymKey;
use crate::generator::{self, GenerateOptions};
use crate::hello::{self, HelloError, HelloStatus, Protector};
use crate::model::{Category, Item, ItemSummary, PasskeyRow, PasskeySecret};
use crate::store::{
    AccountClaimed, AccountCreated, AccountDevice, AccountSecretKey, AccountStatus, Counts,
    DeviceIdentity, DeviceSecretKeys, EnrolCode, Page, RecoveryKit, RecoveryStatus,
    SealedEnrolment, Store, StoreError, VaultMeta, VaultSummary, GRANT_KIND_CLI, GRANT_KIND_MCP,
};
use crate::totp;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub const DEFAULT_AUTOLOCK_SECS: u64 = 300;
pub const CLIPBOARD_CLEAR_SECS: u64 = 30;
/// Upper bound for the timed clipboard wipe; longer intervals defeat the point.
pub const CLIPBOARD_MAX_SECS: u64 = 300;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("{0}")]
    Store(#[from] StoreError),
    #[error("vault is locked")]
    Locked,
    #[error("totp: {0}")]
    Totp(#[from] totp::TotpError),
    #[error("field not found")]
    FieldNotFound,
    #[error("item not found")]
    NotFound,
    #[error("this client has no grant for that field")]
    NotGranted,
    #[error("{0}")]
    Invalid(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("master password must be at least 10 characters")]
    WeakPassword,
    /// A new vault was asked for at a path that already holds something.
    #[error("a file already exists at that path")]
    AlreadyExists,
    #[error("clipboard: {0}")]
    Clipboard(String),
    #[error("{0}")]
    Hello(#[from] HelloError),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStateDto {
    pub initialized: bool,
    pub locked: bool,
    pub item_count: i64,
    pub autolock_seconds: u64,
    pub clipboard_clear_seconds: u64,
    /// The vault this session is scoped to; empty while locked.
    pub vault_uuid: String,
    pub vault_name: String,
    /// How many vaults this account has, so the switcher knows when to collapse.
    pub vault_count: i64,
    /// Unix milliseconds at which the watchdog will lock an unlocked session;
    /// `None` when the vault is already locked.
    pub lock_at: Option<u64>,
}

/// What a recovery-code unlock leaves behind: the vault is open (the key was
/// unwrapped and proved against the verifier) but the *session* is deliberately
/// not created. Until a new master password exists nothing else in the core can
/// reach any data, which is what "after the code, a password" means. The key
/// lives in [`VaultState`]'s pending slot and dies with a lock.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryOpen {
    /// Named so the forced-change screen can say which vault is open.
    pub vault_name: String,
}

/// The finished rotation: the new password is live and the new kit is handed
/// over exactly once. The session is not open yet — [`VaultState::recovery_finish`]
/// is the acknowledgement that the code has been seen. `kit` is `None` only when
/// the rotation succeeded but the new code could not be stored; the caller says
/// so, and the user creates a kit from settings because the password is already
/// live.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCompletion {
    pub vault_name: String,
    pub kit: Option<RecoveryKit>,
}

/// One allowed read for an MCP client: this item, this field. No value, no
/// label — the card resolves those from [`VaultState`] if it wants to show them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpGrant {
    pub client: String,
    pub item_id: String,
    pub field: String,
    pub created_at: i64,
}

/// One stored grant for any principal. `principal_kind` is `mcp` for an MCP
/// client and `cli` for a CLI token; `principal_id` is the client name the
/// grant, and the audit line, are recorded against.
///
/// `expires_at` is a unix timestamp or `None` for a grant with no deadline;
/// `one_shot` marks a grant the next successful read deletes. A deadline in
/// the past is reported as stored but never authorizes a read — the check,
/// not this listing, is the authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessGrant {
    pub principal_kind: String,
    pub principal_id: String,
    pub item_id: String,
    pub field: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub one_shot: bool,
}

/// One recorded read. The value that was read is deliberately absent: the audit
/// answers "who read what, when", never "what did they see".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAuditEntry {
    pub client: String,
    pub item_id: String,
    pub field: String,
    pub at: i64,
}

/// The two principal kinds a grant may name. An unknown kind is a programming
/// error at the call site, so it is refused instead of silently persisting a
/// row no read path would ever consult.
fn grant_kind(raw: &str) -> Result<&'static str, VaultError> {
    match raw {
        GRANT_KIND_MCP => Ok(GRANT_KIND_MCP),
        GRANT_KIND_CLI => Ok(GRANT_KIND_CLI),
        other => Err(VaultError::Invalid(format!(
            "unknown grant principal kind {other:?}"
        ))),
    }
}

/// Map a stored row to the public shape. The store's row type stays private to
/// the crate; this is the only conversion the shell and the SDK see.
fn access_grant(row: crate::store::GrantRow) -> AccessGrant {
    AccessGrant {
        principal_kind: row.principal_kind,
        principal_id: row.principal_id,
        item_id: row.item_id,
        field: row.field,
        created_at: row.created_at,
        expires_at: row.expires_at,
        one_shot: row.one_shot,
    }
}

/// Lower-case hex for the public credential id. Kept here rather than in the
/// private store module so the session (and, through it, the shell) can name
/// the conversion without exposing the storage module.
fn credential_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// One credential as the detail pane may show it. `credential_id` is the
/// public identifier in lower-case hex; the private key is not part of this
/// shape and no command can ask for it alongside this metadata.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyInfo {
    pub credential_id: String,
    pub item_id: String,
    pub rp_id: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpDto {
    pub code: String,
    pub seconds_remaining: u64,
    /// Seconds per cycle, honoured from the `otpauth://` secret (default 30).
    pub period: u64,
}

/// One explicit `browser_sites` row. A missing row means `ask`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserRule {
    pub origin: String,
    pub mode: String,
    pub updated_at: i64,
}

/// One field of a [`BrowserItem`]: id, label and kind, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserField {
    pub id: String,
    pub label: String,
    pub kind: String,
}

/// What `browser.items` returns for one matching login. The chip needs a
/// title, an origin and the field ids it will ask to reveal after the click;
/// it never needs, and never receives, a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserItem {
    pub id: String,
    pub title: String,
    pub category: String,
    pub fields: Vec<BrowserField>,
}

struct Session {
    master: SymKey,
    meta: VaultMeta,
    last_activity: Instant,
}

/// A master key unwrapped from a printed recovery code and proved against the
/// verifier, waiting for the forced new master password and then for the user to
/// acknowledge the replacement code. It is not a session: no command can read
/// through it, because every data command needs [`Session`]. `rotated` marks the
/// second stage (new key live, waiting for [`VaultState::recovery_finish`]), and
/// `opened` lets the auto-lock clock age the whole thing out.
struct PendingRecovery {
    master: SymKey,
    meta: VaultMeta,
    vault_name: String,
    opened: Instant,
    rotated: bool,
}

/// Whether any URL saved on `item` belongs to the canonical `origin`. Both
/// the dedicated URL list and `url`-kind fields count: the default login
/// template stores its website as a field, while the editor may also add
/// explicit URLs.
fn item_matches_origin(item: &Item, origin: &str) -> bool {
    item.urls
        .iter()
        .any(|url| Store::browser_url_matches(origin, url))
        || item
            .fields
            .iter()
            .filter(|field| field.kind == "url")
            .any(|field| Store::browser_url_matches(origin, &field.value))
}

/// Why a data command refuses before the user has picked a file.
const NO_VAULT: &str = "no vault is open";

/// The app's single vault session: which file is open, the unlocked key derived
/// from the master password, and the timers around it.
///
/// Lock order is fixed as `store -> autolock -> clipboard -> session -> pending`:
/// a helper that holds one guard never waits for an earlier one. Swapping the
/// file ([`VaultState::open_at`] / [`VaultState::create_at`]) takes the store
/// guard first and holds it while it replaces the session, so no other command
/// can observe half a switch.
pub struct VaultState {
    /// The selected vault, or `None` before one is chosen. Concurrent swaps and
    /// access go through this mutex; the value is only ever replaced, never
    /// cleared, so a `Some` stays `Some` for the life of a guard.
    store: Mutex<Option<Store>>,
    session: Mutex<Option<Session>>,
    /// Recovery keys that were unwrapped but whose forced password change has
    /// not happened yet. Last in the lock order, so it is only ever taken on its
    /// own or after everything above it.
    pending: Mutex<Option<PendingRecovery>>,
    autolock: Mutex<Duration>,
    clipboard: Mutex<Duration>,
    /// How Windows Hello wraps the master key. Production always uses
    /// [`hello::platform_protector`]; the seam exists so the enrolment and
    /// unlock paths can be exercised without a gesture.
    hello: Box<dyn Protector>,
}

/// A borrow of the selected store. Holding it also holds the location mutex, so
/// the vault cannot be swapped underneath a command. [`VaultState::db`] only
/// builds one after finding a store, and nothing ever clears the slot, so the
/// deref is total.
pub struct StoreGuard<'a> {
    slot: MutexGuard<'a, Option<Store>>,
}

impl std::ops::Deref for StoreGuard<'_> {
    type Target = Store;
    fn deref(&self) -> &Store {
        match self.slot.as_ref() {
            Some(store) => store,
            None => unreachable!("a store guard implies a selected vault"),
        }
    }
}

impl std::ops::DerefMut for StoreGuard<'_> {
    fn deref_mut(&mut self) -> &mut Store {
        match self.slot.as_mut() {
            Some(store) => store,
            None => unreachable!("a store guard implies a selected vault"),
        }
    }
}

/// The intervals a vault stored last time, or the documented defaults.
///
/// A vault that never saved one gets the default rather than a guess: the
/// auto-lock watchdog and the clipboard wipe are safety defaults, and reading a
/// damaged row as "no auto-lock" would quietly weaken the vault.
fn stored_intervals(store: &Store) -> (Duration, Duration) {
    let autolock = store
        .autolock_seconds()
        .ok()
        .flatten()
        .map(|seconds| Duration::from_secs(seconds.clamp(15, 86_400)))
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_AUTOLOCK_SECS));
    let clipboard = store
        .clipboard_clear_seconds()
        .ok()
        .flatten()
        .map(|seconds| Duration::from_secs(seconds.min(CLIPBOARD_MAX_SECS)))
        .unwrap_or_else(|| Duration::from_secs(CLIPBOARD_CLEAR_SECS));
    (autolock, clipboard)
}

impl VaultState {
    /// Open the vault file at `db_path`. A file that vanished or cannot be read
    /// is an ordinary error, never a panic: the caller chooses between offering
    /// another file and starting over.
    pub fn open(db_path: PathBuf) -> Result<VaultState, VaultError> {
        Self::open_with_protector(db_path, hello::platform_protector())
    }

    /// No vault selected yet. [`VaultState::path`] is `None`, status reads show
    /// an empty vault, and every data command answers `no vault is open`.
    pub fn unselected() -> Result<VaultState, VaultError> {
        Self::unselected_with_protector(hello::platform_protector())
    }

    /// Same as [`VaultState::open`] with an explicit protector. The desktop
    /// app never calls this; tests use it to run the whole session path with an
    /// in-memory protector instead of a Hello prompt.
    pub fn open_with_protector(
        db_path: PathBuf,
        protector: Box<dyn Protector>,
    ) -> Result<VaultState, VaultError> {
        let store = Store::open(db_path)?;
        let (autolock, clipboard) = stored_intervals(&store);
        Ok(VaultState {
            store: Mutex::new(Some(store)),
            session: Mutex::new(None),
            pending: Mutex::new(None),
            autolock: Mutex::new(autolock),
            clipboard: Mutex::new(clipboard),
            hello: protector,
        })
    }

    /// [`VaultState::unselected`] with an explicit protector.
    pub fn unselected_with_protector(
        protector: Box<dyn Protector>,
    ) -> Result<VaultState, VaultError> {
        Ok(VaultState {
            store: Mutex::new(None),
            session: Mutex::new(None),
            pending: Mutex::new(None),
            autolock: Mutex::new(Duration::from_secs(DEFAULT_AUTOLOCK_SECS)),
            clipboard: Mutex::new(Duration::from_secs(CLIPBOARD_CLEAR_SECS)),
            hello: protector,
        })
    }

    fn db(&self) -> Result<StoreGuard<'_>, VaultError> {
        let slot = self.store.lock().expect("store mutex");
        if slot.is_none() {
            return Err(VaultError::Invalid(NO_VAULT.to_string()));
        }
        Ok(StoreGuard { slot })
    }

    /// Where this vault lives, or `None` when no vault is selected yet.
    pub fn path(&self) -> Option<PathBuf> {
        self.store
            .lock()
            .expect("store mutex")
            .as_ref()
            .map(|store| store.path().to_path_buf())
    }

    /// Point at another file: the open session is dropped (which zeroizes the
    /// master key) and the store is replaced. A file that does not exist, or
    /// that SQLite refuses, leaves the current vault selected and untouched.
    pub fn open_at(&self, path: PathBuf) -> Result<VaultStateDto, VaultError> {
        let metadata = std::fs::metadata(&path)?;
        if metadata.is_dir() {
            return Err(VaultError::Invalid(format!(
                "{} is a directory, not a vault",
                path.display()
            )));
        }
        // Build the new store before touching the live one: a refusal must not
        // disturb the vault the user is already looking at.
        //
        // `Store::open` creates the file when it is missing (SQLite's default
        // flags), which is right for `create_at` and wrong here: pointing at a
        // file the user moved away from must be a refusal, not a new empty
        // vault in its place.
        if !path.is_file() {
            return Err(VaultError::Invalid(format!(
                "{} is not a file",
                path.display()
            )));
        }
        let store = Store::open(&path)?;
        // A file that opens but has no salt is not a vault: unlocking it can
        // never succeed, and the gate would show a password prompt that no
        // password satisfies.
        if !store.is_initialised()? {
            return Err(VaultError::Invalid(format!(
                "{} is not a Kestrel vault",
                path.display()
            )));
        }
        {
            // Lock order: store -> session -> pending. `state()` takes the same
            // order, so the two cannot deadlock.
            let (autolock, clipboard) = stored_intervals(&store);
            *self.autolock.lock().expect("autolock mutex") = autolock;
            *self.clipboard.lock().expect("clipboard mutex") = clipboard;
            let mut slot = self.store.lock().expect("store mutex");
            *slot = Some(store);
            *self.session.lock().expect("session mutex") = None;
            *self.pending.lock().expect("recovery mutex") = None;
        }
        self.state()
    }

    /// Create a vault at `path` and open it, unlocked.
    ///
    /// The file must not exist: not only a vault, any file. The password rule is
    /// the same one [`VaultState::create`] applies, and it is checked before the
    /// disk is touched so a rejected password leaves no half-made file.
    pub fn create_at(
        &self,
        path: PathBuf,
        password: &str,
        hint: Option<&str>,
    ) -> Result<VaultStateDto, VaultError> {
        if password.chars().count() < 10 {
            return Err(VaultError::WeakPassword);
        }
        if path.as_os_str().is_empty() {
            return Err(VaultError::Invalid("vault path is empty".to_string()));
        }
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        let store = Store::open(&path)?;
        let (master, meta) = store.initialise_with_hint(password, hint)?;
        // Same uniformity as `create`: a fresh store is already on the current
        // on-disk formats, so this is a no-op that keeps the paths identical.
        store.migrate_encrypted(&master, &meta)?;
        {
            let mut slot = self.store.lock().expect("store mutex");
            *slot = Some(store);
            let mut session = self.session.lock().expect("session mutex");
            *session = Some(Session {
                master,
                meta,
                last_activity: Instant::now(),
            });
            *self.pending.lock().expect("recovery mutex") = None;
        }
        self.state()
    }

    /// The optional, user-written hint. Readable while locked, because it is
    /// stored unsealed in the vault's own metadata; never a secret.
    pub fn password_hint(&self) -> Result<Option<String>, VaultError> {
        Ok(self.db()?.password_hint()?)
    }

    pub fn state(&self) -> Result<VaultStateDto, VaultError> {
        // Lock order everywhere is: store -> autolock -> clipboard -> session.
        let slot = self.store.lock().expect("store mutex");
        let autolock = *self.autolock.lock().expect("autolock mutex");
        let clipboard = *self.clipboard.lock().expect("clipboard mutex");
        let session = self.session.lock().expect("session mutex");
        let Some(store) = slot.as_ref() else {
            // No vault yet: report the shape a first-run screen expects. The
            // caller already has `path()` / `vault_location` to explain why.
            return Ok(VaultStateDto {
                initialized: false,
                locked: true,
                item_count: 0,
                autolock_seconds: autolock.as_secs(),
                clipboard_clear_seconds: clipboard.as_secs(),
                vault_uuid: String::new(),
                vault_name: String::new(),
                vault_count: 0,
                lock_at: None,
            });
        };
        let initialized = store.is_initialised()?;
        let mut vault_uuid = String::new();
        let mut vault_name = String::new();
        let mut vault_count = 0;
        let item_count = match session.as_ref() {
            Some(active) => {
                let vaults = store.list_vaults(&active.master, &active.meta)?;
                vault_uuid = active.meta.vault_uuid.clone();
                vault_name = vaults
                    .iter()
                    .find(|v| v.uuid == vault_uuid)
                    .map(|v| v.name.clone())
                    .unwrap_or_default();
                vault_count = vaults.len() as i64;
                store.live_count(&active.meta)?
            }
            None => 0,
        };
        // Absolute pre-lock deadline: the same clock the watchdog compares
        // `last_activity.elapsed()` against, expressed in unix milliseconds.
        let lock_at = session.as_ref().map(|active| {
            let remaining = autolock.saturating_sub(active.last_activity.elapsed());
            unix_millis_now() + remaining.as_millis() as u64
        });
        Ok(VaultStateDto {
            initialized,
            locked: session.is_none(),
            item_count,
            autolock_seconds: autolock.as_secs(),
            clipboard_clear_seconds: clipboard.as_secs(),
            vault_uuid,
            vault_name,
            vault_count,
            lock_at,
        })
    }

    pub fn create(&self, password: &str) -> Result<VaultStateDto, VaultError> {
        if password.chars().count() < 10 {
            return Err(VaultError::WeakPassword);
        }
        let (master, meta) = self.db()?.initialise(password)?;
        // A fresh store is already on the current format; the call is a no-op
        // but keeps the unlock path uniform. Never hold the session guard here:
        // `state()` locks store before session, so the reverse order deadlocks.
        self.db()?.migrate_encrypted(&master, &meta)?;
        let mut session = self.session.lock().expect("session mutex");
        *session = Some(Session {
            master,
            meta,
            last_activity: Instant::now(),
        });
        drop(session);
        self.state()
    }

    pub fn unlock(&self, password: &str) -> Result<VaultStateDto, VaultError> {
        let (master, meta) = self.db()?.unlock(password)?;
        // Legacy archived blobs are re-sealed here, before the session exists.
        // The store guard is released before the session guard is taken, which
        // preserves the documented `store -> autolock -> clipboard -> session`
        // lock order; holding both in the other order deadlocks with `state()`.
        self.db()?.migrate_encrypted(&master, &meta)?;
        // Items written before per-item keys existed are re-sealed too: only the
        // master key can read them, and a locked vault is never touched. The step
        // is idempotent and commits per vault.
        self.db()?.backfill_item_keys(&master, &meta)?;
        let mut session = self.session.lock().expect("session mutex");
        *session = Some(Session {
            master,
            meta,
            last_activity: Instant::now(),
        });
        drop(session);
        self.state()
    }

    /* ------------------------------------------------------- hello unlock */

    /// Whether this vault has a Hello enrolment and whether this machine can
    /// offer one. Reads one row and the provider's state, never a secret, so it
    /// is safe to call while locked — that is where the Gate needs it.
    pub fn hello_status(&self) -> Result<HelloStatus, VaultError> {
        let store = self.db()?;
        let meta = store.meta_identity()?;
        Ok(hello::status(&store, &meta, self.hello.as_ref())?)
    }

    /// Wrap the master key behind Windows Hello. Requires an unlocked session:
    /// only the live master key is ever wrapped, never a password.
    pub fn hello_enroll(&self) -> Result<HelloStatus, VaultError> {
        // Guards are released before the prompt: `hello::enroll` raises the
        // Hello UI, which must not block every other command on the store.
        //
        // The row belongs to the vault the Gate unlocks (the default one): the
        // master key is account-wide, so the same key wraps either way, and
        // enrolling from a switched vault must not write a row no unlock door
        // can reach.
        let (master, meta) = {
            let store = self.db()?;
            let session = self.session.lock().expect("session mutex");
            let active = session.as_ref().ok_or(VaultError::Locked)?;
            (active.master.clone(), store.meta_identity()?)
        };
        let status = {
            let store = self.db()?;
            hello::enroll(&store, &master, &meta, self.hello.as_ref())?
        };
        self.touch();
        Ok(status)
    }

    /// Drop the enrolment. Allowed while locked: it deletes a local convenience
    /// credential and needs no key material of its own.
    pub fn hello_disable(&self) -> Result<HelloStatus, VaultError> {
        let store = self.db()?;
        let meta = store.meta_identity()?;
        Ok(hello::disable(&store, &meta, self.hello.as_ref())?)
    }

    /// Unlock with the Hello-wrapped key. Mirrors [`VaultState::unlock`]: the
    /// unwrapped key is proved against the vault before it becomes a session,
    /// and legacy rows are re-sealed before the session exists.
    pub fn hello_unlock(&self) -> Result<VaultStateDto, VaultError> {
        let (master, meta) = {
            let store = self.db()?;
            let meta = store.meta_identity()?;
            let master = hello::unlock(&store, &meta, self.hello.as_ref())?;
            (master, meta)
        };
        // The same lazy upgrades the password path runs: a Hello-only user must
        // not stay on the legacy blobs forever, and the backfill is idempotent.
        self.db()?.migrate_encrypted(&master, &meta)?;
        self.db()?.backfill_item_keys(&master, &meta)?;
        let mut session = self.session.lock().expect("session mutex");
        *session = Some(Session {
            master,
            meta,
            last_activity: Instant::now(),
        });
        drop(session);
        self.state()
    }

    /* --------------------------------------------------- recovery kit */

    /// Whether a kit exists. Answers while locked: it is one row of public
    /// shape, and the settings card asks on mount.
    pub fn recovery_status(&self) -> Result<RecoveryStatus, VaultError> {
        Ok(self.db()?.recovery_status()?)
    }

    /// Mint a new code from the live session and replace any previous one.
    ///
    /// The code is returned once and never again: nothing stores it, so the
    /// caller has exactly this call to show and print it. Requires an unlocked
    /// session, because only the live master key is ever wrapped.
    pub fn recovery_create(&self) -> Result<RecoveryKit, VaultError> {
        let kit = {
            let store = self.db()?;
            let session = self.session.lock().expect("session mutex");
            let active = session.as_ref().ok_or(VaultError::Locked)?;
            store.recovery_create(&active.master)?
        };
        self.touch();
        Ok(kit)
    }

    /// Unwrap the master key from a printed code and park it as a pending
    /// recovery. The session stays closed on purpose: `state()` keeps reporting
    /// `locked: true`, so every data command keeps answering `Locked` and the
    /// gate stays on screen until [`VaultState::recovery_complete`] re-keys.
    pub fn recovery_unlock(&self, code: &str) -> Result<RecoveryOpen, VaultError> {
        if !self.is_locked() {
            return Err(VaultError::Invalid(
                "the vault is already unlocked".to_string(),
            ));
        }
        let (master, meta, vault_name) = {
            let store = self.db()?;
            let (master, meta) = store.recovery_unwrap(code)?;
            let vault_name = store
                .list_vaults(&master, &meta)?
                .into_iter()
                .find(|vault| vault.uuid == meta.vault_uuid)
                .map(|vault| vault.name)
                .unwrap_or_default();
            (master, meta, vault_name)
        };
        *self.pending.lock().expect("recovery mutex") = Some(PendingRecovery {
            master,
            meta,
            vault_name: vault_name.clone(),
            opened: Instant::now(),
            rotated: false,
        });
        Ok(RecoveryOpen { vault_name })
    }

    /// Finish a recovery unlock: re-key the whole account under `new_password`,
    /// then mint a fresh recovery code for the new master key.
    ///
    /// Rotation is the existing [`Store::change_password`] path, so every vault,
    /// item, archived version, attachment and passkey is re-sealed and the old
    /// ciphertext is deleted in the same transaction. Replacing the recovery row
    /// afterwards is what makes the printed code one-shot: the row it opened is
    /// gone, and only the new code (returned once here) can open the vault next.
    ///
    /// The session is still *not* created: the new key waits in the pending slot
    /// until [`VaultState::recovery_finish`], which is what keeps the vault
    /// unreadable while the replacement code is on screen. Opening it here would
    /// let the shell navigate away before the user has printed that code.
    pub fn recovery_complete(&self, new_password: &str) -> Result<RecoveryCompletion, VaultError> {
        if new_password.chars().count() < 10 {
            return Err(VaultError::WeakPassword);
        }
        // The guard is released immediately: nothing below holds `pending` while
        // waiting for the store or the session (see the lock order note).
        let pending = self.pending.lock().expect("recovery mutex").take();
        let Some(pending) = pending else {
            return Err(VaultError::Invalid(
                "no recovery unlock is in progress".to_string(),
            ));
        };
        if pending.rotated {
            return Err(VaultError::Invalid(
                "the master password was already changed; the vault is waiting to be opened"
                    .to_string(),
            ));
        }
        let rotated = {
            let store = self.db()?;
            store.change_password(&pending.master, &pending.meta, new_password)
        };
        let (master, meta) = match rotated {
            Ok(pair) => pair,
            // Rotation is transactional, so a failure leaves the old password
            // (and the old kit) valid: put the key back and let the user retry.
            Err(error) => {
                // A retry is activity: without this the unwrapped key would age
                // out on the clock started at `recovery_unlock`, so a user who
                // reads an error and fixes the password could be logged out of
                // a screen that has no other way forward.
                *self.pending.lock().expect("recovery mutex") = Some(PendingRecovery {
                    opened: Instant::now(),
                    ..pending
                });
                return Err(error.into());
            }
        };
        // The Hello enrolment wrapped the key the rotation just replaced; it
        // could only produce an unlock that fails the verifier. Cleanup cannot
        // fail a completed rotation.
        let _ = {
            let store = self.db()?;
            hello::invalidate(&store, self.hello.as_ref())
        };
        // One-shot replacement, minted from the key the new password derives. A
        // storage failure here cannot roll the rotation back; the completion
        // reports the missing kit and the user recreates one from settings.
        let kit = {
            let store = self.db()?;
            store.recovery_create(&master).ok()
        };
        let vault_name = pending.vault_name;
        *self.pending.lock().expect("recovery mutex") = Some(PendingRecovery {
            master,
            meta,
            vault_name: vault_name.clone(),
            opened: Instant::now(),
            rotated: true,
        });
        Ok(RecoveryCompletion { vault_name, kit })
    }

    /// Open the session after a completed recovery. The new password is already
    /// live; this is the acknowledgement that the replacement code has been
    /// seen, so it is also the only way the rotated key becomes a session.
    pub fn recovery_finish(&self) -> Result<VaultStateDto, VaultError> {
        let pending = self.pending.lock().expect("recovery mutex").take();
        let Some(pending) = pending else {
            return Err(VaultError::Invalid(
                "no recovery unlock is in progress".to_string(),
            ));
        };
        if !pending.rotated {
            *self.pending.lock().expect("recovery mutex") = Some(pending);
            return Err(VaultError::Invalid(
                "set a new master password before opening the vault".to_string(),
            ));
        }
        let mut session = self.session.lock().expect("session mutex");
        *session = Some(Session {
            master: pending.master,
            meta: pending.meta,
            last_activity: Instant::now(),
        });
        drop(session);
        self.state()
    }

    /* ------------------------------------------------------------ account */

    /// Account presence, id, device count and Secret Key presence. Public shape
    /// only, so Settings can ask while the vault is locked.
    pub fn account_status(&self) -> Result<AccountStatus, VaultError> {
        Ok(self.db()?.account_status()?)
    }

    /// Create the account for this vault file. Returns the printed Secret Key
    /// exactly once; nothing can ask for it again.
    pub fn account_create(&self) -> Result<AccountCreated, VaultError> {
        let created =
            self.with_session(|store, master, _meta| Ok(store.account_create(master)?))?;
        self.touch();
        Ok(created)
    }

    /// Prove the stored Secret Key still opens and still derives the stored
    /// account key. Neither value crosses this call.
    pub fn account_secret_key(&self) -> Result<AccountSecretKey, VaultError> {
        self.with_session(|store, master, _meta| Ok(store.account_secret_key(master)?))
    }

    /// A fresh enrolment code for one handover. It is not stored: the caller
    /// reads it aloud and never sees it again.
    pub fn account_enrol_code(&self) -> Result<EnrolCode, VaultError> {
        let code = self.with_session(|store, _master, _meta| Ok(store.account_enrol_code()))?;
        self.touch();
        Ok(code)
    }

    /// Seal the account key to a new device's agreement public key (hex).
    pub fn account_seal_for_device(
        &self,
        code: &str,
        device_agreement_pub: &str,
    ) -> Result<SealedEnrolment, VaultError> {
        let sealed = self.with_session(|store, master, _meta| {
            Ok(store.account_seal_for_device(master, code, device_agreement_pub)?)
        })?;
        self.touch();
        Ok(sealed)
    }

    /// Devices the local mirror knows. Public keys only.
    pub fn account_devices(&self) -> Result<Vec<AccountDevice>, VaultError> {
        Ok(self.db()?.account_devices()?)
    }

    /// This device's public keys, generating its keypair on first use.
    ///
    /// The joining side of an enrolment needs this before it has an account:
    /// the sending device can only seal the account key to a public key it has
    /// been shown. Only public halves cross this call.
    pub fn device_identity(&self) -> Result<DeviceIdentity, VaultError> {
        self.with_session(|store, master, _meta| Ok(store.device_identity(master)?))
    }

    /// This device's private halves, for the net crate to sign requests and
    /// open enrolment envelopes with. The returned value has no `Debug`, does
    /// not serialize and wipes itself on drop; no command exposes it to the
    /// renderer.
    pub fn device_secret_keys(&self) -> Result<DeviceSecretKeys, VaultError> {
        self.with_session(|store, master, _meta| Ok(store.device_secret_keys(master)?))
    }

    /// Receive an account on this device from the three values the sending
    /// device printed. The account key is sealed into the account row; only the
    /// account id is returned.
    pub fn account_enroll_claim(
        &self,
        code: &str,
        sealed: &str,
        sender_agreement_pub: &str,
    ) -> Result<AccountClaimed, VaultError> {
        let claimed = self.with_session(|store, master, _meta| {
            Ok(store.account_enroll_claim(master, code, sealed, sender_agreement_pub)?)
        })?;
        self.touch();
        Ok(claimed)
    }

    pub fn lock(&self) -> Result<VaultStateDto, VaultError> {
        let mut session = self.session.lock().expect("session mutex");
        *session = None; // dropping the session zeroizes the master key
        drop(session);
        // A recovery key that was unwrapped but never used must not outlive the
        // lock: cancelling the forced password change discards it here.
        *self.pending.lock().expect("recovery mutex") = None;
        self.state()
    }

    pub fn touch(&self) {
        if let Some(s) = self.session.lock().expect("session mutex").as_mut() {
            s.last_activity = Instant::now();
        }
    }

    pub fn set_autolock(&self, seconds: u64) -> Result<VaultStateDto, VaultError> {
        let clamped = seconds.clamp(15, 86_400);
        // Persist first: a setting the user made must survive a restart, and a
        // store that refuses the write is a real error, not something to hide
        // behind a value that only this process will ever see.
        if self.path().is_some() {
            self.db()?.set_autolock_seconds(clamped)?;
        }
        *self.autolock.lock().expect("autolock mutex") = Duration::from_secs(clamped);
        self.state()
    }

    /// Set how long a copied secret may stay on the clipboard. The interval is
    /// clamped to 0..=300 seconds; 0 wipes on the next tick instead of waiting.
    pub fn set_clipboard_clear(&self, seconds: u64) -> Result<VaultStateDto, VaultError> {
        let clamped = seconds.min(CLIPBOARD_MAX_SECS);
        if self.path().is_some() {
            self.db()?.set_clipboard_clear_seconds(clamped)?;
        }
        *self.clipboard.lock().expect("clipboard mutex") = Duration::from_secs(clamped);
        self.state()
    }

    /// Absolute path of the SQLite file this state is backed by, or an empty
    /// path when none is selected. New code should use [`VaultState::path`],
    /// which states the no-vault case in its type; this stays for callers that
    /// only format a display string.
    pub fn vault_path(&self) -> PathBuf {
        self.path().unwrap_or_default()
    }

    /// Whether the session is closed, without decrypting anything.
    pub fn is_locked(&self) -> bool {
        self.session.lock().expect("session mutex").is_none()
    }

    pub fn maybe_autolock(&self) -> Result<bool, VaultError> {
        let timeout = *self.autolock.lock().expect("autolock mutex");
        let mut session = self.session.lock().expect("session mutex");
        if let Some(s) = session.as_ref() {
            if s.last_activity.elapsed() >= timeout {
                *session = None;
                return Ok(true);
            }
        }
        drop(session);
        // A key unwrapped from a recovery code ages on the same clock, even
        // though no session exists for the watchdog to lock.
        let mut pending = self.pending.lock().expect("recovery mutex");
        if pending
            .as_ref()
            .is_some_and(|recovery| recovery.opened.elapsed() >= timeout)
        {
            // `true` for the same reason a session lock returns it: the caller
            // emits `vault://locked`, so a screen waiting on the unwrapped key
            // learns that the key is gone instead of rendering a dead form.
            *pending = None;
            return Ok(true);
        }
        Ok(false)
    }

    /// Run `f` with the store and an unlocked session.
    /// Run one closure with the unlocked store, the master key and the vault
    /// identity. The sync engine lives in another crate and needs all three at
    /// once; this is the seam that lends them for the length of one call, so no
    /// key ends up in a longer-lived struct.
    pub fn with_unlocked<T>(
        &self,
        f: impl FnOnce(&Store, &SymKey, &VaultMeta) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        self.with_session(f)
    }

    /// The store behind the selected vault. Keyless reads (sync metadata, row
    /// counts, public shape) use it while locked; anything that touches
    /// ciphertext takes the master key through [`VaultState::with_unlocked`]
    /// instead. Errors with `no vault is open` before a file is selected.
    pub fn store(&self) -> Result<StoreGuard<'_>, VaultError> {
        self.db()
    }

    /// Write or clear one sync metadata value. Unsealed by design: these are
    /// cursors, timestamps and the server URL, never vault content.
    pub fn set_sync_meta(&self, key: &str, value: Option<&str>) -> Result<(), VaultError> {
        let store = self.db()?;
        match value {
            Some(text) => store.sync_meta_set(key, text)?,
            None => store.sync_meta_remove(key)?,
        }
        Ok(())
    }

    /// One sync metadata value, readable while locked: the server URL, the last
    /// sync time and the status line need no key, so the titlebar can show
    /// "synced at 14:02" on the lock screen instead of a guess.
    pub fn sync_meta(&self, key: &str) -> Result<Option<String>, VaultError> {
        Ok(self.db()?.sync_meta_get(key)?)
    }

    pub(crate) fn with_session<T>(
        &self,
        f: impl FnOnce(&Store, &SymKey, &VaultMeta) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        let store = self.db()?;
        let session = self.session.lock().expect("session mutex");
        match session.as_ref() {
            Some(s) => f(&store, &s.master, &s.meta),
            None => Err(VaultError::Locked),
        }
    }

    /* ------------------------------------------------------------- vaults */

    /// Every vault in the account with its live item count.
    pub fn vaults(&self) -> Result<Vec<VaultSummary>, VaultError> {
        self.touch();
        self.with_session(|store, master, meta| Ok(store.list_vaults(master, meta)?))
    }

    /// A new vault gets its own key derived from the same master password, so
    /// it is a separate key, not a folder.
    pub fn create_vault(&self, name: &str) -> Result<VaultSummary, VaultError> {
        self.touch();
        self.with_session(|store, master, meta| Ok(store.create_vault(master, meta, name)?))
    }

    /// Point the session at another vault. The master key stays; only the
    /// derived item key changes, so the next command reads the other ciphertext.
    pub fn switch_vault(&self, uuid: &str) -> Result<VaultStateDto, VaultError> {
        // Every guard is released before `state()` re-acquires them: std mutexes
        // are not reentrant, so an early return inside the block would deadlock.
        {
            let store = self.db()?;
            let mut session = self.session.lock().expect("session mutex");
            let active = session.as_mut().ok_or(VaultError::Locked)?;
            if active.meta.vault_uuid != uuid {
                if !store.vault_exists(&active.master, &active.meta, uuid)? {
                    return Err(VaultError::NotFound);
                }
                active.meta.vault_uuid = uuid.to_string();
                active.last_activity = Instant::now();
            }
        }
        self.state()
    }

    pub fn rename_vault(&self, uuid: &str, name: &str) -> Result<(), VaultError> {
        self.touch();
        self.with_session(|store, master, meta| Ok(store.rename_vault(master, meta, uuid, name)?))
    }

    /// The whole filtered list. The filters run in SQL against the plaintext
    /// projection, so a query never decrypts a row it cannot match.
    pub fn list(
        &self,
        needle: &str,
        category: Option<&str>,
        favorites_only: bool,
    ) -> Result<Vec<ItemSummary>, VaultError> {
        self.touch();
        self.list_quiet(needle, category, favorites_only)
    }

    /// The same list without counting as user activity, for background
    /// surfaces (the SSH agent, the SDK pipe): a client polling them must not
    /// keep the vault unlocked past its idle timeout.
    pub fn list_quiet(
        &self,
        needle: &str,
        category: Option<&str>,
        favorites_only: bool,
    ) -> Result<Vec<ItemSummary>, VaultError> {
        self.with_session(|store, master, meta| {
            Ok(store
                .list_page(
                    master,
                    meta,
                    needle,
                    category,
                    favorites_only,
                    usize::MAX,
                    0,
                )?
                .items)
        })
    }

    /// One page of the filtered list plus the total the same filter matches.
    pub fn list_page(
        &self,
        needle: &str,
        category: Option<&str>,
        favorites_only: bool,
        limit: usize,
        offset: usize,
    ) -> Result<Page, VaultError> {
        self.touch();
        self.with_session(|store, master, meta| {
            Ok(store.list_page(
                master,
                meta,
                needle,
                category,
                favorites_only,
                limit,
                offset,
            )?)
        })
    }

    /// Every `sshKey` item, for the SSH agent.
    ///
    /// Unlike [`VaultState::list`] and [`VaultState::get`] this does **not**
    /// count as user activity: a client polling the agent pipe must not keep
    /// the vault unlocked past its idle timeout.
    pub fn ssh_items_quiet(&self) -> Result<Vec<Item>, VaultError> {
        self.with_session(|store, master, meta| {
            let page = store.list_page(
                master,
                meta,
                "",
                Some(Category::SshKey.as_str()),
                false,
                usize::MAX,
                0,
            )?;
            let mut items = Vec::with_capacity(page.items.len());
            for summary in &page.items {
                items.push(store.get(master, meta, &summary.id)?);
            }
            Ok(items)
        })
    }

    /// Vault-wide counters from one grouped query, for the sidebar badges.
    pub fn counts(&self) -> Result<Counts, VaultError> {
        self.touch();
        self.with_session(|store, _master, meta| Ok(store.counts(meta)?))
    }

    /* ------------------------------------------------------------ passkeys */

    /// Credentials attached to one item, metadata only. The credential id is
    /// public; the seal is not opened here at all.
    pub fn passkeys_for_item(&self, item_id: &str) -> Result<Vec<PasskeyInfo>, VaultError> {
        self.touch();
        self.with_session(|store, _master, meta| {
            Ok(store
                .passkeys_for_item(meta, item_id)?
                .into_iter()
                .map(|row| PasskeyInfo {
                    credential_id: credential_hex(&row.credential_id),
                    item_id: row.item_uuid,
                    rp_id: row.rp_id,
                    created_at: row.created_at,
                    last_used_at: row.last_used_at,
                })
                .collect())
        })
    }

    /// Whether an excluded credential already exists. The CTAP2 answer to a
    /// duplicate is a refusal, not a second credential over the same id.
    pub fn passkey_exists(&self, credential_id: &[u8]) -> Result<bool, VaultError> {
        self.with_session(|store, _master, meta| Ok(store.passkey_exists(meta, credential_id)?))
    }

    /// Persist a credential created by the plugin path. The scalar is sealed by
    /// the store under the item key; the caller keeps no copy.
    pub fn passkey_insert(
        &self,
        row: PasskeyRow,
        private_key: &[u8],
        sign_count: u32,
    ) -> Result<(), VaultError> {
        self.touch();
        self.with_session(|store, master, meta| {
            Ok(store.passkey_insert(master, meta, &row, private_key, sign_count)?)
        })
    }

    /// Open the credential that answers an assertion for `rp_id`.
    pub fn passkey_open_for_assertion(
        &self,
        rp_id: &str,
        allow_list: &[Vec<u8>],
    ) -> Result<Option<PasskeySecret>, VaultError> {
        self.touch();
        self.with_session(|store, master, meta| {
            Ok(store.passkey_open_for_assertion(master, meta, rp_id, allow_list)?)
        })
    }

    /// Bump the signature counter and stamp `last_used_at` after a successful
    /// assertion. The same scalar is resealed; if the row vanished in between
    /// this is `NotFound` rather than a silent stale counter.
    pub fn passkey_record_use(
        &self,
        credential_id: &[u8],
        private_key: &[u8],
        sign_count: u32,
    ) -> Result<(), VaultError> {
        let at = chrono::Utc::now().timestamp();
        self.with_session(|store, master, meta| {
            Ok(store.passkey_record_use(
                master,
                meta,
                credential_id,
                private_key,
                sign_count,
                at,
            )?)
        })
    }

    /// Remove one credential from one item. Returns whether a row was deleted.
    pub fn passkey_remove(&self, item_id: &str, credential_id: &[u8]) -> Result<bool, VaultError> {
        self.touch();
        self.with_session(|store, _master, meta| {
            Ok(store.passkey_delete(meta, item_id, credential_id)?)
        })
    }

    pub fn get(&self, id: &str) -> Result<Item, VaultError> {
        self.touch();
        self.get_quiet(id)
    }

    /// [`VaultState::get`] without the activity stamp.
    pub fn get_quiet(&self, id: &str) -> Result<Item, VaultError> {
        self.with_session(|store, master, meta| Ok(store.get(master, meta, id)?))
    }

    pub fn save(&self, mut item: Item) -> Result<Item, VaultError> {
        self.touch();
        self.with_session(|store, master, meta| {
            if item.id.is_empty() {
                item.id = uuid::Uuid::new_v4().to_string();
            }
            if item.title.trim().is_empty() {
                item.title = "Untitled".to_string();
            }
            Ok(store.save_item(master, meta, item)?)
        })
    }

    /// A new item that is **not** in the vault yet.
    ///
    /// The field template comes from the core, but nothing is written until the
    /// editor saves: an abandoned draft leaves no row, no history entry and no
    /// search-index entry, so cancelling needs no compensating delete. The
    /// session must be unlocked, because saving is the only thing a draft can
    /// lead to.
    pub fn create_default(&self, category: &str) -> Result<Item, VaultError> {
        let category = Category::from_str(category);
        self.touch();
        self.with_session(|_store, _master, _meta| Ok(Item::new(category, title_for(category))))
    }

    pub fn delete(&self, id: &str) -> Result<(), VaultError> {
        self.touch();
        self.with_session(|store, _, meta| Ok(store.delete_item(meta, id)?))
    }

    pub fn totp(&self, id: &str) -> Result<TotpDto, VaultError> {
        let item = self.get(id)?;
        let secret = item.totp_secret.ok_or(VaultError::FieldNotFound)?;
        let current = totp::code_now(&secret)?;
        Ok(TotpDto {
            code: current.code,
            seconds_remaining: current.seconds_remaining,
            period: current.period,
        })
    }

    pub fn generate_password(&self, options: GenerateOptions) -> String {
        generator::generate(&options)
    }

    /// Copy a decrypted field value to the clipboard and schedule a wipe.
    pub fn copy_field(&self, item_id: &str, field_id: &str) -> Result<(), VaultError> {
        self.touch();
        self.copy_field_quiet(item_id, field_id)
    }

    /// [`VaultState::copy_field`] without the activity stamp: the SDK's copy
    /// answers a client, not the person at the keyboard.
    pub fn copy_field_quiet(&self, item_id: &str, field_id: &str) -> Result<(), VaultError> {
        let item = self.get_quiet(item_id)?;
        let value = if field_id == "__notes" {
            item.notes.clone()
        } else {
            item.fields
                .iter()
                .find(|f| f.id == field_id)
                .map(|f| f.value.clone())
                .ok_or(VaultError::FieldNotFound)?
        };
        self.write_clipboard(value)
    }

    /// Copy arbitrary text (generated passwords, TOTP codes) with the same
    /// timed wipe that field copies use.
    pub fn copy_text(&self, text: String) -> Result<(), VaultError> {
        self.write_clipboard(text)
    }

    fn write_clipboard(&self, value: String) -> Result<(), VaultError> {
        let mut clipboard =
            arboard::Clipboard::new().map_err(|e| VaultError::Clipboard(e.to_string()))?;
        clipboard
            .set_text(value.clone())
            .map_err(|e| VaultError::Clipboard(e.to_string()))?;
        let clear_after = *self.clipboard.lock().expect("clipboard mutex");
        std::thread::spawn(move || {
            std::thread::sleep(clear_after);
            if let Ok(mut cb) = arboard::Clipboard::new() {
                if let Ok(current) = cb.get_text() {
                    if current == value {
                        let _ = cb.clear();
                    }
                }
            }
        });
        Ok(())
    }

    /* --------------------------------------------------------------- grants */

    /// Check every `(item, field)` against the vault, then return them with the
    /// canonical ids. A field that does not exist cannot be granted, so an
    /// allowlist can never outlive the field it named.
    fn checked_grants(
        &self,
        grants: &[(String, String)],
    ) -> Result<Vec<(String, String)>, VaultError> {
        let mut items: std::collections::HashMap<String, Item> = std::collections::HashMap::new();
        let mut checked = Vec::with_capacity(grants.len());
        for (item_id, field) in grants {
            if !items.contains_key(item_id) {
                items.insert(item_id.clone(), self.get_quiet(item_id)?);
            }
            let item = &items[item_id];
            if !item.fields.iter().any(|candidate| candidate.id == *field) {
                return Err(VaultError::FieldNotFound);
            }
            checked.push((item.id.clone(), field.clone()));
        }
        Ok(checked)
    }

    /// Replace one principal's allowlist.
    ///
    /// `principal_kind` is `mcp` or `cli`; anything else is refused rather than
    /// written, because a grant under an unknown kind could never be consulted
    /// and would silently do nothing. `expires_at` is a unix timestamp or
    /// `None`; `one_shot` marks grants that the next successful read spends.
    /// The persisted list is the whole truth for that principal — pairing
    /// decides it once, and re-pairing replaces it.
    pub fn set_grants(
        &self,
        principal_kind: &str,
        principal_id: &str,
        grants: &[(String, String)],
        expires_at: Option<i64>,
        one_shot: bool,
    ) -> Result<(), VaultError> {
        let kind = grant_kind(principal_kind)?;
        if principal_id.trim().is_empty() {
            return Err(VaultError::Invalid(
                "a grant needs a named principal".into(),
            ));
        }
        let checked = self.checked_grants(grants)?;
        self.with_session(|store, _master, _meta| {
            Ok(store.set_grants(kind, principal_id, &checked, expires_at, one_shot)?)
        })
    }

    /// Replace everything granted on one item, across principals. This is the
    /// per-item access editor's save: the list it sends is the item's whole
    /// allowlist, and an empty list removes access for everyone.
    pub fn set_item_grants(
        &self,
        item_id: &str,
        grants: &[(String, String, String)],
    ) -> Result<(), VaultError> {
        let item = self.get_quiet(item_id)?;
        let mut checked = Vec::with_capacity(grants.len());
        for (kind, principal_id, field) in grants {
            let kind = grant_kind(kind)?;
            if principal_id.trim().is_empty() {
                return Err(VaultError::Invalid(
                    "a grant needs a named principal".into(),
                ));
            }
            if !item.fields.iter().any(|candidate| candidate.id == *field) {
                return Err(VaultError::FieldNotFound);
            }
            checked.push((kind.to_string(), principal_id.clone(), field.clone()));
        }
        self.with_session(|store, _master, _meta| Ok(store.set_item_grants(&item.id, &checked)?))
    }

    /// Every grant held by one principal.
    pub fn grants_for(
        &self,
        principal_kind: &str,
        principal_id: &str,
    ) -> Result<Vec<AccessGrant>, VaultError> {
        let kind = grant_kind(principal_kind)?;
        self.with_session(|store, _master, _meta| {
            Ok(store
                .grants_for(kind, principal_id)?
                .into_iter()
                .map(access_grant)
                .collect())
        })
    }

    /// Every grant that names one item, for the item editor.
    pub fn grants_for_item(&self, item_id: &str) -> Result<Vec<AccessGrant>, VaultError> {
        self.with_session(|store, _master, _meta| {
            Ok(store
                .grants_for_item(item_id)?
                .into_iter()
                .map(access_grant)
                .collect())
        })
    }

    /// One item's read history, newest first.
    pub fn audit_for_item(&self, item_id: &str) -> Result<Vec<McpAuditEntry>, VaultError> {
        self.with_session(|store, _master, _meta| {
            Ok(store
                .audit_for_item(item_id)?
                .into_iter()
                .map(|row| McpAuditEntry {
                    client: row.client,
                    item_id: row.item_id,
                    field: row.field,
                    at: row.at,
                })
                .collect())
        })
    }

    /// Replace one MCP client's allowlist. The MCP path has no deadline and no
    /// one-shot grant; it is the `mcp` principal with those defaults, and it
    /// keeps its own store entry point so a scoped CLI write and an MCP write
    /// can never be confused.
    pub fn mcp_set_grants(
        &self,
        client: &str,
        grants: &[(String, String)],
    ) -> Result<(), VaultError> {
        if client.trim().is_empty() {
            return Err(VaultError::Invalid(
                "a grant needs a named principal".into(),
            ));
        }
        let checked = self.checked_grants(grants)?;
        self.with_session(|store, _master, _meta| Ok(store.replace_mcp_grants(client, &checked)?))
    }

    /// Replace one CLI token's allowlist. The kind is fixed here so callers
    /// never spell the store's principal vocabulary; `expires_at` and
    /// `one_shot` are the same controls [`Self::set_grants`] documents.
    pub fn cli_set_grants(
        &self,
        client: &str,
        grants: &[(String, String)],
        expires_at: Option<i64>,
        one_shot: bool,
    ) -> Result<(), VaultError> {
        self.set_grants(GRANT_KIND_CLI, client, grants, expires_at, one_shot)
    }

    /// Every persisted MCP grant, for the settings card.
    pub fn mcp_grants(&self) -> Result<Vec<McpGrant>, VaultError> {
        self.with_session(|store, _master, _meta| {
            Ok(store
                .mcp_grants()?
                .into_iter()
                .map(|row| McpGrant {
                    client: row.principal_id,
                    item_id: row.item_id,
                    field: row.field,
                    created_at: row.created_at,
                })
                .collect())
        })
    }

    /// Drop one MCP client's allowlist. Returns how many rows went away.
    pub fn mcp_clear_grants(&self, client: &str) -> Result<usize, VaultError> {
        self.with_session(|store, _master, _meta| Ok(store.clear_mcp_grants(client)?))
    }

    /// Recent reads, newest first, capped by the store.
    pub fn mcp_audit(&self, limit: usize) -> Result<Vec<McpAuditEntry>, VaultError> {
        self.with_session(|store, _master, _meta| {
            Ok(store
                .mcp_audit(limit)?
                .into_iter()
                .map(|row| McpAuditEntry {
                    client: row.client,
                    item_id: row.item_id,
                    field: row.field,
                    at: row.at,
                })
                .collect())
        })
    }

    /// Read one field for a paired MCP client.
    ///
    /// The grant check, the decryption, the one-shot spend and the audit append
    /// happen under one session lock, in that order. A read that fails the
    /// grant check touches nothing; a read that passes is recorded before its
    /// value is returned, so there is no window in which a value exists without
    /// a row. Field values are the only thing this returns — labels, notes and
    /// TOTP secrets are not reachable through it.
    pub fn mcp_reveal(
        &self,
        client: &str,
        item_id: &str,
        field_id: &str,
    ) -> Result<String, VaultError> {
        self.with_session(|store, master, meta| {
            if !store.mcp_granted(client, item_id, field_id)? {
                return Err(VaultError::NotGranted);
            }
            let item = store.get(master, meta, item_id)?;
            let value = item
                .fields
                .iter()
                .find(|field| field.id == field_id)
                .map(|field| field.value.clone())
                .ok_or(VaultError::FieldNotFound)?;
            store.consume_one_shot_grant(GRANT_KIND_MCP, client, item_id, field_id)?;
            store.append_mcp_audit(client, item_id, field_id)?;
            Ok(value)
        })
    }

    /* ------------------------------------------------------------------ cli */

    /// The items a CLI token may see: those where it holds at least one live
    /// grant. A token with grants on no item lists nothing, while a token
    /// minted without an allowlist (the legacy `sdk.pair`) never reaches this
    /// method — the SDK layer keeps that path on the unrestricted listing.
    pub fn cli_items(&self, client: &str) -> Result<Vec<ItemSummary>, VaultError> {
        let now = chrono::Utc::now().timestamp();
        self.with_session(|store, master, meta| {
            let granted: std::collections::HashSet<String> = store
                .granted_item_ids(GRANT_KIND_CLI, client, now)?
                .into_iter()
                .collect();
            let summaries = store
                .list_page(master, meta, "", None, false, usize::MAX, 0)?
                .items;
            Ok(summaries
                .into_iter()
                .filter(|summary| granted.contains(&summary.id))
                .collect())
        })
    }

    /// Copy one field to the clipboard for a CLI token, under its grant.
    ///
    /// The grant check, the decryption, the one-shot spend and the audit append
    /// happen under one session lock; the clipboard write happens after the
    /// lock is released, exactly like [`Self::copy_field_quiet`]. The audit
    /// label is `cli:<client>` so the shared history says which surface read.
    pub fn cli_copy(&self, client: &str, item_id: &str, field_id: &str) -> Result<(), VaultError> {
        let now = chrono::Utc::now().timestamp();
        let value = self.with_session(|store, master, meta| {
            if !store.grant_allows(GRANT_KIND_CLI, client, item_id, field_id, now)? {
                return Err(VaultError::NotGranted);
            }
            let item = store.get(master, meta, item_id)?;
            let value = item
                .fields
                .iter()
                .find(|field| field.id == field_id)
                .map(|field| field.value.clone())
                .ok_or(VaultError::FieldNotFound)?;
            store.consume_one_shot_grant(GRANT_KIND_CLI, client, item_id, field_id)?;
            store.append_mcp_audit(&format!("cli:{client}"), item_id, field_id)?;
            Ok(value)
        })?;
        self.write_clipboard(value)
    }

    /// Resolve `run`'s environment bindings under a CLI token's grants.
    ///
    /// Returns values in binding order; the caller puts them in a child's
    /// environment, so they never cross the pipe. Every binding has to be
    /// granted before anything is resolved for it, and every value is resolved
    /// before any one-shot grant is spent: a run that names one forbidden field
    /// leaves all its grants intact and starts nothing. The read is audited as
    /// `cli:<client>` once per binding, before the values are returned.
    pub fn cli_resolve(
        &self,
        client: &str,
        bindings: &[(String, String)],
    ) -> Result<Vec<String>, VaultError> {
        let now = chrono::Utc::now().timestamp();
        self.with_session(|store, master, meta| {
            let mut items: std::collections::HashMap<String, Item> =
                std::collections::HashMap::new();
            let mut values = Vec::with_capacity(bindings.len());
            for (item_id, field_id) in bindings {
                if !store.grant_allows(GRANT_KIND_CLI, client, item_id, field_id, now)? {
                    return Err(VaultError::NotGranted);
                }
                if !items.contains_key(item_id) {
                    items.insert(item_id.clone(), store.get(master, meta, item_id)?);
                }
                let value = items[item_id]
                    .fields
                    .iter()
                    .find(|field| field.id == *field_id)
                    .map(|field| field.value.clone())
                    .ok_or(VaultError::FieldNotFound)?;
                values.push(value);
            }
            for (item_id, field_id) in bindings {
                store.consume_one_shot_grant(GRANT_KIND_CLI, client, item_id, field_id)?;
                store.append_mcp_audit(&format!("cli:{client}"), item_id, field_id)?;
            }
            Ok(values)
        })
    }

    /* --------------------------------------------------------------- browser */

    /// Every explicit browser rule, alphabetically by origin.
    ///
    /// Rules are policy, not content: this reads the plaintext `browser_sites`
    /// table directly, so the settings card can list them without an unlock.
    pub fn browser_rules(&self) -> Result<Vec<BrowserRule>, VaultError> {
        Ok(self
            .db()?
            .browser_rules()?
            .into_iter()
            .map(|row| BrowserRule {
                origin: row.origin,
                mode: row.mode,
                updated_at: row.updated_at,
            })
            .collect())
    }

    /// The rule for one origin: `fill`, `ask` or `off`. A missing row is
    /// `ask`, which is what makes "allow fill" an explicit decision.
    pub fn browser_rule(&self, origin: &str) -> Result<String, VaultError> {
        Ok(self.db()?.browser_rule(origin)?)
    }

    /// Upsert a rule, then return the table.
    pub fn browser_set_rule(
        &self,
        origin: &str,
        mode: &str,
    ) -> Result<Vec<BrowserRule>, VaultError> {
        self.db()?.set_browser_rule(origin, mode)?;
        self.browser_rules()
    }

    /// Delete a rule, so the origin falls back to `ask`. Returns the table.
    pub fn browser_clear_rule(&self, origin: &str) -> Result<Vec<BrowserRule>, VaultError> {
        self.db()?.clear_browser_rule(origin)?;
        self.browser_rules()
    }

    /// Items whose saved URLs point at `origin`, with the field ids the chip
    /// may ask about. Metadata only: no value is decrypted into the result.
    ///
    /// The match is exact on the canonical origin, so a page on
    /// `example.com.evil.test` never sees a login saved for `example.com`.
    pub fn browser_items(&self, origin: &str) -> Result<Vec<BrowserItem>, VaultError> {
        let origin = Store::canonical_browser_origin(origin).ok_or_else(|| {
            VaultError::Invalid(format!("{origin} is not an http or https origin"))
        })?;
        // `off` is not only "no reveal": the chip has nothing to show, so the
        // metadata is withheld too. `ask` still lists, because the chip is the
        // thing that explains why nothing can be filled.
        if self.db()?.browser_rule(&origin)? == "off" {
            return Ok(Vec::new());
        }
        let summaries = self.list_quiet("", None, false)?;
        let mut items = Vec::new();
        for summary in summaries {
            let item = self.get_quiet(&summary.id)?;
            if !item_matches_origin(&item, &origin) {
                continue;
            }
            let fields: Vec<BrowserField> = item
                .fields
                .iter()
                .filter(|field| matches!(field.kind.as_str(), "username" | "password" | "email"))
                .map(|field| BrowserField {
                    id: field.id.clone(),
                    label: field.label.clone(),
                    kind: field.kind.clone(),
                })
                .collect();
            if fields.is_empty() {
                // A matching item with nothing the chip could fill is noise.
                continue;
            }
            items.push(BrowserItem {
                id: item.id,
                title: item.title,
                category: item.category.as_str().to_string(),
                fields,
            });
        }
        Ok(items)
    }

    /// Reveal one login field for the browser bridge.
    ///
    /// Three checks happen under one session lock, in this order: the origin
    /// rule must be `fill`, the item must have a URL on that same origin, and
    /// the field must be one a login form can use. Only then is the value read
    /// and the read appended to the audit ledger as `browser:<origin>` before
    /// the value is returned. A refused request touches nothing.
    pub fn browser_reveal(
        &self,
        origin: &str,
        item_id: &str,
        field_id: &str,
    ) -> Result<String, VaultError> {
        let origin = Store::canonical_browser_origin(origin).ok_or_else(|| {
            VaultError::Invalid(format!("{origin} is not an http or https origin"))
        })?;
        self.with_session(|store, master, meta| {
            if store.browser_rule(&origin)? != "fill" {
                return Err(VaultError::NotGranted);
            }
            let item = store.get(master, meta, item_id)?;
            if !item_matches_origin(&item, &origin) {
                return Err(VaultError::NotFound);
            }
            let field = item
                .fields
                .iter()
                .find(|field| field.id == field_id)
                .ok_or(VaultError::FieldNotFound)?;
            if !matches!(field.kind.as_str(), "username" | "password" | "email") {
                return Err(VaultError::FieldNotFound);
            }
            let value = field.value.clone();
            store.append_mcp_audit(&format!("browser:{origin}"), item_id, field_id)?;
            Ok(value)
        })
    }

    pub fn change_password(&self, old: &str, new: &str) -> Result<VaultStateDto, VaultError> {
        if new.chars().count() < 10 {
            return Err(VaultError::WeakPassword);
        }
        // Re-key inside a scope so both guards are released before `state()`
        // re-acquires them (std mutexes are not reentrant).
        let (master, meta) = {
            let store = self.db()?;
            let session = self.session.lock().expect("session mutex");
            let current = session.as_ref().ok_or(VaultError::Locked)?;
            // Prove the caller knows the current password before re-keying.
            store.unlock(old)?;
            store.change_password(&current.master, &current.meta, new)?
        };
        // The Hello enrolment wrapped the *previous* master key; after the
        // re-key it could only produce an unlock that fails the verifier. Drop
        // it rather than leave a button that cannot work. Cleanup cannot fail a
        // completed rotation.
        let _ = {
            let store = self.db()?;
            hello::invalidate(&store, self.hello.as_ref())
        };
        // The recovery row sealed the *previous* master key, and the code that
        // opens it is not stored anywhere, so the row cannot be re-sealed here.
        // Keeping it would leave a printed code that silently fails; dropping it
        // makes the settings card show "no code", which is the truth. Cleanup
        // cannot fail a completed rotation.
        let _ = {
            let store = self.db()?;
            store.recovery_wipe()
        };
        let mut session = self.session.lock().expect("session mutex");
        *session = Some(Session {
            master,
            meta,
            last_activity: Instant::now(),
        });
        drop(session);
        self.state()
    }
}

fn unix_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since_epoch| since_epoch.as_millis() as u64)
        .unwrap_or(0)
}

fn title_for(category: Category) -> String {
    let label = match category {
        Category::Login => "New Login",
        Category::Password => "New Password",
        Category::CreditCard => "New Credit Card",
        Category::Identity => "New Identity",
        Category::SecureNote => "New Note",
        Category::Document => "New Document",
        Category::SshKey => "New SSH Key",
        Category::Server => "New Server",
        Category::Database => "New Database",
        Category::BankAccount => "New Bank Account",
        Category::CryptoWallet => "New Wallet",
        Category::DriverLicense => "New Driver License",
        Category::Passport => "New Passport",
        Category::Membership => "New Membership",
        Category::MedicalRecord => "New Medical Record",
        Category::SoftwareLicense => "New License",
        Category::ApiCredential => "New API Credential",
        Category::WirelessRouter => "New Router",
    };
    label.to_string()
}

#[cfg(test)]
mod quiet_reads {
    use super::*;

    /// A pending recovery ages on the auto-lock clock, and when it does the
    /// caller must be told (`Ok(true)`), exactly as a session lock is: the
    /// renderer emits `vault://locked` on that signal, and without it the
    /// forced-change screen keeps rendering a form whose every action fails.
    #[test]
    fn an_expired_pending_recovery_reports_itself_as_a_lock() {
        let dir = tempfile::tempdir().expect("temp dir");
        let state = VaultState::open(dir.path().join("kestrel.db")).expect("vault opens");
        state
            .create("correct horse battery staple")
            .expect("created");
        let kit = state.recovery_create().expect("kit");
        state.lock().expect("locked");
        state.recovery_unlock(&kit.code).expect("armed");

        // The public setter clamps to 15 s; this module owns the mutex, so the
        // test can use a clock it does not have to wait on.
        *state.autolock.lock().expect("autolock mutex") = Duration::from_millis(20);
        std::thread::sleep(Duration::from_millis(60));

        assert!(
            state.maybe_autolock().expect("watchdog"),
            "clearing the pending key must be reported"
        );
        assert!(
            state.recovery_complete("another long passphrase").is_err(),
            "the unwrapped key must be gone"
        );
    }

    /// The SSH agent must never keep the vault alive: a client polling the pipe
    /// is not the user working. `list`/`get` still count, because they answer
    /// the renderer.
    #[test]
    fn background_reads_do_not_extend_the_idle_timer() {
        let dir = tempfile::tempdir().expect("temp dir");
        let state = VaultState::open(dir.path().join("kestrel.db")).expect("vault opens");
        state
            .create("correct horse battery staple")
            .expect("created");

        let activity = || {
            let session = state.session.lock().expect("session mutex");
            session.as_ref().expect("unlocked").last_activity
        };

        let before = activity();
        std::thread::sleep(Duration::from_millis(30));
        state.ssh_items_quiet().expect("quiet read");
        let after_quiet = activity();
        assert_eq!(before, after_quiet, "the agent read counts as activity");

        state.list("", None, false).expect("list");
        let after_list = activity();
        assert!(
            after_list > after_quiet,
            "a renderer read must still postpone the lock"
        );

        // The same split for the SDK surface: a pipe client polling
        // `items.list` or fetching one item must not keep the session alive.
        let saved = state
            .save(Item::new(Category::Login, "quiet".to_string()))
            .expect("saved");
        std::thread::sleep(Duration::from_millis(30));
        let before_quiet_list = activity();
        state.list_quiet("", None, false).expect("quiet list");
        state.get_quiet(&saved.id).expect("quiet get");
        assert_eq!(
            before_quiet_list,
            activity(),
            "the SDK reads count as activity"
        );
        state.get(&saved.id).expect("get");
        assert!(activity() > before_quiet_list, "get still touches");
    }
}
