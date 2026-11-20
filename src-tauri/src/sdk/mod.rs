//! CLI + SDK: a local automation surface for the vault.
//!
//! The surface exists for scripts and editors, not for the renderer:
//!
//! * `pipe.rs` owns `\\.\pipe\kestrel-sdk` and its user-only DACL;
//! * `protocol.rs` owns the JSON line protocol, the pairing rules and the token
//!   scopes;
//! * this module is the bridge to the vault — it resolves field values for
//!   `items.copy` and `run` inside the process, so a value reaches the
//!   clipboard or a child's environment and never appears in a response. A
//!   child that prints its environment discloses it: an unrestricted CLI token
//!   is full read access while the vault is unlocked, which is why it is minted
//!   in-app and dies with the session.
//!
//! A CLI token can be scoped instead. `sdk.pair(client, grants)` records the
//! ticked fields for the `cli` principal and mints a token that lists the same
//! fields; `items.list` then shows only items it holds a grant on, `items.copy`
//! and `run` answer `not_granted` for any other field, and every successful
//! read is audited as `cli:<client>`. The legacy `sdk.pair()` token (no
//! allowlist) keeps its original full-read behaviour on purpose: it is the
//! pairing that existed before grants and its callers did not opt into a
//! narrower one.
//!
//! `kestrel-mcp` is the second client. Its token has an `Mcp` scope: the client
//! name it was paired under, and the exact fields the person ticked in Settings.
//! It may list field names and reveal one granted field per call; every granted
//! reveal is appended to `mcp_audit` by the core before the value is answered,
//! and the renderer never receives a value at all.
//!
//! `kestrel-nmhost` is the third client. Its `Browser` token is minted when the
//! host is installed, written to the user-only `bridge.token` file next to the
//! vault, and restored from that file on the next start — the browser-started
//! host has nowhere else to get it. It may list items for one origin and reveal
//! one login field, and only where `browser_sites` says `fill`; every reveal is
//! appended to `mcp_audit` as `browser:<origin>` before the value is answered.
//!
//! Pairing mints a 32-byte token per client and keeps only its SHA-256 digest.
//! Locking the vault revokes the CLI and MCP tokens: the watcher below polls the
//! session and drops them the moment the vault is no longer open. The Browser
//! token is **not** destroyed by a lock — every browser op answers `locked`
//! while the vault is closed, and a persisted bridge that died on the first idle
//! lock would be broken by design. It is removed by uninstall.

mod browser_ops;
pub mod pipe;
pub mod protocol;

pub use pipe::PIPE_PATH;
pub use protocol::{
    Auth, BrowserItem, BrowserStatus, EnvBinding, Grant, ItemMeta, RunOutput, SdkBackend, SdkError,
    SecretField, SecretItem, SessionToken, TokenKind,
};

use kestrel_core::session::{VaultError, VaultState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Manager, State};

/// How often the watcher checks whether the vault is still open. The core's
/// own watchdog ticks every five seconds; a token should not outlive a lock by
/// that long, so this is faster and does a single indexed read.
const LOCK_POLL: Duration = Duration::from_millis(500);

/// Snapshot for `sdk_status`. Everything here is non-secret: no token, no item
/// data, no field values.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SdkStatus {
    /// The pipe exists and its accept loop is running.
    pub running: bool,
    pub pipe: String,
    /// A token is valid for this session.
    pub paired: bool,
    pub unlocked: bool,
    /// Why the pipe could not be created, e.g. a stale owner.
    pub error: Option<String>,
}

/// What `sdk_pair` returns: the token exists in readable form only in this
/// response and in the Rust call that produced it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SdkPairing {
    pub pipe: String,
    pub token: String,
}

/// The optional `sdk_pair` request. Omitting the argument is the legacy
/// pairing: a token with no allowlist that behaves exactly as it did before
/// grants existed — every item and field while the vault is open. That path is
/// kept for callers that only want a token, and is the reason an empty grant
/// list is refused instead of minting a token that could read nothing.
///
/// Supplying it mints a scoped token: `grants` is the whole allowlist,
/// `client` is the name the grants and the audit rows are recorded under, and
/// `expiresAt`/`oneShot` apply to every field in the list.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdkPairRequest {
    pub client: String,
    pub grants: Vec<McpGrantInput>,
    /// Unix timestamp after which the grants stop authorizing reads.
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// Spend each grant on its first successful read.
    #[serde(default)]
    pub one_shot: bool,
}

/// One paired MCP client as the settings card may show it: the name the person
/// typed and how many field grants the token carries. No token, no item data.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpClientInfo {
    pub client: String,
    pub grants: usize,
}

/// Snapshot for the MCP card. The binary path is reported even when it is
/// missing, because "where Kestrel looked" is the only actionable answer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpStatus {
    pub pipe: String,
    pub binary: String,
    pub binary_present: bool,
    /// The SDK pipe is serving; MCP has no listener of its own.
    pub running: bool,
    pub unlocked: bool,
    pub clients: Vec<McpClientInfo>,
}

/// One field ticked in the pairing checklist. `itemId`/`fieldId` are the ids
/// `mcp_inventory` returned; the core verifies both before they become a grant.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpGrantInput {
    pub item_id: String,
    pub field_id: String,
}

/// Returned by `mcp_pair`: the token is readable once, and the client name is
/// echoed so the card can confirm what it just approved.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpPairing {
    pub client: String,
    pub pipe: String,
    pub token: String,
}

/// One audit row with the names resolved for display. The value that was read
/// is not here and is never stored in the table.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpAuditRow {
    pub client: String,
    pub item_id: String,
    /// `None` once the item has been deleted from the vault.
    pub item_title: Option<String>,
    pub field: String,
    /// `None` once the field no longer exists.
    pub field_label: Option<String>,
    pub at: i64,
}

/// Where the live session comes from. Production uses Tauri's managed
/// `VaultState`; tests point at a scratch vault directly so no app is needed.
enum VaultSource {
    App(AppHandle),
    #[cfg(test)]
    Direct(Arc<VaultState>),
}

impl VaultSource {
    fn state(&self) -> &VaultState {
        match self {
            VaultSource::App(app) => app.state::<VaultState>().inner(),
            #[cfg(test)]
            VaultSource::Direct(state) => state,
        }
    }
}

/// The protocol backend. It holds no secrets: every request re-reads the vault,
/// and a `run` value lives only in the stack frame that builds the child's
/// environment.
struct VaultBackend {
    source: VaultSource,
    /// Shared with the pipe server; set when the app shuts down so a long-lived
    /// child is killed instead of blocking the exit path.
    stop: Arc<AtomicBool>,
}

impl VaultBackend {
    /// Run `read` with an open session. Both the core watchdog and this check
    /// can expire the session, so a request that arrives just after the timeout
    /// is still refused.
    fn session<T>(
        &self,
        read: impl FnOnce(&VaultState) -> Result<T, VaultError>,
    ) -> Result<T, SdkError> {
        let state = self.source.state();
        match state.maybe_autolock() {
            Ok(true) => return Err(SdkError::Locked),
            Ok(false) => {}
            Err(error) => return Err(map_error(error)),
        }
        read(state).map_err(map_error)
    }
}

impl SdkBackend for VaultBackend {
    fn unlocked(&self) -> bool {
        let state = self.source.state();
        if matches!(state.maybe_autolock(), Ok(true)) {
            return false;
        }
        // Cheap on purpose: the watcher calls this twice a second, and
        // `state()` decrypts every vault name to build a snapshot.
        !state.is_locked()
    }

    fn items(&self) -> Result<Vec<ItemMeta>, SdkError> {
        self.session(|state| {
            // Metadata is mapped immediately: the summaries carry the username
            // and URL, and neither may cross the pipe.
            let summaries = state.list_quiet("", None, false)?;
            Ok(summaries
                .into_iter()
                .map(|summary| ItemMeta {
                    id: summary.id,
                    title: summary.title,
                    category: summary.category,
                })
                .collect())
        })
    }

    fn items_for(&self, client: &str) -> Result<Vec<ItemMeta>, SdkError> {
        self.session(|state| {
            // A scoped CLI token sees only the items it holds a live grant on,
            // so a title the person did not hand out is not even listable.
            Ok(state
                .cli_items(client)?
                .into_iter()
                .map(|summary| ItemMeta {
                    id: summary.id,
                    title: summary.title,
                    category: summary.category,
                })
                .collect())
        })
    }

    fn copy(&self, item_id: &str, field: &str) -> Result<(), SdkError> {
        // Quiet: answering a pipe client is not the user working, so it must
        // not postpone the auto-lock (and with it the token's own revocation).
        self.session(|state| state.copy_field_quiet(item_id, field))
    }

    fn copy_for(&self, client: &str, item_id: &str, field: &str) -> Result<(), SdkError> {
        self.session(|state| state.cli_copy(client, item_id, field))
    }

    fn run(&self, argv: &[String], env: &[EnvBinding]) -> Result<RunOutput, SdkError> {
        // Resolve every value inside the vault first: the command must not
        // start with a partial environment.
        let resolved = self.session(|state| {
            let mut pairs = Vec::with_capacity(env.len());
            for binding in env {
                let item = state.get_quiet(&binding.id)?;
                let value = if binding.field == "__notes" {
                    item.notes
                } else {
                    item.fields
                        .iter()
                        .find(|field| field.id == binding.field)
                        .map(|field| field.value.clone())
                        .ok_or(VaultError::FieldNotFound)?
                };
                pairs.push((binding.name.clone(), value));
            }
            Ok(pairs)
        })?;
        spawn_child(argv, &resolved, &self.stop)
    }

    fn run_for(
        &self,
        client: &str,
        argv: &[String],
        env: &[EnvBinding],
    ) -> Result<RunOutput, SdkError> {
        // One round trip under one lock: every binding is checked and resolved
        // before a one-shot grant is spent, and nothing is spawned if one of
        // them is not granted.
        let resolved = self.session(|state| {
            let bindings: Vec<(String, String)> = env
                .iter()
                .map(|binding| (binding.id.clone(), binding.field.clone()))
                .collect();
            let values = state.cli_resolve(client, &bindings)?;
            Ok(env
                .iter()
                .zip(values)
                .map(|(binding, value)| (binding.name.clone(), value))
                .collect::<Vec<_>>())
        })?;
        spawn_child(argv, &resolved, &self.stop)
    }

    fn secrets(&self) -> Result<Vec<SecretItem>, SdkError> {
        self.session(secret_items)
    }

    fn reveal(&self, client: &str, item_id: &str, field: &str) -> Result<String, SdkError> {
        // Grant check, decryption and audit happen under one session lock in
        // the core; this layer only names the client the token belongs to.
        self.session(|state| state.mcp_reveal(client, item_id, field))
    }

    fn browser_status(&self) -> Result<BrowserStatus, SdkError> {
        self.session(browser_ops::status)
    }

    fn browser_mode(&self, origin: &str) -> Result<String, SdkError> {
        self.session(|state| Ok(state.browser_rule(origin)?))
    }

    fn browser_items(&self, origin: &str) -> Result<Vec<BrowserItem>, SdkError> {
        self.session(|state| browser_ops::items(state, origin))
    }

    fn browser_reveal(&self, origin: &str, item_id: &str, field: &str) -> Result<String, SdkError> {
        // The core re-checks the origin rule, the item's URL and the field
        // kind, then audits the read before returning the value.
        self.session(|state| browser_ops::reveal(state, origin, item_id, field))
    }

    fn focus(&self) -> Result<(), SdkError> {
        let app = match &self.source {
            VaultSource::App(app) => Some(app),
            #[cfg(test)]
            VaultSource::Direct(_) => None,
        };
        crate::browser::focus_main_optional(app).map_err(SdkError::Internal)
    }
}

/// Normalize and vet a principal name: what the grants and every audit row are
/// recorded under. Trimmed, at most 64 characters, ASCII letters/digits and the
/// three separators a tool name usually has. Both pairing paths use this so an
/// MCP client and a CLI token can never be nameable one way and not the other.
fn validate_principal_name(raw: &str) -> Result<&str, String> {
    let client = raw.trim();
    if client.is_empty() {
        return Err("Name the client you are pairing.".into());
    }
    if client.chars().count() > 64 {
        return Err("A client name is at most 64 characters.".into());
    }
    if !client
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
    {
        return Err(
            "A client name may use letters, digits, spaces, dot, dash and underscore.".into(),
        );
    }
    Ok(client)
}

/// Map a ticked checklist to canonical `(item uuid, field id)` pairs.
///
/// A tick naming an item or field that is no longer in the vault is refused
/// instead of silently dropped: the person reviewed a different list. A
/// repeated tick is collapsed, because the grant table keys on the pair.
fn grant_pairs(
    state: &VaultState,
    grants: &[McpGrantInput],
) -> Result<Vec<(String, String)>, String> {
    let mut pairs: Vec<(String, String)> = Vec::with_capacity(grants.len());
    for grant in grants {
        let item = state
            .get_quiet(&grant.item_id)
            .map_err(|error| error.to_string())?;
        let field = item
            .fields
            .iter()
            .find(|field| field.id == grant.field_id)
            .ok_or_else(|| "That field is no longer in the item. Reload the list.".to_string())?;
        let pair = (item.id.clone(), field.id.clone());
        if !pairs.contains(&pair) {
            pairs.push(pair);
        }
    }
    Ok(pairs)
}

/// Item ids, titles and field names, resolved inside the open session.
///
/// Shared by `secrets.list` and the pairing checklist so the two can never
/// disagree about what a client is allowed to ask for. Nothing here retains a
/// value: each item is decrypted, mapped, and dropped.
fn secret_items(state: &VaultState) -> Result<Vec<SecretItem>, VaultError> {
    let summaries = state.list_quiet("", None, false)?;
    let mut items = Vec::with_capacity(summaries.len());
    for summary in summaries {
        let item = state.get_quiet(&summary.id)?;
        items.push(SecretItem {
            id: item.id,
            title: item.title,
            fields: item
                .fields
                .into_iter()
                .map(|field| SecretField {
                    id: field.id,
                    label: field.label,
                    kind: field.kind,
                })
                .collect(),
        });
    }
    Ok(items)
}

/// Start `argv` with `env` added to its environment and capture a bounded
/// amount of output. The values are placed in the child's environment block by
/// `Command`; they are never written anywhere else, and the wait loop watches
/// the shutdown flag so an app exit cannot hang on a long-running child.
fn spawn_child(
    argv: &[String],
    env: &[(String, String)],
    stop: &AtomicBool,
) -> Result<RunOutput, SdkError> {
    let Some(program) = argv.first() else {
        return Err(SdkError::BadRequest("run needs a command".into()));
    };
    let mut command = Command::new(program);
    command
        .args(&argv[1..])
        // A child that reads stdin would otherwise wait on the app's console.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    let mut child = command
        .spawn()
        .map_err(|error| SdkError::Spawn(error.to_string()))?;

    let stdout = child.stdout.take().map(drain);
    let stderr = child.stderr.take().map(drain);

    let exit = loop {
        if stop.load(Ordering::SeqCst) {
            let _ = child.kill();
            break child.wait();
        }
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                let _ = child.kill();
                break Err(error);
            }
        }
    };
    let stdout = stdout
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let stderr = stderr
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let status = exit.map_err(|error| SdkError::Internal(error.to_string()))?;

    Ok(RunOutput {
        // A process killed by a signal has no code; -1 says so rather than
        // pretending it succeeded.
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout.bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr.bytes).into_owned(),
        truncated: stdout.truncated || stderr.truncated,
    })
}

/// Bounded capture of one stream. Beyond the cap the bytes are counted as
/// truncated and discarded — the pipe is still drained so the child never
/// blocks, but the response cannot grow without bound.
#[derive(Default)]
struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
}

fn drain<R: Read + Send + 'static>(mut reader: R) -> std::thread::JoinHandle<Captured> {
    std::thread::spawn(move || {
        let mut captured = Captured::default();
        let mut buffer = [0u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let room = protocol::MAX_CAPTURE_LEN.saturating_sub(captured.bytes.len());
                    let take = room.min(read);
                    captured.bytes.extend_from_slice(&buffer[..take]);
                    if take < read {
                        captured.truncated = true;
                    }
                }
            }
        }
        captured
    })
}

fn map_error(error: VaultError) -> SdkError {
    match error {
        VaultError::Locked => SdkError::Locked,
        VaultError::NotGranted => SdkError::NotGranted,
        VaultError::NotFound | VaultError::FieldNotFound => SdkError::NotFound,
        // The store reports a missing row inside its own error. A client asking
        // for an item that was deleted must see `not_found`, not `internal`.
        VaultError::Store(kestrel_core::store::StoreError::NotFound) => SdkError::NotFound,
        // An origin that is not `http(s)://host[:port]`, or a rule literal
        // that is not fill/ask/off, is the caller's mistake.
        VaultError::Invalid(message) => SdkError::BadRequest(message),
        other => SdkError::Internal(other.to_string()),
    }
}

/// Revoke the token when the vault is not open. Split out so the watcher's one
/// decision is testable without an app handle.
fn revoke_if_locked(state: &VaultState, auth: &Auth) -> bool {
    let locked = state
        .state()
        .map(|snapshot| snapshot.locked)
        .unwrap_or(true);
    if locked && auth.has_session_tokens() {
        // Only session tokens die here. The browser token is persisted in a
        // file and every browser op already answers `locked` while the vault
        // is closed, so deleting it would break the bridge after one idle lock.
        auth.revoke_session();
        return true;
    }
    false
}

/// Owns the pipe server and the pairing state for the process lifetime.
pub struct SdkHandle {
    server: Mutex<Option<pipe::Server>>,
    startup_error: Mutex<Option<String>>,
    auth: Arc<Auth>,
    stop: Arc<AtomicBool>,
}

impl SdkHandle {
    /// Start the pipe against the app's managed session and watch for a lock.
    pub fn start(app: &AppHandle) -> SdkHandle {
        let auth = Arc::new(Auth::new());
        // The bridge token is the one pairing that survives a restart: the
        // browser-started host has only the file to go on. Restoring its
        // digest here means the file is not a stale artefact after relaunch.
        if let Ok(Some(token)) = crate::browser::read_token() {
            auth.restore_browser(&token);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let backend: Arc<dyn SdkBackend> = Arc::new(VaultBackend {
            source: VaultSource::App(app.clone()),
            stop: Arc::clone(&stop),
        });
        let handle = Self::launch(auth, stop, backend);

        // The token is bound to one unlocked session. Poll rather than hook
        // every lock path (UI, tray, auto-lock): there is exactly one place
        // that answers "is the vault still open", and it is the session.
        let watcher_app = app.clone();
        let watcher_auth = Arc::clone(&handle.auth);
        let watcher_stop = Arc::clone(&handle.stop);
        let _ = std::thread::Builder::new()
            .name("kestrel-sdk-lock".into())
            .spawn(move || {
                while !watcher_stop.load(Ordering::SeqCst) {
                    std::thread::sleep(LOCK_POLL);
                    if watcher_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let state = watcher_app.state::<VaultState>();
                    revoke_if_locked(state.inner(), &watcher_auth);
                }
            });
        handle
    }

    fn launch(auth: Arc<Auth>, stop: Arc<AtomicBool>, backend: Arc<dyn SdkBackend>) -> SdkHandle {
        let shared = Arc::new(pipe::Shared {
            backend,
            auth: Arc::clone(&auth),
            stop: Arc::clone(&stop),
        });
        let (server, error) = match pipe::Server::start(shared) {
            Ok(server) => (Some(server), None),
            Err(error) => (None, Some(error.to_string())),
        };
        SdkHandle {
            server: Mutex::new(server),
            startup_error: Mutex::new(error),
            auth,
            stop,
        }
    }

    /// Stop the pipe and wait for its threads. Idempotent.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let server = self.server.lock().expect("sdk server mutex").take();
        if let Some(server) = server {
            server.stop();
        }
        // A stopped handle cannot be paired: the pipe is gone, so a token would
        // only sit in memory until the process dies.
        self.auth.revoke();
    }

    /// Pipe state plus pairing state. No secret is touched.
    pub fn status(&self, state: &VaultState) -> SdkStatus {
        SdkStatus {
            running: self.server.lock().expect("sdk server mutex").is_some(),
            pipe: PIPE_PATH.to_string(),
            paired: self.auth.cli_paired(),
            unlocked: state
                .state()
                .map(|snapshot| !snapshot.locked)
                .unwrap_or(false),
            error: self.startup_error.lock().expect("sdk error mutex").clone(),
        }
    }

    /// Mint a new token with no allowlist. Re-pairing replaces the previous
    /// CLI token, which is what makes a leaked token recoverable from this card
    /// alone.
    ///
    /// Compatibility path: a token minted here reads every field of every item
    /// while the vault is open, exactly as `sdk.pair()` always has. A person
    /// who wants field-level consent uses [`Self::pair_scoped`] instead.
    pub fn pair(&self, state: &VaultState) -> Result<SdkPairing, String> {
        self.require_unlocked(state)?;
        Ok(SdkPairing {
            pipe: PIPE_PATH.to_string(),
            token: self.auth.pair(),
        })
    }

    /// Mint a CLI token bound to exactly `request.grants`.
    ///
    /// The allowlist is persisted for the `cli` principal before the token
    /// exists, so the token is never the only record of what it may read. The
    /// token also carries the list, which makes a field outside it
    /// `not_granted` without a vault read; the persisted rows remain the
    /// authority for the fields it does carry, so a deleted or expired grant
    /// stops working even while the token is alive.
    pub fn pair_scoped(
        &self,
        state: &VaultState,
        request: &SdkPairRequest,
    ) -> Result<SdkPairing, String> {
        self.require_unlocked(state)?;
        let client = validate_principal_name(&request.client)?;
        if request.grants.is_empty() {
            return Err(
                "Tick at least one field to grant, or pair a CLI without an allowlist.".into(),
            );
        }
        let pairs = grant_pairs(state, &request.grants)?;
        state
            .cli_set_grants(client, &pairs, request.expires_at, request.one_shot)
            .map_err(|error| error.to_string())?;
        let scope = pairs
            .into_iter()
            .map(|(item, field)| Grant { item, field })
            .collect();
        Ok(SdkPairing {
            pipe: PIPE_PATH.to_string(),
            token: self.auth.pair_cli(client, scope),
        })
    }

    /// Refuse pairing while the vault is closed: a token minted then would only
    /// ever answer `locked`.
    fn require_unlocked(&self, state: &VaultState) -> Result<(), String> {
        let unlocked = state
            .state()
            .map(|snapshot| !snapshot.locked)
            .unwrap_or(false);
        if !unlocked {
            return Err("Unlock the vault before pairing a CLI.".into());
        }
        Ok(())
    }

    /* -------------------------------------------------------------- browser */

    /// Mint the one token the browser host reads from its file. The vault must
    /// be open: a token minted while locked would only ever answer `locked`.
    pub fn pair_browser(&self, state: &VaultState) -> Result<String, String> {
        let unlocked = state
            .state()
            .map(|snapshot| !snapshot.locked)
            .unwrap_or(false);
        if !unlocked {
            return Err("Unlock the vault before installing the browser bridge.".into());
        }
        Ok(self.auth.pair_browser())
    }

    /// Drop the browser token (uninstall). The file is removed separately.
    pub fn revoke_browser(&self) -> bool {
        self.auth.revoke_browser()
    }

    /* ---------------------------------------------------------------- mcp */

    /// Where the MCP binary sits: next to the app executable, which is also
    /// where Cargo puts it for a dev build. Reported even when absent.
    fn mcp_binary() -> (String, bool) {
        let path = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("kestrel-mcp.exe")))
            .unwrap_or_else(|| std::path::PathBuf::from("kestrel-mcp.exe"));
        let present = path.is_file();
        (path.display().to_string(), present)
    }

    /// The MCP card's state. Grants and clients come from the session; the
    /// counts are the token's own allowlist, not a fresh database read.
    pub fn mcp_status(&self, state: &VaultState) -> McpStatus {
        let (binary, binary_present) = Self::mcp_binary();
        McpStatus {
            pipe: PIPE_PATH.to_string(),
            binary,
            binary_present,
            running: self.server.lock().expect("sdk server mutex").is_some(),
            unlocked: state
                .state()
                .map(|snapshot| !snapshot.locked)
                .unwrap_or(false),
            clients: self
                .auth
                .mcp_clients()
                .into_iter()
                .map(|(client, grants)| McpClientInfo { client, grants })
                .collect(),
        }
    }

    /// Pair one MCP client with exactly the fields the person ticked.
    ///
    /// Nothing is minted until every grant is verified against the vault: an
    /// allowlist that names a field which does not exist would be a promise the
    /// server cannot keep. The persisted rows and the token describe the same
    /// list; the token carries it so a request never has to trust the caller.
    pub fn pair_mcp(
        &self,
        state: &VaultState,
        client: &str,
        grants: &[McpGrantInput],
    ) -> Result<McpPairing, String> {
        let unlocked = state
            .state()
            .map(|snapshot| !snapshot.locked)
            .unwrap_or(false);
        if !unlocked {
            return Err("Unlock the vault before pairing an MCP client.".into());
        }
        let client = validate_principal_name(client)?;
        if grants.is_empty() {
            return Err("Tick at least one field to grant.".into());
        }
        let pairs = grant_pairs(state, grants)?;
        state
            .mcp_set_grants(client, &pairs)
            .map_err(|error| error.to_string())?;
        let scope = pairs
            .into_iter()
            .map(|(item, field)| Grant { item, field })
            .collect();
        Ok(McpPairing {
            client: client.to_string(),
            pipe: PIPE_PATH.to_string(),
            token: self.auth.pair_mcp(client, scope),
        })
    }

    /// End one MCP client's access: drop its token and its persisted grants.
    /// Reports a name that was never paired instead of silently succeeding.
    pub fn revoke_mcp(&self, state: &VaultState, client: &str) -> Result<(), String> {
        let client = client.trim();
        let had_token = self.auth.revoke_mcp(client);
        let cleared = state
            .mcp_clear_grants(client)
            .map_err(|error| error.to_string())?;
        if !had_token && cleared == 0 {
            return Err("That MCP client is not paired.".into());
        }
        Ok(())
    }

    /// Every live CLI/MCP token without its secret. The item editor uses this
    /// to name only principals that can actually read, and to respect each
    /// token's own allowlist as the ceiling a grant cannot exceed.
    pub fn access_tokens(&self) -> Vec<SessionToken> {
        self.auth.session_tokens()
    }

    /// Drop one CLI token. The caller clears the matching persisted grants;
    /// only the vault knows where they live.
    pub fn revoke_cli(&self, client: Option<&str>) -> bool {
        self.auth.revoke_cli(client)
    }

    /// The checklist: every item with its field ids and labels, no values.
    pub fn mcp_inventory(&self, state: &VaultState) -> Result<Vec<SecretItem>, String> {
        secret_items(state).map_err(|error| error.to_string())
    }

    /// Recent MCP reads with item titles and field labels resolved for display.
    /// A row whose item was deleted keeps its ids and loses only the names.
    pub fn mcp_audit(&self, state: &VaultState, limit: usize) -> Result<Vec<McpAuditRow>, String> {
        let entries = state.mcp_audit(limit).map_err(|error| error.to_string())?;
        let mut resolved: HashMap<String, Option<(String, HashMap<String, String>)>> =
            HashMap::new();
        let mut rows = Vec::with_capacity(entries.len());
        for entry in entries {
            if !resolved.contains_key(&entry.item_id) {
                let names = state.get_quiet(&entry.item_id).ok().map(|item| {
                    let fields = item
                        .fields
                        .into_iter()
                        .map(|field| (field.id, field.label))
                        .collect();
                    (item.title, fields)
                });
                resolved.insert(entry.item_id.clone(), names);
            }
            let names = resolved.get(&entry.item_id).and_then(Option::as_ref);
            let (item_title, field_label) = match names {
                Some((title, fields)) => (Some(title.clone()), fields.get(&entry.field).cloned()),
                None => (None, None),
            };
            rows.push(McpAuditRow {
                client: entry.client,
                item_id: entry.item_id,
                item_title,
                field: entry.field,
                field_label,
                at: entry.at,
            });
        }
        Ok(rows)
    }
}

/// `sdk_status` command: the pipe, whether it is serving, whether a token is
/// valid, and whether the vault is open.
#[tauri::command]
pub fn sdk_status(state: State<'_, VaultState>, sdk: State<'_, SdkHandle>) -> SdkStatus {
    sdk.status(state.inner())
}

/// `sdk_pair` command: issue a fresh token, shown once.
///
/// Without `request` this is the legacy unrestricted token. With it, the token
/// is scoped to the ticked fields and the allowlist is persisted for the `cli`
/// principal, the same way `mcp_pair` does for an MCP client.
#[tauri::command]
pub fn sdk_pair(
    state: State<'_, VaultState>,
    sdk: State<'_, SdkHandle>,
    request: Option<SdkPairRequest>,
) -> Result<SdkPairing, String> {
    match request {
        Some(request) => sdk.pair_scoped(state.inner(), &request),
        None => sdk.pair(state.inner()),
    }
}

/// `mcp_status`: the binary path, the pipe, and which MCP clients hold a token.
#[tauri::command]
pub fn mcp_status(state: State<'_, VaultState>, sdk: State<'_, SdkHandle>) -> McpStatus {
    sdk.mcp_status(state.inner())
}

/// `mcp_inventory`: item ids, titles and field names for the pairing checklist.
#[tauri::command]
pub fn mcp_inventory(state: State<'_, VaultState>) -> Result<Vec<SecretItem>, String> {
    secret_items(state.inner()).map_err(|error| error.to_string())
}

/// `mcp_pair`: record the checked grants and mint an `Mcp` token for `client`.
#[tauri::command]
pub fn mcp_pair(
    state: State<'_, VaultState>,
    sdk: State<'_, SdkHandle>,
    client: String,
    grants: Vec<McpGrantInput>,
) -> Result<McpPairing, String> {
    sdk.pair_mcp(state.inner(), &client, &grants)
}

/// `mcp_audit`: recent reads, newest first. No value is in this payload.
#[tauri::command]
pub fn mcp_audit(
    state: State<'_, VaultState>,
    sdk: State<'_, SdkHandle>,
    limit: Option<usize>,
) -> Result<Vec<McpAuditRow>, String> {
    sdk.mcp_audit(state.inner(), limit.unwrap_or(50))
}

/// `mcp_revoke`: drop one client's token and its grants.
#[tauri::command]
pub fn mcp_revoke(
    state: State<'_, VaultState>,
    sdk: State<'_, SdkHandle>,
    client: String,
) -> Result<(), String> {
    sdk.revoke_mcp(state.inner(), &client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::protocol;
    use kestrel_core::model::{Category, Item};
    use std::io::{BufRead, BufReader, Write};
    use std::os::windows::io::AsRawHandle;
    use std::path::PathBuf;
    use std::process::id;
    use std::time::{SystemTime, UNIX_EPOCH};

    const PASSWORD: &str = "correct horse battery staple";

    fn scratch_vault(tag: &str) -> (Arc<VaultState>, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "kestrel-sdk-{tag}-{}-{}",
            id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let state = VaultState::open(dir.join("kestrel.db")).expect("vault opens");
        state.create(PASSWORD).expect("vault created");
        (Arc::new(state), dir)
    }

    fn handle_without_pipe() -> SdkHandle {
        SdkHandle {
            server: Mutex::new(None),
            startup_error: Mutex::new(None),
            auth: Arc::new(Auth::new()),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    #[test]
    fn status_reports_the_pipe_and_pairing_without_secrets() {
        let (state, dir) = scratch_vault("status");
        let handle = handle_without_pipe();
        let status = handle.status(&state);
        assert!(!status.running, "no pipe was started for this test");
        assert_eq!(status.pipe, PIPE_PATH);
        assert!(status.unlocked);
        assert!(!status.paired);
        assert!(status.error.is_none());

        let token = handle.pair(&state).expect("pair").token;
        assert_eq!(token.len(), 64, "32 bytes as hex");
        assert!(handle.status(&state).paired);
        // The status snapshot must never carry the token itself.
        let serialised = serde_json::to_string(&handle.status(&state)).expect("status json");
        assert!(!serialised.contains(&token));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pairing_needs_an_unlocked_vault_and_locking_revokes() {
        let (state, dir) = scratch_vault("revoke");
        let handle = handle_without_pipe();
        state.lock().expect("lock");
        assert!(handle.pair(&state).is_err(), "a locked vault cannot pair");

        state.unlock(PASSWORD).expect("unlock");
        let _ = handle.pair(&state).expect("pair");
        assert!(handle.auth.paired());
        assert!(!revoke_if_locked(&state, &handle.auth));

        state.lock().expect("lock");
        assert!(revoke_if_locked(&state, &handle.auth));
        assert!(!handle.auth.paired(), "locking the vault revokes the token");
        assert!(!handle.status(&state).paired);

        let _ = std::fs::remove_dir_all(dir);
    }

    /* ------------------------------------------------------------- mcp api */

    /// Seed a login whose password field is `secret`. Returns the saved item
    /// and the password field id, plus the username field id for refusals.
    fn seed_login(state: &VaultState, secret: &str) -> (Item, String, String) {
        let mut item = Item::new(Category::Login, "Deploy target".to_string());
        let mut password = String::new();
        let mut username = String::new();
        for field in &mut item.fields {
            match field.kind.as_str() {
                "password" => {
                    field.value = secret.to_string();
                    password = field.id.clone();
                }
                "username" => username = field.id.clone(),
                _ => {}
            }
        }
        let item = state.save(item).expect("seed item");
        (item, password, username)
    }

    #[test]
    fn mcp_pairing_records_grants_and_every_granted_read_is_audited() {
        let (state, dir) = scratch_vault("mcp-audit");
        let secret = "mcp-secret-value".to_string();
        let (item, password_field, username_field) = seed_login(&state, &secret);
        let handle = handle_without_pipe();

        let pairing = handle
            .pair_mcp(
                &state,
                "editor",
                &[McpGrantInput {
                    item_id: item.id.clone(),
                    field_id: password_field.clone(),
                }],
            )
            .expect("pair");
        assert_eq!(pairing.client, "editor");
        assert_eq!(pairing.pipe, PIPE_PATH);
        assert_eq!(pairing.token.len(), 64, "32 bytes as hex");
        // The allowlist is persisted before the token exists; the card reads it
        // back and the reveal consults it.
        let grants = state.mcp_grants().expect("grants");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].client, "editor");
        assert_eq!(grants[0].item_id, item.id);
        assert_eq!(grants[0].field, password_field);

        let value = state
            .mcp_reveal("editor", &item.id, &password_field)
            .expect("granted reveal");
        assert_eq!(value, secret);
        let audit = state.mcp_audit(10).expect("audit");
        assert_eq!(audit.len(), 1, "one read, one row: {audit:?}");
        assert_eq!(audit[0].client, "editor");
        assert_eq!(audit[0].item_id, item.id);
        assert_eq!(audit[0].field, password_field);
        assert!(audit[0].at > 0);

        // A field the person did not tick is refused, and refusing records
        // nothing.
        let refused = state
            .mcp_reveal("editor", &item.id, &username_field)
            .expect_err("no grant");
        assert!(matches!(refused, VaultError::NotGranted));
        assert_eq!(state.mcp_audit(10).expect("audit").len(), 1);

        // The card's rows resolve names for display and still carry no value.
        let rows = handle.mcp_audit(&state, 10).expect("audit rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].item_title.as_deref(), Some("Deploy target"));
        assert_eq!(rows[0].field_label.as_deref(), Some("password"));
        let serialised = serde_json::to_string(&rows).expect("audit json");
        assert!(
            !serialised.contains(&secret),
            "the card's audit leaked: {serialised}"
        );

        // Revoking drops the token and the rows: the old grant is dead.
        handle.revoke_mcp(&state, "editor").expect("revoke");
        assert!(state.mcp_grants().expect("grants").is_empty());
        assert!(matches!(
            state.mcp_reveal("editor", &item.id, &password_field),
            Err(VaultError::NotGranted)
        ));
        assert!(handle.mcp_status(&state).clients.is_empty());
        assert!(
            handle.revoke_mcp(&state, "editor").is_err(),
            "already revoked"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mcp_pairing_requires_an_unlocked_vault_a_name_and_real_fields() {
        let (state, dir) = scratch_vault("mcp-validate");
        let (item, password_field, _username) = seed_login(&state, "value");
        let handle = handle_without_pipe();
        let grant = McpGrantInput {
            item_id: item.id.clone(),
            field_id: password_field.clone(),
        };

        assert!(
            handle.pair_mcp(&state, "", &[grant.clone()]).is_err(),
            "no name"
        );
        assert!(handle
            .pair_mcp(&state, "bad/name", &[grant.clone()])
            .is_err());
        assert!(handle.pair_mcp(&state, "editor", &[]).is_err(), "no grants");
        assert!(
            handle
                .pair_mcp(
                    &state,
                    "editor",
                    &[McpGrantInput {
                        item_id: item.id.clone(),
                        field_id: "no-such-field".into(),
                    }]
                )
                .is_err(),
            "a grant must name a field that exists"
        );
        assert!(
            handle
                .pair_mcp(
                    &state,
                    "editor",
                    &[McpGrantInput {
                        item_id: "no-such-item".into(),
                        field_id: password_field.clone(),
                    }]
                )
                .is_err(),
            "a grant must name an item that exists"
        );
        // None of the refusals minted anything.
        assert!(handle.mcp_status(&state).clients.is_empty());
        assert!(state.mcp_grants().expect("grants").is_empty());

        state.lock().expect("lock");
        assert!(
            handle.pair_mcp(&state, "editor", &[grant]).is_err(),
            "locked"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mcp_inventory_is_field_names_without_values() {
        let (state, dir) = scratch_vault("mcp-inventory");
        let secret = "inventory-secret".to_string();
        let (item, password_field, _username) = seed_login(&state, &secret);
        let handle = handle_without_pipe();

        let items = handle.mcp_inventory(&state).expect("inventory");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, item.id);
        assert_eq!(items[0].title, "Deploy target");
        let password = items[0]
            .fields
            .iter()
            .find(|field| field.id == password_field)
            .expect("password field listed");
        assert_eq!(password.label, "password");
        assert_eq!(password.kind, "password");
        let serialised = serde_json::to_string(&items).expect("inventory json");
        assert!(
            !serialised.contains(&secret),
            "inventory leaked: {serialised}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cli_pairing_with_an_allowlist_scopes_the_token_and_the_legacy_pair_does_not() {
        let (state, dir) = scratch_vault("cli-scoped");
        let secret = "cli-scoped-value";
        let (item, password_field, username_field) = seed_login(&state, secret);
        let handle = handle_without_pipe();

        let pairing = handle
            .pair_scoped(
                &state,
                &SdkPairRequest {
                    client: "terminal".to_string(),
                    grants: vec![McpGrantInput {
                        item_id: item.id.clone(),
                        field_id: password_field.clone(),
                    }],
                    expires_at: None,
                    one_shot: false,
                },
            )
            .expect("scoped pair");
        assert_eq!(pairing.token.len(), 64, "32 bytes as hex");
        assert_eq!(pairing.pipe, PIPE_PATH);
        // The token is scoped to the same list that was persisted.
        match handle.auth.scope(Some(&pairing.token)) {
            Some(protocol::Scope::CliScoped { client, grants }) => {
                assert_eq!(client, "terminal");
                assert_eq!(grants.len(), 1);
                assert_eq!(grants[0].field, password_field);
            }
            other => panic!("expected a scoped CLI token, got {other:?}"),
        }
        let grants = state.grants_for("cli", "terminal").expect("grants");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].item_id, item.id);
        assert_eq!(grants[0].field, password_field);

        // A field outside the list is refused; the granted one is audited.
        assert!(matches!(
            state.cli_resolve("terminal", &[(item.id.clone(), username_field.clone())]),
            Err(VaultError::NotGranted)
        ));
        assert_eq!(
            state
                .cli_resolve("terminal", &[(item.id.clone(), password_field.clone())])
                .expect("granted read"),
            vec![secret.to_string()]
        );
        let audit = state.audit_for_item(&item.id).expect("audit");
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].client, "cli:terminal");

        // The legacy pairing still mints an unrestricted token: no allowlist,
        // and the scope is the old `Cli` variant, not `CliScoped`.
        let legacy = handle.pair(&state).expect("legacy pair");
        assert!(matches!(
            handle.auth.scope(Some(&legacy.token)),
            Some(protocol::Scope::Cli)
        ));
        // There is one CLI slot, so the scoped token is gone.
        assert!(handle.auth.scope(Some(&pairing.token)).is_none());
        assert!(handle.auth.cli_paired());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn scoped_cli_pairing_refuses_an_empty_list_a_bad_name_and_a_locked_vault() {
        let (state, dir) = scratch_vault("cli-validate");
        let (item, password_field, _username) = seed_login(&state, "value");
        let handle = handle_without_pipe();
        let grant = McpGrantInput {
            item_id: item.id.clone(),
            field_id: password_field.clone(),
        };
        let request = |client: &str, grants: Vec<McpGrantInput>| SdkPairRequest {
            client: client.to_string(),
            grants,
            expires_at: None,
            one_shot: false,
        };

        assert!(
            handle
                .pair_scoped(&state, &request("terminal", vec![]))
                .is_err(),
            "an empty allowlist would be a token that can read nothing"
        );
        assert!(handle
            .pair_scoped(&state, &request("", vec![grant.clone()]))
            .is_err());
        assert!(handle
            .pair_scoped(&state, &request("bad/name", vec![grant.clone()]))
            .is_err());
        assert!(
            handle
                .pair_scoped(
                    &state,
                    &request(
                        "terminal",
                        vec![McpGrantInput {
                            item_id: item.id.clone(),
                            field_id: "no-such-field".into(),
                        }],
                    ),
                )
                .is_err(),
            "a grant must name a field that exists"
        );
        // None of the refusals minted a token or a row.
        assert!(!handle.auth.cli_paired());
        assert!(state
            .grants_for("cli", "terminal")
            .expect("grants")
            .is_empty());

        state.lock().expect("lock");
        assert!(handle
            .pair_scoped(&state, &request("terminal", vec![grant]))
            .is_err());

        let _ = std::fs::remove_dir_all(dir);
    }

    fn ask(
        client: &mut std::fs::File,
        reader: &mut BufReader<std::fs::File>,
        request: &serde_json::Value,
    ) -> (String, serde_json::Value) {
        let mut line = serde_json::to_vec(request).expect("request json");
        line.push(b'\n');
        client.write_all(&line).expect("write request");
        client.flush().expect("flush request");
        let mut response = String::new();
        reader.read_line(&mut response).expect("read response");
        let value = serde_json::from_str(&response).expect("response json");
        (response, value)
    }

    /// End-to-end over the real pipe: start the server on the production pipe
    /// name (or a unique one when a Kestrel instance already owns it), inspect
    /// the DACL the kernel applied, list metadata, run a real child with a
    /// vault value in its environment, and check the value never appears in a
    /// response. When `KESTREL_CLI_BIN` points at the built `kestrel-cli`, the
    /// same server is driven through the real client binary — that is the
    /// transcript the acceptance report uses.
    #[test]
    fn live_sdk_pipe_end_to_end() {
        let (state, dir) = scratch_vault("live");
        let secret = format!(
            "sdk-secret-{}-{}",
            id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );

        let mut item = Item::new(Category::Login, "Deploy target".to_string());
        item.fields
            .iter_mut()
            .find(|field| field.kind == "password")
            .expect("login has a password field")
            .value = secret.clone();
        let item = state.save(item).expect("seed item");
        let field_id = item
            .fields
            .iter()
            .find(|field| field.kind == "password")
            .expect("password field")
            .id
            .clone();

        let stop = Arc::new(AtomicBool::new(false));
        let backend: Arc<dyn SdkBackend> = Arc::new(VaultBackend {
            source: VaultSource::Direct(Arc::clone(&state)),
            stop: Arc::clone(&stop),
        });
        let auth = Arc::new(Auth::new());
        let token = auth.pair();
        let shared = Arc::new(pipe::Shared {
            backend,
            auth: Arc::clone(&auth),
            stop: Arc::clone(&stop),
        });
        let name = format!(
            r"\\.\pipe\kestrel-sdk-test-{}-{}",
            id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let (server, production) = match pipe::Server::start(Arc::clone(&shared)) {
            Ok(server) => (server, true),
            // Another Kestrel owns the name; the protocol is identical, so the
            // wire checks still run on a private pipe.
            Err(pipe::PipeError::AlreadyRunning(_)) => (
                pipe::Server::start_named(&name, Arc::clone(&shared)).expect("test pipe starts"),
                false,
            ),
            Err(error) => panic!("could not start the SDK pipe: {error}"),
        };
        let pipe_name = if production {
            PIPE_PATH.to_string()
        } else {
            name
        };
        let client = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pipe_name)
            .expect("connect to the SDK pipe");
        let mut reader = BufReader::new(client.try_clone().expect("clone pipe"));
        let mut client = client;

        // The ACL the kernel actually stored: protected, one ACE, current user.
        let dacl = crate::agent::pipe::dacl_sddl(client.as_raw_handle()).expect("dacl");
        let sid = crate::agent::pipe::current_user_sid_for_test().expect("user sid");
        assert!(dacl.starts_with("D:P"), "DACL must be protected: {dacl}");
        assert_eq!(dacl.matches('(').count(), 1, "exactly one ACE: {dacl}");
        assert!(dacl.contains(&sid), "ACE must name the user: {dacl}");
        assert!(!dacl.contains(";;;WD"), "Everyone must not appear: {dacl}");
        assert!(!dacl.contains(";;;BU"), "Users must not appear: {dacl}");
        eprintln!("SDK pipe DACL: {dacl}");

        // status needs no token.
        let (_, status) = ask(
            &mut client,
            &mut reader,
            &serde_json::json!({"op": "status"}),
        );
        assert_eq!(status["ok"], serde_json::json!(true));
        assert_eq!(status["running"], serde_json::json!(true));
        assert_eq!(status["pipe"], serde_json::json!(PIPE_PATH));
        assert_eq!(status["paired"], serde_json::json!(true));
        assert_eq!(status["unlocked"], serde_json::json!(true));

        // items.list: metadata only, and the response never contains the value.
        let (raw, listed) = ask(
            &mut client,
            &mut reader,
            &serde_json::json!({"op": "items.list", "token": token}),
        );
        assert_eq!(listed["ok"], serde_json::json!(true));
        let items = listed["items"].as_array().expect("items array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], serde_json::json!(item.id));
        assert_eq!(items[0]["title"], serde_json::json!("Deploy target"));
        assert_eq!(items[0]["category"], serde_json::json!("login"));
        assert!(!raw.contains(&secret), "items.list leaked a value: {raw}");
        assert!(
            !raw.contains("password"),
            "items.list leaked a field id: {raw}"
        );

        // run: the server starts a real child with the value in its environment.
        // The child compares the variable without printing it, so the exit code
        // proves the exact value arrived while the response stays value-free.
        // `expected` is the test's own comparison target, not a vault string.
        let run_request = |expected: &str| -> serde_json::Value {
            serde_json::from_str(&format!(
                r#"{{"op":"run","token":"{token}","argv":["cmd","/d","/c","if \"%KESTREL_TEST_SECRET%\"==\"{expected}\" (exit 0) else (exit 9)"],"env":[{{"id":"{}","field":"{field_id}","as":"KESTREL_TEST_SECRET"}}]}}"#,
                item.id
            ))
            .expect("run request")
        };
        let (raw, matched) = ask(&mut client, &mut reader, &run_request(&secret));
        assert_eq!(matched["ok"], serde_json::json!(true));
        assert_eq!(
            matched["exitCode"],
            serde_json::json!(0),
            "the child must see the vault value in its environment"
        );
        assert!(
            !raw.contains(&secret),
            "the value must never come back over the pipe: {raw}"
        );
        // The same comparison against a wrong value fails, so exit 0 above is
        // the comparison succeeding, not the child ignoring its environment.
        let (_, mismatched) = ask(&mut client, &mut reader, &run_request("not-the-value"));
        assert_eq!(mismatched["exitCode"], serde_json::json!(9));
        // The response has exactly the fields the protocol defines: there is no
        // side channel that could carry the value.
        let mut keys: Vec<&str> = matched
            .as_object()
            .expect("run response object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["exitCode", "ok"]);

        // A bad token and an unknown op are coded errors, not silent successes.
        let (_, denied) = ask(
            &mut client,
            &mut reader,
            &serde_json::json!({"op": "items.list", "token": "not-the-token"}),
        );
        assert_eq!(
            denied["error"],
            serde_json::json!(protocol::ERR_UNAUTHORIZED)
        );
        let (_, unknown) = ask(
            &mut client,
            &mut reader,
            &serde_json::json!({"op": "items.purge", "token": token}),
        );
        assert_eq!(
            unknown["error"],
            serde_json::json!(protocol::ERR_UNKNOWN_OP)
        );

        // The real client binary, when the harness points at it. It can only
        // reach the production pipe name, which is why this runs only when the
        // server owns that name and not a private test name.
        let cli = if production {
            std::env::var("KESTREL_CLI_BIN").ok()
        } else {
            None
        };
        if let Some(cli) = &cli {
            fn run_cli(exe: &str, args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
                let mut command = std::process::Command::new(exe);
                command.args(args);
                for (key, value) in env {
                    command.env(key, value);
                }
                command.output().expect("kestrel-cli runs")
            }

            let status = run_cli(cli, &["status"], &[]);
            let out = String::from_utf8_lossy(&status.stdout);
            eprintln!("$ kestrel-cli status\n{}", out.trim_end());
            assert!(status.status.success(), "status failed: {out}");
            assert!(out.contains("unlocked: yes"), "{out}");
            assert!(out.contains("paired:   yes"), "{out}");

            let list = run_cli(cli, &["--token", token.as_str(), "list"], &[]);
            let out = String::from_utf8_lossy(&list.stdout);
            eprintln!("$ kestrel-cli --token <token> list\n{}", out.trim_end());
            assert!(list.status.success(), "list failed: {out}");
            assert!(out.contains(&item.id), "list lost the item id: {out}");
            assert!(out.contains("Deploy target"), "list lost the title: {out}");
            assert!(!out.contains(&secret), "list leaked a value: {out}");

            let binding = format!("{}:{field_id}=KESTREL_TEST_SECRET", item.id);
            let run = run_cli(
                cli,
                &[
                    "run",
                    "--env",
                    &binding,
                    "--",
                    "cmd",
                    "/c",
                    "echo",
                    "%KESTREL_TEST_SECRET%",
                ],
                &[("KESTREL_TOKEN", token.as_str())],
            );
            let out = String::from_utf8_lossy(&run.stdout);
            eprintln!(
                "$ kestrel-cli run --env {binding} -- cmd /c echo %KESTREL_TEST_SECRET%\n{}\nexit {}",
                out.trim_end(),
                run.status.code().unwrap_or(-1)
            );
            assert!(run.status.success(), "run failed: {out}");
            assert_eq!(
                out.trim(),
                secret.as_str(),
                "the child did not see the value"
            );

            let denied = run_cli(cli, &["--token", "not-the-token", "list"], &[]);
            eprintln!(
                "$ kestrel-cli --token not-the-token list -> exit {}",
                denied.status.code().unwrap_or(-1)
            );
            assert_eq!(denied.status.code(), Some(4), "bad token must be exit 4");
        } else {
            eprintln!(
                "skipping CLI transcript: KESTREL_CLI_BIN is unset or the production pipe is owned"
            );
        }

        // --- MCP over the same pipe -----------------------------------------
        // A scoped token lists field names without a value, reveals exactly the
        // field the person granted, is refused for any other field, and the
        // read lands in the store's audit table before the answer is built.
        let username_field = item
            .fields
            .iter()
            .find(|field| field.kind == "username")
            .expect("login has a username field")
            .id
            .clone();
        state
            .mcp_set_grants("editor", &[(item.id.clone(), field_id.clone())])
            .expect("record the grant");
        let mcp_token = auth.pair_mcp(
            "editor",
            vec![protocol::Grant {
                item: item.id.clone(),
                field: field_id.clone(),
            }],
        );

        let (raw, secrets) = ask(
            &mut client,
            &mut reader,
            &serde_json::json!({"op": "secrets.list", "token": mcp_token}),
        );
        assert_eq!(secrets["ok"], serde_json::json!(true));
        assert!(!raw.contains(&secret), "secrets.list leaked a value: {raw}");
        assert!(raw.contains(&field_id), "secrets.list lost the field id");
        assert!(
            raw.contains("password"),
            "secrets.list lost the field label"
        );
        assert!(
            secrets["items"][0].get("fields").is_some(),
            "secrets.list must describe fields"
        );

        let (reveal_request, revealed) = ask(
            &mut client,
            &mut reader,
            &serde_json::json!({
                "op": "items.reveal",
                "token": mcp_token,
                "id": item.id,
                "field": field_id,
            }),
        );
        assert_eq!(
            revealed,
            serde_json::json!({"ok": true, "value": secret}),
            "a granted reveal answers with the value: {reveal_request}"
        );
        eprintln!(
            "items.reveal (granted) -> ok, value of {} bytes",
            revealed["value"].as_str().map(str::len).unwrap_or(0)
        );

        let (_, ungranted) = ask(
            &mut client,
            &mut reader,
            &serde_json::json!({
                "op": "items.reveal",
                "token": mcp_token,
                "id": item.id,
                "field": username_field,
            }),
        );
        assert_eq!(
            ungranted["error"],
            serde_json::json!(protocol::ERR_NOT_GRANTED)
        );
        // A CLI token asking for the same op is a scope violation.
        let (_, cli_reveal) = ask(
            &mut client,
            &mut reader,
            &serde_json::json!({
                "op": "items.reveal",
                "token": token,
                "id": item.id,
                "field": field_id,
            }),
        );
        assert_eq!(
            cli_reveal["error"],
            serde_json::json!(protocol::ERR_FORBIDDEN)
        );

        let audit = state.mcp_audit(10).expect("audit rows");
        assert_eq!(
            audit.len(),
            1,
            "only the granted read is recorded: {audit:?}"
        );
        assert_eq!(audit[0].client, "editor");
        eprintln!(
            "mcp_audit -> {} row(s): {} read {} / {}",
            audit.len(),
            audit[0].client,
            audit[0].item_id,
            audit[0].field
        );

        // The real binary, when the harness points at it. It can only reach the
        // production pipe name, which is why this needs `production`.
        if let Ok(binary) = std::env::var("KESTREL_MCP_BIN") {
            if production {
                let script = [
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "kestrel-sdk-test", "version": "1"}
                        }
                    }),
                    serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                    serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "list_secrets", "arguments": {}}
                    }),
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 4,
                        "method": "tools/call",
                        "params": {
                            "name": "get_secret",
                            "arguments": {"id": item.id, "field": field_id}
                        }
                    }),
                ]
                .iter()
                .map(|message| message.to_string())
                .collect::<Vec<_>>()
                .join("\n")
                    + "\n";

                let mut child = std::process::Command::new(&binary)
                    .env("KESTREL_TOKEN", &mcp_token)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .expect("kestrel-mcp runs");
                child
                    .stdin
                    .as_mut()
                    .expect("mcp stdin")
                    .write_all(script.as_bytes())
                    .expect("write mcp script");
                drop(child.stdin.take());
                let output = child.wait_with_output().expect("mcp output");
                let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("$ kestrel-mcp (stdio)\n{}", stdout.trim_end());
                assert!(output.status.success(), "mcp exited: {stderr}");

                let replies: Vec<serde_json::Value> = stdout
                    .lines()
                    .map(|line| serde_json::from_str(line).expect("one json message per line"))
                    .collect();
                assert_eq!(replies.len(), 4, "the notification has no reply: {stdout}");
                assert_eq!(
                    replies[0]["result"]["serverInfo"]["name"],
                    serde_json::json!("kestrel-mcp")
                );
                assert_eq!(
                    replies[0]["result"]["clientInfo"]["name"],
                    serde_json::json!("kestrel-sdk-test")
                );
                assert_eq!(
                    replies[1]["result"]["tools"]
                        .as_array()
                        .expect("tools")
                        .len(),
                    2
                );
                let listed = replies[2]["result"]["content"][0]["text"]
                    .as_str()
                    .expect("list text");
                assert!(listed.contains(&item.id), "list lost the item id");
                assert!(listed.contains(&field_id), "list lost the field id");
                assert!(!listed.contains(&secret), "list leaked a value");
                assert_eq!(
                    replies[3]["result"]["content"][0]["text"],
                    serde_json::json!(secret),
                    "get_secret must answer with the value"
                );
                assert!(!stderr.contains(&secret), "the value must not reach stderr");

                // The binary's read is a second audit row, same client.
                let audit = state.mcp_audit(10).expect("audit rows");
                assert_eq!(audit.len(), 2, "{audit:?}");
                assert!(audit.iter().all(|row| row.client == "editor"));
            } else {
                eprintln!(
                    "skipping kestrel-mcp transcript: the production pipe is owned by another instance"
                );
            }
        } else {
            eprintln!("skipping kestrel-mcp transcript: KESTREL_MCP_BIN is unset");
        }

        // Locking revokes the token and every op but status answers `locked`.
        state.lock().expect("lock");
        auth.revoke();
        let (_, locked) = ask(
            &mut client,
            &mut reader,
            &serde_json::json!({"op": "items.list", "token": token}),
        );
        assert_eq!(locked["error"], serde_json::json!(protocol::ERR_LOCKED));
        let (_, status) = ask(
            &mut client,
            &mut reader,
            &serde_json::json!({"op": "status"}),
        );
        assert_eq!(status["unlocked"], serde_json::json!(false));
        assert_eq!(status["paired"], serde_json::json!(false));

        if let Some(cli) = &cli {
            let locked = std::process::Command::new(cli)
                .args(["--token", token.as_str(), "list"])
                .output()
                .expect("kestrel-cli runs");
            eprintln!(
                "$ kestrel-cli --token <token> list (vault locked) -> exit {}",
                locked.status.code().unwrap_or(-1)
            );
            assert_eq!(locked.status.code(), Some(3), "a locked vault is exit 3");
        }

        drop(client);
        drop(reader);
        server.stop();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn run_reports_a_missing_command_instead_of_panicking() {
        let stop = AtomicBool::new(false);
        let error = spawn_child(&[], &[], &stop).expect_err("empty argv");
        assert_eq!(error.code(), protocol::ERR_BAD_REQUEST);
        let error = spawn_child(&["kestrel-no-such-program".to_string()], &[], &stop)
            .expect_err("missing program");
        assert_eq!(error.code(), protocol::ERR_SPAWN_FAILED);
    }
}
