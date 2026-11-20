//! CLI/SDK wire protocol: one JSON object per line, request → response.
//!
//! The protocol is transport-free on purpose — [`respond`] is a pure function
//! of (auth, backend, request) — so every op, the auth rules and the locked
//! vault behaviour are testable without a pipe.
//!
//! Three rules shape every handler:
//!
//! * **A token has a scope.** A `Cli` token is the original pairing: `status`,
//!   `items.list`, `items.copy` and `run` over every item and field — that is
//!   the behaviour of a token minted without an allowlist and it is kept for
//!   compatibility. A `CliScoped` token has the same ops but every item and
//!   field it names must be on the allowlist the person ticked, and a field
//!   outside it is `not_granted`. An `Mcp` token names the client it was minted
//!   for and the exact fields that client may read; it answers `secrets.list`
//!   (ids, titles and field names — no values) and `items.reveal`, and nothing
//!   else. A token that asks for an op outside its scope is `forbidden`, the
//!   same code as a token that is not paired at all, because the caller's next
//!   move is identical: re-pair.
//! * **Only `items.reveal` returns a value, and only with consent.** The value
//!   goes to the MCP server's own stdout, which is the one place a person asked
//!   for it. Every granted reveal is recorded by the backend before the answer
//!   is built; the check *and* the audit live there, next to the vault.
//! * **Failures are coded.** Every refusal is `{"ok":false,"error":"<code>"}`
//!   with one of the stable [`ERR_*`] codes; an unknown op is never a success.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Largest request line accepted, before the JSON is parsed. `run --argv` with
/// many environment bindings still fits comfortably; anything bigger is a
/// client bug or an attempt to make the server allocate unbounded memory.
pub const MAX_REQUEST_LEN: usize = 64 * 1024;

/// Largest bytes captured from the child's stdout (and, separately, stderr).
/// Beyond this the stream is drained and discarded: the child must never block
/// on a full pipe, but the response must never grow without bound either.
pub const MAX_CAPTURE_LEN: usize = 64 * 1024;

pub const ERR_BAD_REQUEST: &str = "bad_request";
pub const ERR_UNKNOWN_OP: &str = "unknown_op";
pub const ERR_UNAUTHORIZED: &str = "unauthorized";
pub const ERR_FORBIDDEN: &str = "forbidden";
pub const ERR_LOCKED: &str = "locked";
pub const ERR_NOT_FOUND: &str = "not_found";
pub const ERR_NOT_GRANTED: &str = "not_granted";
pub const ERR_INVALID_ENV_NAME: &str = "invalid_env_name";
pub const ERR_SPAWN_FAILED: &str = "spawn_failed";
pub const ERR_INTERNAL: &str = "internal";

/// One `run` environment binding: item id, field id, and the variable name the
/// child will see.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct EnvBinding {
    pub id: String,
    pub field: String,
    #[serde(rename = "as")]
    pub name: String,
}

/// One field an MCP client was granted at pairing time. `item` is the item
/// uuid, `field` the field id inside the encrypted blob.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub item: String,
    pub field: String,
}

/// What one token may do. A scope is decided when the token is minted and never
/// widens afterwards: re-pairing replaces the token, it does not extend it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum Scope {
    /// The original CLI/SDK pairing: metadata, clipboard, run — every item and
    /// every field while the vault is open. This is what `sdk.pair()` mints and
    /// it keeps that behaviour for a person who has not chosen an allowlist.
    Cli,
    /// A CLI token minted with an explicit allowlist. `client` is the principal
    /// the grants and the audit line are recorded under; `grants` is the same
    /// list the token was minted with, so a field outside it never reaches the
    /// backend. The backend still re-checks the persisted rows, which is what
    /// makes a revoked or expired grant effective before the token dies.
    CliScoped { client: String, grants: Vec<Grant> },
    /// One MCP client and the fields its user ticked in Settings.
    Mcp { client: String, grants: Vec<Grant> },
    /// The browser bridge. It may list items matching an origin and reveal one
    /// login field, but only where `browser_sites` says `fill`.
    Browser,
}

/// A parsed request line. All payload fields are optional and validated by the
/// op that needs them, so an unknown op is reported as such instead of as a
/// deserialisation failure.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub token: Option<String>,
    pub op: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub argv: Option<Vec<String>>,
    #[serde(default)]
    pub env: Option<Vec<EnvBinding>>,
    /// Canonical origin for `browser.*`. Required by those ops.
    #[serde(default)]
    pub origin: Option<String>,
}

/// Item metadata: the only item data ever returned to a client. Field values,
/// notes, TOTP secrets and tags stay in the vault.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ItemMeta {
    pub id: String,
    pub title: String,
    pub category: String,
}

/// One field of a [`SecretItem`]: id, label and kind, never a value.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecretField {
    pub id: String,
    pub label: String,
    pub kind: String,
}

/// What `secrets.list` returns: enough for an MCP client to ask for a field,
/// and not one byte of what is in it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecretItem {
    pub id: String,
    pub title: String,
    pub fields: Vec<SecretField>,
}

/// One field the browser chip may ask to reveal. No value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserField {
    pub id: String,
    pub label: String,
    pub kind: String,
}

/// One item matching the page's origin. The chip shows the title and the
/// origin; the field ids are only used after the person clicks Fill.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserItem {
    pub id: String,
    pub title: String,
    pub category: String,
    pub fields: Vec<BrowserField>,
}

/// `browser.status`: non-secret state for the extension and the settings card.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BrowserStatus {
    /// The native host is registered for at least one browser and its manifest
    /// exists.
    pub installed: bool,
    /// The native messaging host name (`com.kestrel.bridge`).
    pub host: String,
    /// Explicit `browser_sites` rows, not counting the implicit `ask` default.
    pub rules: usize,
    /// The origin the host was installed for; fixed by the extension's key.
    pub extension_id: String,
    /// A bridge token file exists next to the vault.
    pub token_present: bool,
}

/// What `run` reports back. The environment values used to start the child are
/// deliberately absent: the client can read the child's output, not the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    /// At least one stream exceeded [`MAX_CAPTURE_LEN`] and was cut.
    pub truncated: bool,
}

/// Why an op could not be served. [`SdkError::code`] is the stable string a
/// client switches on; the rendered message is for a human reading stderr.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SdkError {
    #[error("vault is locked")]
    Locked,
    #[error("token is not paired")]
    Unauthorized,
    /// The token is valid but its scope does not cover this op. Distinct from
    /// [`SdkError::Unauthorized`] on purpose: a client that reads
    /// "token is not paired" for a perfectly good token cannot tell a bug in
    /// its own pairing from a permission it will never have.
    #[error("this token is not allowed to call {0}")]
    Forbidden(String),
    #[error("not found")]
    NotFound,
    #[error("this client has no grant for that field")]
    NotGranted,
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("unknown operation: {0}")]
    UnknownOp(String),
    #[error("invalid environment variable name")]
    InvalidEnvName,
    #[error("could not start the command: {0}")]
    Spawn(String),
    #[error("{0}")]
    Internal(String),
}

impl SdkError {
    pub fn code(&self) -> &'static str {
        match self {
            SdkError::Locked => ERR_LOCKED,
            SdkError::Unauthorized => ERR_UNAUTHORIZED,
            SdkError::Forbidden(_) => ERR_FORBIDDEN,
            SdkError::NotFound => ERR_NOT_FOUND,
            SdkError::NotGranted => ERR_NOT_GRANTED,
            SdkError::BadRequest(_) => ERR_BAD_REQUEST,
            SdkError::UnknownOp(_) => ERR_UNKNOWN_OP,
            SdkError::InvalidEnvName => ERR_INVALID_ENV_NAME,
            SdkError::Spawn(_) => ERR_SPAWN_FAILED,
            SdkError::Internal(_) => ERR_INTERNAL,
        }
    }
}

/// What the protocol layer needs from the vault. Implementations resolve item
/// data and spawn children; the protocol never touches a field value itself.
pub trait SdkBackend: Send + Sync {
    /// The vault is open. While this is false every op except `status` answers
    /// `locked`, regardless of the token.
    fn unlocked(&self) -> bool;

    /// Item metadata only, in vault order. This is the unrestricted path: a
    /// `Cli` token minted without an allowlist lists everything the vault has.
    fn items(&self) -> Result<Vec<ItemMeta>, SdkError>;

    /// Item metadata for a scoped CLI token: only the items `client` holds a
    /// live grant on.
    ///
    /// The default refuses instead of delegating to [`Self::items`], because a
    /// backend that does not understand grants must not answer a scoped token
    /// with the unrestricted listing — that would turn an allowlist into a
    /// suggestion. A backend that has the vault overrides this.
    fn items_for(&self, _client: &str) -> Result<Vec<ItemMeta>, SdkError> {
        Err(SdkError::Forbidden("scoped CLI listing".into()))
    }

    /// Copy one field through the core's clipboard path (timed wipe included).
    fn copy(&self, item_id: &str, field: &str) -> Result<(), SdkError>;

    /// Copy one field for a scoped CLI token. `client` must hold a live grant
    /// for exactly this item and field, and the read is audited. The default
    /// refuses; see [`Self::items_for`] for why it does not delegate.
    fn copy_for(&self, _client: &str, _item_id: &str, _field: &str) -> Result<(), SdkError> {
        Err(SdkError::Forbidden("scoped CLI copy".into()))
    }

    /// Resolve every binding inside the vault and start `argv` with the values
    /// in its environment. The values must not appear in the returned output.
    fn run(&self, argv: &[String], env: &[EnvBinding]) -> Result<RunOutput, SdkError>;

    /// The same for a scoped CLI token: every binding must be granted for
    /// `client`, and one ungranted binding refuses the whole run before
    /// anything is spawned. The default refuses.
    fn run_for(
        &self,
        _client: &str,
        _argv: &[String],
        _env: &[EnvBinding],
    ) -> Result<RunOutput, SdkError> {
        Err(SdkError::Forbidden("scoped CLI run".into()))
    }

    /// Item ids, titles and field names — no values. Backs `secrets.list`, so
    /// an MCP client can choose a field without a read ever happening.
    fn secrets(&self) -> Result<Vec<SecretItem>, SdkError>;

    /// One field value for a paired MCP client.
    ///
    /// The implementation owns the two decisions that matter: whether the
    /// `grants` row for `(mcp, client, item, field)` allows the read, and
    /// recording it in `mcp_audit` before the value leaves. Returning
    /// `NotGranted` there is what makes a token scope a ceiling rather than a
    /// promise.
    fn reveal(&self, client: &str, item_id: &str, field: &str) -> Result<String, SdkError>;

    /// Non-secret bridge state for `browser.status`.
    fn browser_status(&self) -> Result<BrowserStatus, SdkError>;

    /// The rule in force for `origin`: `fill`, `ask` or `off`.
    fn browser_mode(&self, origin: &str) -> Result<String, SdkError>;

    /// Items whose saved URLs match `origin`, with field ids but no values.
    fn browser_items(&self, origin: &str) -> Result<Vec<BrowserItem>, SdkError>;

    /// One login field for a page on `origin`.
    ///
    /// The implementation owns the policy: `browser_sites.mode` for the
    /// origin must be `fill`, the item must have a URL on that origin, and the
    /// read is audited before the value is returned. Everything else is
    /// `not_granted`.
    fn browser_reveal(&self, origin: &str, item_id: &str, field: &str) -> Result<String, SdkError>;

    /// Bring the app window forward. Used by the extension's "locked" chip;
    /// it reveals nothing, so it is allowed even without a token.
    fn focus(&self) -> Result<(), SdkError> {
        Ok(())
    }
}

/// One minted token: its digest and what it may do. The token itself is never
/// stored — only this.
#[derive(Debug)]
struct Pairing {
    digest: [u8; 32],
    scope: Scope,
    /// Unix seconds when this session minted the token. The card reports it,
    /// because a token that dies with the session has no other creation date.
    created_at: i64,
}

/// The two token kinds the surface can enumerate. The browser bridge has its
/// own lifetime and file, so it is deliberately not part of this shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Cli,
    Mcp,
}

/// One live token as the settings and item-editor surfaces may describe it.
///
/// Neither the token nor its digest is part of this shape. `scope` is exactly
/// the allowlist the token was minted with — a ceiling, not the persisted
/// grant set — and `None` is the legacy CLI pairing that has no allowlist at
/// all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToken {
    pub kind: TokenKind,
    /// The principal name grants and audit rows are recorded under. `None`
    /// only for the unrestricted CLI pairing, which has no name.
    pub client: Option<String>,
    pub scope: Option<Vec<Grant>>,
    pub created_at: i64,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Pairing state: the session's tokens, kept only as SHA-256 digests.
///
/// Two kinds coexist on purpose: a person may run the CLI while an editor speaks
/// MCP, and neither should silently revoke the other. `pair` replaces the CLI
/// slot, `pair_mcp` replaces the slot for that one client name, and `revoke`
/// (what a vault lock calls) drops everything. Once revoked nothing can pair
/// without a new token from Settings.
#[derive(Debug, Default)]
pub struct Auth {
    pairings: Mutex<Vec<Pairing>>,
}

impl Auth {
    pub fn new() -> Auth {
        Auth::default()
    }

    /// Mint a fresh 32-byte `Cli` token, store its digest and return the token.
    /// This is the only moment the token exists in readable form.
    ///
    /// This is the unrestricted pairing: no allowlist, full read access while
    /// the vault is open, exactly as before grants existed. [`Self::pair_cli`]
    /// with a non-empty list is the scoped alternative.
    pub fn pair(&self) -> String {
        self.mint(Scope::Cli, |scope| {
            matches!(scope, Scope::Cli | Scope::CliScoped { .. })
        })
    }

    /// Mint a `CliScoped` token for `client` with exactly `grants`.
    ///
    /// There is one CLI slot, so this replaces the previous CLI token whatever
    /// its shape. The caller has already persisted the same list for the `cli`
    /// principal; a token minted with an empty list would be a token that can
    /// do nothing, and the SDK layer refuses to create one instead.
    pub fn pair_cli(&self, client: &str, grants: Vec<Grant>) -> String {
        self.mint(
            Scope::CliScoped {
                client: client.to_string(),
                grants,
            },
            |scope| matches!(scope, Scope::Cli | Scope::CliScoped { .. }),
        )
    }

    /// Mint an `Mcp` token for `client` with exactly `grants`. A client that
    /// pairs again replaces its previous allowlist; other clients keep theirs.
    pub fn pair_mcp(&self, client: &str, grants: Vec<Grant>) -> String {
        self.mint(
            Scope::Mcp {
                client: client.to_string(),
                grants,
            },
            |scope| matches!(scope, Scope::Mcp { client: existing, .. } if existing == client),
        )
    }

    /// Mint a fresh 32-byte `Browser` token, store its digest and return the
    /// token. The caller writes it to the user-only bridge file, which is the
    /// only copy that survives a restart.
    pub fn pair_browser(&self) -> String {
        self.mint(Scope::Browser, |scope| matches!(scope, Scope::Browser))
    }

    /// Re-register a token read from the bridge file on app start. Only its
    /// digest was ever written down, and a wrong or edited file simply never
    /// matches. An empty token is ignored.
    pub fn restore_browser(&self, token: &str) {
        if token.is_empty() {
            return;
        }
        let mut pairings = self.pairings.lock().expect("sdk token mutex");
        pairings.retain(|pairing| !matches!(pairing.scope, Scope::Browser));
        pairings.push(Pairing {
            digest: digest(token),
            scope: Scope::Browser,
            created_at: unix_now(),
        });
    }

    /// Drop the browser token. Returns whether one existed.
    pub fn revoke_browser(&self) -> bool {
        let mut pairings = self.pairings.lock().expect("sdk token mutex");
        let before = pairings.len();
        pairings.retain(|pairing| !matches!(pairing.scope, Scope::Browser));
        pairings.len() != before
    }

    /// Drop every session-scoped token (CLI and MCP) and keep the browser
    /// token. A lock makes every op `locked` anyway, so the persisted bridge
    /// token must not be destroyed by the lock/unlock cycle.
    pub fn revoke_session(&self) {
        let mut pairings = self.pairings.lock().expect("sdk token mutex");
        pairings.retain(|pairing| matches!(pairing.scope, Scope::Browser));
    }

    /// Whether a CLI token is valid, of either shape. `paired()` counts every
    /// scope; the SDK card asks this narrower question.
    pub fn cli_paired(&self) -> bool {
        self.pairings
            .lock()
            .expect("sdk token mutex")
            .iter()
            .any(|pairing| matches!(pairing.scope, Scope::Cli | Scope::CliScoped { .. }))
    }

    /// Whether the browser bridge has a token.
    pub fn browser_paired(&self) -> bool {
        self.pairings
            .lock()
            .expect("sdk token mutex")
            .iter()
            .any(|pairing| matches!(pairing.scope, Scope::Browser))
    }

    /// Whether a token that dies with the session exists. The lock watcher
    /// uses this so a browser-only process does not churn on every poll.
    pub fn has_session_tokens(&self) -> bool {
        self.pairings
            .lock()
            .expect("sdk token mutex")
            .iter()
            .any(|pairing| !matches!(pairing.scope, Scope::Browser))
    }

    fn mint(&self, scope: Scope, replaces: impl Fn(&Scope) -> bool) -> String {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        let token = hex(&bytes);
        let mut pairings = self.pairings.lock().expect("sdk token mutex");
        pairings.retain(|pairing| !replaces(&pairing.scope));
        pairings.push(Pairing {
            digest: digest(&token),
            scope,
            created_at: unix_now(),
        });
        token
    }

    #[allow(dead_code)] // used by the protocol tests and kept as the any-scope question
    pub fn paired(&self) -> bool {
        !self.pairings.lock().expect("sdk token mutex").is_empty()
    }

    /// Drop every token. Idempotent.
    pub fn revoke(&self) {
        self.pairings.lock().expect("sdk token mutex").clear();
    }

    /// Drop the MCP token minted for `client`. Returns whether one existed, so
    /// the card can report a stale name instead of pretending it worked.
    pub fn revoke_mcp(&self, client: &str) -> bool {
        let mut pairings = self.pairings.lock().expect("sdk token mutex");
        let before = pairings.len();
        pairings.retain(|pairing| {
            !matches!(&pairing.scope, Scope::Mcp { client: existing, .. } if existing == client)
        });
        pairings.len() != before
    }

    /// Every paired MCP client with its grant count. No token, no digest — this
    /// is what the settings card may render.
    pub fn mcp_clients(&self) -> Vec<(String, usize)> {
        self.pairings
            .lock()
            .expect("sdk token mutex")
            .iter()
            .filter_map(|pairing| match &pairing.scope {
                Scope::Mcp { client, grants } => Some((client.clone(), grants.len())),
                Scope::Cli | Scope::CliScoped { .. } | Scope::Browser => None,
            })
            .collect()
    }

    /// Every live CLI/MCP token, described without its secret. The browser
    /// bridge is omitted: it is not a principal and cannot hold field grants.
    ///
    /// The returned list is the token authority, so a surface that offers to
    /// grant or revoke access can name only tokens that actually exist. A
    /// persisted grant whose token was revoked by a lock is therefore not
    /// offered as live access.
    pub fn session_tokens(&self) -> Vec<SessionToken> {
        self.pairings
            .lock()
            .expect("sdk token mutex")
            .iter()
            .filter_map(|pairing| match &pairing.scope {
                Scope::Cli => Some(SessionToken {
                    kind: TokenKind::Cli,
                    client: None,
                    scope: None,
                    created_at: pairing.created_at,
                }),
                Scope::CliScoped { client, grants } => Some(SessionToken {
                    kind: TokenKind::Cli,
                    client: Some(client.clone()),
                    scope: Some(grants.clone()),
                    created_at: pairing.created_at,
                }),
                Scope::Mcp { client, grants } => Some(SessionToken {
                    kind: TokenKind::Mcp,
                    client: Some(client.clone()),
                    scope: Some(grants.clone()),
                    created_at: pairing.created_at,
                }),
                Scope::Browser => None,
            })
            .collect()
    }

    /// Drop the CLI token. `None` targets the unrestricted pairing, `Some`
    /// the scoped token minted for that client. Returns whether one existed.
    ///
    /// There is one CLI slot, so this mirrors [`Self::revoke_mcp`]: a name the
    /// card no longer shows is reported as not paired instead of succeeding
    /// silently.
    pub fn revoke_cli(&self, client: Option<&str>) -> bool {
        let mut pairings = self.pairings.lock().expect("sdk token mutex");
        let before = pairings.len();
        pairings.retain(|pairing| match (&pairing.scope, client) {
            (Scope::Cli, None) => false,
            (
                Scope::CliScoped {
                    client: existing, ..
                },
                Some(name),
            ) => existing.as_str() != name,
            _ => true,
        });
        pairings.len() != before
    }

    /// The scope of the pairing this token belongs to, if any. Comparing every
    /// stored digest in constant time costs nothing at this count and keeps the
    /// "wrong token" path free of an early exit.
    pub fn scope(&self, token: Option<&str>) -> Option<Scope> {
        let token = token?;
        let candidate = digest(token);
        let pairings = self.pairings.lock().expect("sdk token mutex");
        let mut found: Option<Scope> = None;
        for pairing in pairings.iter() {
            if constant_time_eq(&pairing.digest, &candidate) {
                found = Some(pairing.scope.clone());
            }
        }
        found
    }
}

/// Parse one request line.
pub fn parse_request(line: &[u8]) -> Result<Request, SdkError> {
    if line.len() > MAX_REQUEST_LEN {
        return Err(SdkError::BadRequest(format!(
            "request of {} bytes exceeds {MAX_REQUEST_LEN}",
            line.len()
        )));
    }
    serde_json::from_slice(line).map_err(|error| SdkError::BadRequest(error.to_string()))
}

/// The `{"ok":false,...}` body for an error.
pub fn error_response(error: &SdkError) -> Value {
    json!({
        "ok": false,
        "error": error.code(),
        "message": error.to_string(),
    })
}

/// Answer one request. The returned value is exactly what goes on the wire.
pub fn respond(auth: &Auth, backend: &dyn SdkBackend, request: &Request, pipe: &str) -> Value {
    match dispatch(auth, backend, request, pipe) {
        Ok(value) => value,
        Err(error) => error_response(&error),
    }
}

fn dispatch(
    auth: &Auth,
    backend: &dyn SdkBackend,
    request: &Request,
    pipe: &str,
) -> Result<Value, SdkError> {
    // `browser.focus` only asks the app window to come forward. It reads no
    // vault state and returns nothing secret, so it is answered even while the
    // vault is locked — that is exactly when the chip needs it.
    if request.op == "browser.focus" {
        backend.focus()?;
        return Ok(json!({ "ok": true }));
    }

    // `status` is the one op a locked vault answers: it reports the pipe and
    // pairing state (both non-secret) so a client can tell "not running" from
    // "locked" without a token.
    if request.op == "status" {
        return Ok(json!({
            "ok": true,
            "running": true,
            "pipe": pipe,
            "paired": auth.cli_paired(),
            "browserPaired": auth.browser_paired(),
            "unlocked": backend.unlocked(),
        }));
    }

    // Locked first, token second: a lock revokes the token, and the useful
    // answer for a client in that state is `locked`, not `unauthorized`.
    if !backend.unlocked() {
        return Err(SdkError::Locked);
    }
    let scope = auth
        .scope(request.token.as_deref())
        .ok_or(SdkError::Unauthorized)?;

    match request.op.as_str() {
        // A CLI token's surface. An MCP token is deliberately not allowed here:
        // its consent is field-by-field, and `run`/`copy` would reach every
        // field of every item. A scoped CLI token keeps the same ops but every
        // item and field it touches has to be on its allowlist.
        "items.list" | "items.copy" | "run" => {
            let (client, grants) = match &scope {
                Scope::Cli => (None, None),
                Scope::CliScoped { client, grants } => {
                    (Some(client.as_str()), Some(grants.as_slice()))
                }
                _ => return Err(SdkError::Forbidden(request.op.clone())),
            };
            cli_op(backend, request, client, grants)
        }
        "secrets.list" => {
            let Scope::Mcp { .. } = scope else {
                return Err(SdkError::Forbidden(request.op.clone()));
            };
            Ok(json!({ "ok": true, "items": backend.secrets()? }))
        }
        "items.reveal" => {
            let Scope::Mcp { client, grants } = scope else {
                return Err(SdkError::Forbidden(request.op.clone()));
            };
            let id = required(&request.id, "id")?;
            let field = required(&request.field, "field")?;
            // The token names the fields the person approved; a field outside
            // that list never reaches the backend. The backend then re-checks
            // the persisted grant before reading and records the read.
            if !grants
                .iter()
                .any(|grant| grant.item == id && grant.field == field)
            {
                return Err(SdkError::NotGranted);
            }
            let value = backend.reveal(&client, id, field)?;
            Ok(json!({ "ok": true, "value": value }))
        }
        // The browser bridge has one scope and one shape. A CLI or MCP token
        // asking for any of these is `forbidden`, because the origin policy is
        // not something those tokens carry.
        "browser.status" => {
            if !matches!(scope, Scope::Browser) {
                return Err(SdkError::Forbidden(request.op.clone()));
            }
            let status = backend.browser_status()?;
            Ok(json!({
                "ok": true,
                "installed": status.installed,
                "host": status.host,
                "rules": status.rules,
                "extensionId": status.extension_id,
                "tokenPresent": status.token_present,
            }))
        }
        "browser.items" => {
            if !matches!(scope, Scope::Browser) {
                return Err(SdkError::Forbidden(request.op.clone()));
            }
            let origin = required(&request.origin, "origin")?;
            let mode = backend.browser_mode(origin)?;
            let items = backend.browser_items(origin)?;
            Ok(json!({ "ok": true, "origin": origin, "mode": mode, "items": items }))
        }
        "browser.reveal" => {
            if !matches!(scope, Scope::Browser) {
                return Err(SdkError::Forbidden(request.op.clone()));
            }
            let origin = required(&request.origin, "origin")?;
            let id = required(&request.id, "id")?;
            let field = required(&request.field, "field")?;
            let value = backend.browser_reveal(origin, id, field)?;
            Ok(json!({ "ok": true, "value": value }))
        }
        other => Err(SdkError::UnknownOp(other.to_string())),
    }
}

/// The ops a CLI token may ask for.
///
/// `grants` is the token's own allowlist. It is a ceiling, not the authority:
/// the backend re-checks the persisted rows, so a revoked or expired grant
/// stops a read even while the token still carries it. A field outside the
/// token's list never reaches the backend at all.
fn cli_op(
    backend: &dyn SdkBackend,
    request: &Request,
    client: Option<&str>,
    grants: Option<&[Grant]>,
) -> Result<Value, SdkError> {
    match request.op.as_str() {
        "items.list" => {
            // A scoped token is filtered by the backend, which is the only side
            // that can consult the persisted grants; the protocol never
            // decrypts anything to answer a list.
            let items = match client {
                Some(client) => backend.items_for(client)?,
                None => backend.items()?,
            };
            Ok(json!({ "ok": true, "items": items }))
        }
        "items.copy" => {
            let id = required(&request.id, "id")?;
            let field = required(&request.field, "field")?;
            if let Some(grants) = grants {
                if !granted(grants, id, field) {
                    return Err(SdkError::NotGranted);
                }
            }
            match client {
                Some(client) => backend.copy_for(client, id, field)?,
                None => backend.copy(id, field)?,
            }
            Ok(json!({ "ok": true }))
        }
        "run" => {
            let argv = request
                .argv
                .as_deref()
                .filter(|argv| !argv.is_empty())
                .ok_or_else(|| SdkError::BadRequest("run needs a non-empty argv".into()))?;
            let env = request.env.clone().unwrap_or_default();
            for binding in &env {
                if !valid_env_name(&binding.name) {
                    return Err(SdkError::InvalidEnvName);
                }
                if binding.id.is_empty() || binding.field.is_empty() {
                    return Err(SdkError::BadRequest(
                        "every env binding needs an item id and a field".into(),
                    ));
                }
                if let Some(grants) = grants {
                    if !granted(grants, &binding.id, &binding.field) {
                        return Err(SdkError::NotGranted);
                    }
                }
            }
            let output = match client {
                Some(client) => backend.run_for(client, argv, &env)?,
                None => backend.run(argv, &env)?,
            };
            let mut body = serde_json::Map::new();
            body.insert("ok".into(), Value::Bool(true));
            body.insert("exitCode".into(), json!(output.exit_code));
            if !output.stdout.is_empty() {
                body.insert("stdout".into(), Value::String(output.stdout));
            }
            if !output.stderr.is_empty() {
                body.insert("stderr".into(), Value::String(output.stderr));
            }
            if output.truncated {
                body.insert("truncated".into(), Value::Bool(true));
            }
            Ok(Value::Object(body))
        }
        // `dispatch` only routes the three CLI ops here.
        other => Err(SdkError::UnknownOp(other.to_string())),
    }
}

/// Whether a token's allowlist names this exact pair.
fn granted(grants: &[Grant], item_id: &str, field: &str) -> bool {
    grants
        .iter()
        .any(|grant| grant.item == item_id && grant.field == field)
}

fn required<'a>(value: &'a Option<String>, name: &str) -> Result<&'a str, SdkError> {
    value
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| SdkError::BadRequest(format!("missing {name}")))
}

/// `[A-Z_][A-Z0-9_]*`. Deliberately ASCII: `Command::env` would accept far
/// more on Windows, but automation should not be able to set odd names.
pub fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_uppercase() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for index in 0..left.len() {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIPE: &str = r"\\.\pipe\kestrel-sdk";

    /// Backend double: records what the protocol asked for and returns fixed
    /// data. `run` in this double only reports the argv and names, never the
    /// values, which is what the wire must look like too.
    #[derive(Default)]
    struct FakeBackend {
        unlocked: std::sync::atomic::AtomicBool,
        copied: Mutex<Vec<(String, String)>>,
        ran: Mutex<Vec<(Vec<String>, Vec<EnvBinding>)>>,
        /// The principal each scoped `items` call named, so a test can prove
        /// the token's identity reaches the backend.
        listed: Mutex<Vec<String>>,
        /// Stands in for the `grants` row the real backend consults.
        granted: std::sync::atomic::AtomicBool,
        /// Every reveal that passed the grant check. The real backend writes an
        /// audit row at this point, before it returns the value.
        revealed: Mutex<Vec<(String, String, String)>>,
    }

    const SECRET: &str = "s3cret-value";

    impl FakeBackend {
        fn unlocked() -> FakeBackend {
            FakeBackend {
                unlocked: std::sync::atomic::AtomicBool::new(true),
                granted: std::sync::atomic::AtomicBool::new(true),
                ..FakeBackend::default()
            }
        }

        fn lock(&self) {
            self.unlocked
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl SdkBackend for FakeBackend {
        fn unlocked(&self) -> bool {
            self.unlocked.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn items(&self) -> Result<Vec<ItemMeta>, SdkError> {
            Ok(vec![ItemMeta {
                id: "item-1".into(),
                title: "Bank".into(),
                category: "login".into(),
            }])
        }

        fn items_for(&self, client: &str) -> Result<Vec<ItemMeta>, SdkError> {
            self.listed.lock().unwrap().push(client.to_string());
            Ok(vec![ItemMeta {
                id: "item-1".into(),
                title: "Bank".into(),
                category: "login".into(),
            }])
        }

        fn copy(&self, item_id: &str, field: &str) -> Result<(), SdkError> {
            self.copied
                .lock()
                .unwrap()
                .push((item_id.to_string(), field.to_string()));
            Ok(())
        }

        fn copy_for(&self, _client: &str, item_id: &str, field: &str) -> Result<(), SdkError> {
            self.copy(item_id, field)
        }

        fn run(&self, argv: &[String], env: &[EnvBinding]) -> Result<RunOutput, SdkError> {
            self.ran.lock().unwrap().push((argv.to_vec(), env.to_vec()));
            Ok(RunOutput {
                exit_code: 0,
                stdout: "ok\n".into(),
                stderr: String::new(),
                truncated: false,
            })
        }

        fn run_for(
            &self,
            _client: &str,
            argv: &[String],
            env: &[EnvBinding],
        ) -> Result<RunOutput, SdkError> {
            self.run(argv, env)
        }

        fn secrets(&self) -> Result<Vec<SecretItem>, SdkError> {
            Ok(vec![SecretItem {
                id: "item-1".into(),
                title: "Bank".into(),
                fields: vec![
                    SecretField {
                        id: "field-1".into(),
                        label: "username".into(),
                        kind: "username".into(),
                    },
                    SecretField {
                        id: "field-2".into(),
                        label: "password".into(),
                        kind: "password".into(),
                    },
                ],
            }])
        }

        fn reveal(&self, client: &str, item_id: &str, field: &str) -> Result<String, SdkError> {
            // The order matters and mirrors the real backend: grant, read,
            // record, answer.
            if !self.granted.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(SdkError::NotGranted);
            }
            if item_id != "item-1" || field != "field-2" {
                return Err(SdkError::NotFound);
            }
            self.revealed.lock().unwrap().push((
                client.to_string(),
                item_id.to_string(),
                field.to_string(),
            ));
            Ok(SECRET.to_string())
        }

        fn browser_status(&self) -> Result<BrowserStatus, SdkError> {
            Ok(BrowserStatus {
                installed: true,
                host: "com.kestrel.bridge".into(),
                rules: 2,
                extension_id: "ippcgmeddpnhhbjllfkknhlilnaneclk".into(),
                token_present: true,
            })
        }

        fn browser_mode(&self, _origin: &str) -> Result<String, SdkError> {
            Ok("fill".into())
        }

        fn browser_items(&self, _origin: &str) -> Result<Vec<BrowserItem>, SdkError> {
            Ok(vec![BrowserItem {
                id: "item-1".into(),
                title: "Bank".into(),
                category: "login".into(),
                fields: vec![
                    BrowserField {
                        id: "field-1".into(),
                        label: "username".into(),
                        kind: "username".into(),
                    },
                    BrowserField {
                        id: "field-2".into(),
                        label: "password".into(),
                        kind: "password".into(),
                    },
                ],
            }])
        }

        fn browser_reveal(
            &self,
            origin: &str,
            item_id: &str,
            field: &str,
        ) -> Result<String, SdkError> {
            if origin != "https://example.com" {
                return Err(SdkError::NotGranted);
            }
            if item_id != "item-1" || field != "field-2" {
                return Err(SdkError::NotFound);
            }
            Ok(SECRET.to_string())
        }
    }

    fn request(line: &str) -> Request {
        parse_request(line.as_bytes()).expect("request parses")
    }

    #[test]
    fn status_answers_without_a_token() {
        let auth = Auth::new();
        let backend = FakeBackend::unlocked();
        let response = respond(&auth, &backend, &request(r#"{"op":"status"}"#), PIPE);
        assert_eq!(response["ok"], json!(true));
        assert_eq!(response["running"], json!(true));
        assert_eq!(response["pipe"], json!(PIPE));
        assert_eq!(response["paired"], json!(false));
        assert_eq!(response["unlocked"], json!(true));
    }

    #[test]
    fn items_list_returns_metadata_only() {
        let auth = Auth::new();
        let token = auth.pair();
        let backend = FakeBackend::unlocked();
        let response = respond(
            &auth,
            &backend,
            &request(&format!(r#"{{"op":"items.list","token":"{token}"}}"#)),
            PIPE,
        );
        assert_eq!(response["ok"], json!(true));
        let item = &response["items"][0];
        assert_eq!(item["id"], json!("item-1"));
        assert_eq!(item["title"], json!("Bank"));
        assert_eq!(item["category"], json!("login"));
        // The metadata contract: no field, value, notes or tags keys at all.
        let object = item.as_object().expect("item object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["category", "id", "title"]);
    }

    #[test]
    fn items_copy_goes_through_the_backend() {
        let auth = Auth::new();
        let token = auth.pair();
        let backend = FakeBackend::unlocked();
        let response = respond(
            &auth,
            &backend,
            &request(&format!(
                r#"{{"op":"items.copy","token":"{token}","id":"item-1","field":"field-2"}}"#
            )),
            PIPE,
        );
        assert_eq!(response, json!({ "ok": true }));
        assert_eq!(
            *backend.copied.lock().unwrap(),
            vec![("item-1".to_string(), "field-2".to_string())]
        );
    }

    #[test]
    fn run_reports_output_and_passes_bindings() {
        let auth = Auth::new();
        let token = auth.pair();
        let backend = FakeBackend::unlocked();
        let response = respond(
            &auth,
            &backend,
            &request(&format!(
                r#"{{"op":"run","token":"{token}","argv":["cmd","/c","echo","%DB_PASSWORD%"],
                    "env":[{{"id":"item-1","field":"field-2","as":"DB_PASSWORD"}}]}}"#
            )),
            PIPE,
        );
        assert_eq!(response["ok"], json!(true));
        assert_eq!(response["exitCode"], json!(0));
        assert_eq!(response["stdout"], json!("ok\n"));
        assert!(response.get("stderr").is_none(), "empty stderr is omitted");
        let ran = backend.ran.lock().unwrap();
        assert_eq!(ran[0].0, vec!["cmd", "/c", "echo", "%DB_PASSWORD%"]);
        assert_eq!(ran[0].1[0].name, "DB_PASSWORD");
    }

    #[test]
    fn unknown_op_is_an_error_even_with_a_valid_token() {
        let auth = Auth::new();
        let token = auth.pair();
        let backend = FakeBackend::unlocked();
        let response = respond(
            &auth,
            &backend,
            &request(&format!(r#"{{"op":"items.delete","token":"{token}"}}"#)),
            PIPE,
        );
        assert_eq!(response["ok"], json!(false));
        assert_eq!(response["error"], json!(ERR_UNKNOWN_OP));
    }

    #[test]
    fn a_bad_or_missing_token_is_unauthorized() {
        let auth = Auth::new();
        auth.pair();
        let backend = FakeBackend::unlocked();
        for line in [
            r#"{"op":"items.list"}"#.to_string(),
            r#"{"op":"items.list","token":"0000"}"#.to_string(),
        ] {
            let response = respond(&auth, &backend, &request(&line), PIPE);
            assert_eq!(response["ok"], json!(false), "{line}");
            assert_eq!(response["error"], json!(ERR_UNAUTHORIZED), "{line}");
        }
    }

    #[test]
    fn re_pairing_replaces_the_previous_token() {
        let auth = Auth::new();
        let first = auth.pair();
        let second = auth.pair();
        assert_ne!(first, second);
        assert!(auth.scope(Some(&first)).is_none(), "the old token is dead");
        assert!(auth.scope(Some(&second)).is_some());
        auth.revoke();
        assert!(!auth.paired());
        assert!(
            auth.scope(Some(&second)).is_none(),
            "revoked tokens stay dead"
        );
    }

    #[test]
    fn a_locked_vault_answers_locked_for_every_op_but_status() {
        let auth = Auth::new();
        let token = auth.pair();
        let backend = FakeBackend::unlocked();
        // Locking revokes the token, exactly as the app's watcher does.
        backend.lock();
        auth.revoke();
        let lines = [
            format!(r#"{{"op":"items.list","token":"{token}"}}"#),
            format!(r#"{{"op":"items.copy","token":"{token}","id":"item-1","field":"field-2"}}"#),
            format!(r#"{{"op":"run","token":"{token}","argv":["cmd"]}}"#),
            r#"{"op":"items.list"}"#.to_string(),
        ];
        for line in lines {
            let response = respond(&auth, &backend, &request(&line), PIPE);
            assert_eq!(response["ok"], json!(false), "{line}");
            assert_eq!(response["error"], json!(ERR_LOCKED), "{line}");
        }
        let response = respond(&auth, &backend, &request(r#"{"op":"status"}"#), PIPE);
        assert_eq!(response["ok"], json!(true));
        assert_eq!(response["unlocked"], json!(false));
        assert_eq!(response["paired"], json!(false));
    }

    #[test]
    fn env_names_are_strictly_validated() {
        for name in ["A", "_", "_X", "DB_PASSWORD", "PATH_2"] {
            assert!(valid_env_name(name), "{name} must be accepted");
        }
        for name in ["", "a", "1A", "A-B", "A B", "ПАРОЛЬ", "A=B"] {
            assert!(!valid_env_name(name), "{name:?} must be rejected");
        }

        let auth = Auth::new();
        let token = auth.pair();
        let backend = FakeBackend::unlocked();
        let response = respond(
            &auth,
            &backend,
            &request(&format!(
                r#"{{"op":"run","token":"{token}","argv":["cmd"],
                    "env":[{{"id":"item-1","field":"field-2","as":"lower"}}]}}"#
            )),
            PIPE,
        );
        assert_eq!(response["ok"], json!(false));
        assert_eq!(response["error"], json!(ERR_INVALID_ENV_NAME));
        assert!(
            backend.ran.lock().unwrap().is_empty(),
            "nothing was spawned"
        );
    }

    #[test]
    fn malformed_requests_are_bad_requests() {
        for line in ["", "{", r#"{"token":"x"}"#, "[]"] {
            match parse_request(line.as_bytes()) {
                Ok(request) => panic!("{line:?} must not parse, got {request:?}"),
                Err(error) => assert_eq!(error.code(), ERR_BAD_REQUEST, "{line:?}"),
            }
        }
    }

    #[test]
    fn oversized_requests_are_refused_before_parsing() {
        let line = vec![b'a'; MAX_REQUEST_LEN + 1];
        let error = parse_request(&line).expect_err("too large");
        assert_eq!(error.code(), ERR_BAD_REQUEST);
    }

    /* ------------------------------------------------------------- mcp scope */

    fn grant(item: &str, field: &str) -> Grant {
        Grant {
            item: item.to_string(),
            field: field.to_string(),
        }
    }

    #[test]
    fn secrets_list_has_ids_titles_and_field_names_but_no_value() {
        let auth = Auth::new();
        let token = auth.pair_mcp("editor", vec![grant("item-1", "field-2")]);
        let backend = FakeBackend::unlocked();
        let response = respond(
            &auth,
            &backend,
            &request(&format!(r#"{{"op":"secrets.list","token":"{token}"}}"#)),
            PIPE,
        );
        assert_eq!(response["ok"], json!(true));
        let item = &response["items"][0];
        assert_eq!(item["id"], json!("item-1"));
        assert_eq!(item["title"], json!("Bank"));
        let field = &item["fields"][1];
        assert_eq!(field["id"], json!("field-2"));
        assert_eq!(field["label"], json!("password"));
        assert_eq!(field["kind"], json!("password"));
        // The whole response is metadata: no value key anywhere.
        let serialised = response.to_string();
        assert!(
            !serialised.contains(SECRET),
            "list leaked a value: {serialised}"
        );
        assert!(!serialised.contains("\"value\""), "list has a value key");
        assert!(
            backend.revealed.lock().unwrap().is_empty(),
            "listing must never resolve a field"
        );
    }

    #[test]
    fn an_mcp_token_reveals_a_granted_field_once_and_it_is_recorded() {
        let auth = Auth::new();
        let token = auth.pair_mcp("editor", vec![grant("item-1", "field-2")]);
        let backend = FakeBackend::unlocked();
        let response = respond(
            &auth,
            &backend,
            &request(&format!(
                r#"{{"op":"items.reveal","token":"{token}","id":"item-1","field":"field-2"}}"#
            )),
            PIPE,
        );
        assert_eq!(response, json!({ "ok": true, "value": SECRET }));
        assert_eq!(
            *backend.revealed.lock().unwrap(),
            vec![(
                "editor".to_string(),
                "item-1".to_string(),
                "field-2".to_string()
            )],
            "the read is recorded against the client the token was minted for"
        );
    }

    #[test]
    fn a_field_outside_the_token_never_reaches_the_backend() {
        let auth = Auth::new();
        let token = auth.pair_mcp("editor", vec![grant("item-1", "field-1")]);
        let backend = FakeBackend::unlocked();
        // The token allows field-1; field-2 was never approved.
        let response = respond(
            &auth,
            &backend,
            &request(&format!(
                r#"{{"op":"items.reveal","token":"{token}","id":"item-1","field":"field-2"}}"#
            )),
            PIPE,
        );
        assert_eq!(response["ok"], json!(false));
        assert_eq!(response["error"], json!(ERR_NOT_GRANTED));
        assert!(backend.revealed.lock().unwrap().is_empty());
    }

    #[test]
    fn a_revoked_grant_row_is_refused_even_with_a_matching_token() {
        let auth = Auth::new();
        let token = auth.pair_mcp("editor", vec![grant("item-1", "field-2")]);
        let backend = FakeBackend::unlocked();
        // Someone removed the persisted row: the token alone is not enough.
        backend
            .granted
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let response = respond(
            &auth,
            &backend,
            &request(&format!(
                r#"{{"op":"items.reveal","token":"{token}","id":"item-1","field":"field-2"}}"#
            )),
            PIPE,
        );
        assert_eq!(response["ok"], json!(false));
        assert_eq!(response["error"], json!(ERR_NOT_GRANTED));
        assert!(
            backend.revealed.lock().unwrap().is_empty(),
            "nothing to audit"
        );
    }

    #[test]
    fn a_cli_token_cannot_reveal_or_list_secrets() {
        let auth = Auth::new();
        let token = auth.pair();
        let backend = FakeBackend::unlocked();
        for line in [
            format!(r#"{{"op":"items.reveal","token":"{token}","id":"item-1","field":"field-2"}}"#),
            format!(r#"{{"op":"secrets.list","token":"{token}"}}"#),
        ] {
            let response = respond(&auth, &backend, &request(&line), PIPE);
            assert_eq!(response["ok"], json!(false), "{line}");
            // A valid token whose scope does not cover the op: forbidden, not
            // "not paired" — the client's pairing is fine, its permission is not.
            assert_eq!(response["error"], json!(ERR_FORBIDDEN), "{line}");
            assert!(response.get("value").is_none(), "{line}");
        }
        assert!(backend.revealed.lock().unwrap().is_empty());
    }

    #[test]
    fn an_mcp_token_cannot_copy_run_or_list_items() {
        let auth = Auth::new();
        let token = auth.pair_mcp("editor", vec![grant("item-1", "field-2")]);
        let backend = FakeBackend::unlocked();
        let lines = [
            format!(r#"{{"op":"items.list","token":"{token}"}}"#),
            format!(r#"{{"op":"items.copy","token":"{token}","id":"item-1","field":"field-2"}}"#),
            format!(r#"{{"op":"run","token":"{token}","argv":["cmd"]}}"#),
        ];
        for line in lines {
            let response = respond(&auth, &backend, &request(&line), PIPE);
            assert_eq!(response["error"], json!(ERR_FORBIDDEN), "{line}");
        }
        assert!(backend.copied.lock().unwrap().is_empty());
        assert!(backend.ran.lock().unwrap().is_empty());
    }

    #[test]
    fn mcp_pairings_are_per_client_and_the_cli_slot_survives() {
        let auth = Auth::new();
        let cli = auth.pair();
        let editor = auth.pair_mcp("editor", vec![grant("item-1", "field-1")]);
        let assistant = auth.pair_mcp("assistant", vec![grant("item-1", "field-2")]);

        // Three tokens, three scopes: pairing one did not revoke the others.
        assert!(matches!(auth.scope(Some(&cli)), Some(Scope::Cli)));
        assert!(matches!(
            auth.scope(Some(&editor)),
            Some(Scope::Mcp { ref client, .. }) if client == "editor"
        ));
        assert!(matches!(
            auth.scope(Some(&assistant)),
            Some(Scope::Mcp { ref client, .. }) if client == "assistant"
        ));

        // Re-pairing one client replaces only that client's token.
        let editor_again = auth.pair_mcp("editor", vec![grant("item-1", "field-2")]);
        assert!(
            auth.scope(Some(&editor)).is_none(),
            "the old editor token is dead"
        );
        assert!(auth.scope(Some(&editor_again)).is_some());
        assert!(auth.scope(Some(&cli)).is_some());
        assert!(auth.scope(Some(&assistant)).is_some());

        assert_eq!(
            auth.mcp_clients(),
            vec![("assistant".to_string(), 1), ("editor".to_string(), 1),]
        );
        assert!(auth.revoke_mcp("editor"));
        assert!(!auth.revoke_mcp("editor"), "idempotent");
        assert!(auth.scope(Some(&editor_again)).is_none());
        assert!(
            auth.scope(Some(&assistant)).is_some(),
            "other clients are untouched"
        );

        auth.revoke();
        assert!(auth.scope(Some(&assistant)).is_none());
        assert!(auth.scope(Some(&cli)).is_none());
        assert!(auth.mcp_clients().is_empty());
    }

    #[test]
    fn a_scoped_cli_token_copies_and_lists_only_under_its_allowlist() {
        let auth = Auth::new();
        let token = auth.pair_cli("terminal", vec![grant("item-1", "field-1")]);
        let backend = FakeBackend::unlocked();

        // The principal reaches the backend: that is what lets it filter the
        // list and re-check the persisted grant.
        let response = respond(
            &auth,
            &backend,
            &request(&format!(r#"{{"op":"items.list","token":"{token}"}}"#)),
            PIPE,
        );
        assert_eq!(response["ok"], json!(true));
        assert_eq!(
            *backend.listed.lock().unwrap(),
            vec!["terminal".to_string()]
        );

        // A field outside the token's list never reaches the backend.
        let response = respond(
            &auth,
            &backend,
            &request(&format!(
                r#"{{"op":"items.copy","token":"{token}","id":"item-1","field":"field-2"}}"#
            )),
            PIPE,
        );
        assert_eq!(response["error"], json!(ERR_NOT_GRANTED));
        assert!(backend.copied.lock().unwrap().is_empty());

        // The granted field does.
        let response = respond(
            &auth,
            &backend,
            &request(&format!(
                r#"{{"op":"items.copy","token":"{token}","id":"item-1","field":"field-1"}}"#
            )),
            PIPE,
        );
        assert_eq!(response, json!({ "ok": true }));
        assert_eq!(
            *backend.copied.lock().unwrap(),
            vec![("item-1".to_string(), "field-1".to_string())]
        );
    }

    #[test]
    fn a_run_binding_outside_the_allowlist_starts_nothing() {
        let auth = Auth::new();
        let token = auth.pair_cli("terminal", vec![grant("item-1", "field-1")]);
        let backend = FakeBackend::unlocked();
        let response = respond(
            &auth,
            &backend,
            &request(&format!(
                r#"{{"op":"run","token":"{token}","argv":["cmd"],
                    "env":[{{"id":"item-1","field":"field-2","as":"DB_PASSWORD"}}]}}"#
            )),
            PIPE,
        );
        assert_eq!(response["error"], json!(ERR_NOT_GRANTED));
        assert!(
            backend.ran.lock().unwrap().is_empty(),
            "a refused binding must not spawn a child"
        );

        // The same run with the granted field is allowed.
        let response = respond(
            &auth,
            &backend,
            &request(&format!(
                r#"{{"op":"run","token":"{token}","argv":["cmd"],
                    "env":[{{"id":"item-1","field":"field-1","as":"DB_PASSWORD"}}]}}"#
            )),
            PIPE,
        );
        assert_eq!(response["ok"], json!(true));
        assert_eq!(backend.ran.lock().unwrap().len(), 1);
    }

    #[test]
    fn the_cli_slot_is_single_whether_scoped_or_not() {
        let auth = Auth::new();
        let legacy = auth.pair();
        let scoped = auth.pair_cli("terminal", vec![grant("item-1", "field-1")]);
        // Re-pairing replaces the one CLI slot, of either shape.
        assert!(auth.scope(Some(&legacy)).is_none());
        assert!(matches!(
            auth.scope(Some(&scoped)),
            Some(Scope::CliScoped { ref client, .. }) if client == "terminal"
        ));
        let legacy_again = auth.pair();
        assert!(auth.scope(Some(&scoped)).is_none());
        assert!(matches!(auth.scope(Some(&legacy_again)), Some(Scope::Cli)));
        assert!(auth.cli_paired());
    }

    #[test]
    fn the_scope_is_not_part_of_the_token_string() {
        // A token is random hex and nothing else: no client name, no grant list.
        // Anything reconstructable would be a token that leaks its own consent.
        let auth = Auth::new();
        let token = auth.pair_mcp("editor", vec![grant("item-1", "field-2")]);
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!token.contains("editor"));
    }
}
