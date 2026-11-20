//! Sync surface: the status line, the server setting, a manual run, and the
//! conflict queue.
//!
//! The engine lives in `kestrel-engine` and needs three things this crate is the
//! only place to assemble: the unlocked store with its master key, the account
//! key unwrapped for the length of one call, and this device's signing seed.
//! None of them crosses the bridge. `sync_status` answers while the vault is
//! locked, because everything it shows is either public shape or a value the
//! store keeps unsealed (the server URL, the cursor, the last sync time).
//!
//! A run is synchronous and takes as long as the network does: the command
//! blocks the calling thread, which is the Tauri async pool, not the UI thread.

use kestrel_core::session::{VaultError, VaultState};
use kestrel_core::store::Store;
use kestrel_engine::{ConflictView, ResolveChoice, SyncContext, SyncReport};
use kestrel_net::{check_base_url, ClientConfig, SyncClient};
use serde::Serialize;
use tauri::State;

/// Metadata keys the store keeps for the engine and the status line.
///
/// The service origin is crate-visible: `commands_account` reads the same row
/// when it revokes a device, so the key is one constant rather than a second
/// string literal.
pub(crate) const KEY_SERVER: &str = "server";
const KEY_LAST_SYNC: &str = "last_sync_at";
const KEY_STATE: &str = "state";
const KEY_ERROR: &str = "error";
/// Seconds between automatic runs; read by the scheduler on every wake.
pub(crate) const KEY_AUTO_INTERVAL: &str = "auto_interval";

/// What the titlebar pill and the settings card render. Every field is either
/// public shape or an unsealed bookkeeping value; nothing here is vault content.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    pub configured: bool,
    pub server: Option<String>,
    pub account_id: Option<String>,
    pub device_id: Option<String>,
    pub last_sync_at: Option<i64>,
    /// `idle`, `syncing`, `offline`, `conflict` or `error`.
    pub state: String,
    pub error: Option<String>,
    pub pending_push: u32,
    pub conflicts: u32,
    /// Seconds between automatic runs; 0 means automatic sync is off.
    pub interval_secs: u64,
    /// `interval_secs > 0` and the vault can actually sync.
    pub auto: bool,
}

fn err<E: std::fmt::Display>(error: E) -> String {
    error.to_string()
}

/// An engine failure inside a session closure: the closure's error type is
/// [`VaultError`], so the engine's message is carried as an invalid-operation
/// detail rather than flattened to a string at the boundary.
fn engine_error(failure: kestrel_engine::EngineError) -> VaultError {
    VaultError::Invalid(failure.to_string())
}

/// The same for a raw wire failure, which the enrolment commands call directly.
fn wire_error(failure: kestrel_net::Error) -> VaultError {
    VaultError::Invalid(failure.to_string())
}

/// Assemble the status from the store alone. Safe while locked: no key is used.
fn status(state: &VaultState) -> Result<SyncStatus, String> {
    let server = state.sync_meta(KEY_SERVER).map_err(err)?;
    let account_id = state.account_status().map_err(err)?.account_id;
    let last_sync_at = state
        .sync_meta(KEY_LAST_SYNC)
        .map_err(err)?
        .and_then(|value| value.parse::<i64>().ok());
    let stored_state = state.sync_meta(KEY_STATE).map_err(err)?;
    let stored_error = state.sync_meta(KEY_ERROR).map_err(err)?;
    let (pending_push, conflicts) = {
        let store = state.store().map_err(err)?;
        store.sync_counts_all().map_err(err)?
    };
    let device_id = state.store().map_err(err)?.local_device_id().map_err(err)?;
    // A run in flight is never overridden by the conflict count; otherwise a
    // stored conflict always wins, because a pending decision is the one thing
    // the user has to act on.
    let state_name = match stored_state.as_deref() {
        Some("syncing") => "syncing",
        Some("error") if stored_error.is_some() => "error",
        _ if conflicts > 0 => "conflict",
        Some(name) => name,
        None => "idle",
    };
    let interval_secs = state
        .sync_meta(KEY_AUTO_INTERVAL)
        .map_err(err)?
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    Ok(SyncStatus {
        interval_secs,
        auto: interval_secs > 0 && server.is_some() && account_id.is_some(),
        configured: server.is_some() && account_id.is_some(),
        server,
        account_id,
        device_id,
        last_sync_at,
        state: state_name.to_string(),
        error: stored_error,
        pending_push,
        conflicts,
    })
}

/// Status of the sync loop. Answers while locked.
#[tauri::command]
pub fn sync_status(state: State<'_, VaultState>) -> Result<SyncStatus, String> {
    status(&state)
}

/// Save the service origin. The URL is validated the way the client will
/// validate it, so a bad one is refused here rather than at the first sync.
#[tauri::command]
pub fn sync_configure(state: State<'_, VaultState>, server: String) -> Result<SyncStatus, String> {
    let origin = check_base_url(&server, false).map_err(err)?;
    let previous = state.sync_meta(KEY_SERVER).map_err(err)?;
    state
        .set_sync_meta(KEY_SERVER, Some(&origin))
        .map_err(err)?;
    state.set_sync_meta(KEY_ERROR, None).map_err(err)?;
    // A cursor is a position in one server's change log. Pointing at another
    // server while keeping it would skip everything that log holds before that
    // revision, so a changed origin starts from zero.
    if previous.as_deref() != Some(origin.as_str()) {
        state.set_sync_meta("cursor", None).map_err(err)?;
        state.set_sync_meta(KEY_LAST_SYNC, None).map_err(err)?;
        state.set_sync_meta(KEY_STATE, None).map_err(err)?;
        // Another server has never seen this vault: queue every item and drop
        // the baselines the old service acknowledged. Without this the new
        // server receives nothing and the status still says "Synced".
        state
            .with_unlocked(|store, _master, _meta| Ok(store.sync_requeue_all()?))
            .map_err(err)?;
    }
    status(&state)
}

/// Forget the server and every sync cursor. The vault keeps its items; the next
/// run starts from an empty log, which is what a re-pointed account needs.
#[tauri::command]
pub fn sync_forget(state: State<'_, VaultState>) -> Result<SyncStatus, String> {
    state
        .with_unlocked(|store, _master, _meta| Ok(store.sync_forget_server()?))
        .map_err(err)?;
    status(&state)
}

/// The stored origin, or the error the card shows before anything is set up.
///
/// Read before [`VaultState::with_unlocked`] takes the store lock: the closure
/// already holds that mutex, so re-entering the store from inside it would
/// deadlock.
fn configured_server(state: &VaultState) -> Result<String, String> {
    state
        .sync_meta(KEY_SERVER)
        .map_err(err)?
        .ok_or_else(|| "no sync server is configured".to_string())
}

/// Build a client from the stored settings and this device's identity.
///
/// Returns the client, the account id and the device id: the engine needs all
/// three and none of them comes from the renderer.
fn client(
    server: &str,
    store: &Store,
    master: &kestrel_core::crypto::SymKey,
) -> Result<(SyncClient, String, String), VaultError> {
    let account_id = store
        .account_status()?
        .account_id
        .ok_or_else(|| VaultError::Invalid("this vault has no account".to_string()))?;
    let keys = store.device_secret_keys(master)?;
    let device_id = keys.device_id().to_string();
    let config = ClientConfig {
        base_url: server.to_string(),
        account_id: account_id.clone(),
        device_id: device_id.clone(),
        signing_key: *keys.signing_secret(),
        allow_insecure: false,
    };
    let client =
        SyncClient::new(config).map_err(|failure| VaultError::Invalid(failure.to_string()))?;
    Ok((client, account_id, device_id))
}

/// One sync round, without the Tauri wrapper. The background scheduler calls
/// this; `sync_now` is the same work behind a command.
///
/// A locked vault is an error with the word "locked" in it, which is how the
/// scheduler tells "nothing to do" from "the service failed".
pub fn run_sync(state: &VaultState) -> Result<(), String> {
    let server = configured_server(state)?;
    let outcome: Result<SyncReport, VaultError> = state.with_unlocked(|store, master, meta| {
        let (client, account_id, device_id) = client(&server, store, master)?;
        let account_key = store.account_key(master)?;
        let ctx = SyncContext {
            store,
            master,
            meta,
            account_id: &account_id,
            account_key: &account_key,
            device_id: &device_id,
            client: &client,
        };
        Ok(kestrel_engine::sync_once(&ctx).map_err(engine_error)?)
    });
    match outcome {
        Ok(_report) => {
            // The engine records the cursor, the timestamp and the status; the
            // command only clears the error it would otherwise keep showing.
            state.set_sync_meta(KEY_ERROR, None).map_err(err)?;
            Ok(())
        }
        // A locked vault is not a failure and has nothing to report: the
        // scheduler runs on a timer and would otherwise paint "the last exchange
        // failed" on the lock screen every interval.
        Err(VaultError::Locked) => Ok(()),
        Err(failure) => {
            let text = failure.to_string();
            state.set_sync_meta(KEY_ERROR, Some(&text)).map_err(err)?;
            // The engine writes `offline` for a transport failure and `error`
            // for anything else; overwriting both with `error` would make the
            // Offline state unreachable through the UI.
            let state_name = state
                .sync_meta(KEY_STATE)
                .map_err(err)?
                .filter(|value| value == "offline")
                .unwrap_or_else(|| "error".to_string());
            state
                .set_sync_meta(KEY_STATE, Some(&state_name))
                .map_err(err)?;
            Err(text)
        }
    }
}

/// Run one sync round now: pull, merge, push. Returns the status afterwards.
#[tauri::command]
pub fn sync_now(state: State<'_, VaultState>) -> Result<SyncStatus, String> {
    run_sync(&state)?;
    status(&state)
}

/// Turn automatic sync on or off. `interval_secs = 0` disables it.
#[tauri::command]
pub fn sync_set_auto(
    state: State<'_, VaultState>,
    interval_secs: u64,
) -> Result<SyncStatus, String> {
    // Anything below a minute would hammer a service for no reason; anything
    // above a day is indistinguishable from off.
    let interval_secs = if interval_secs == 0 {
        0
    } else {
        interval_secs.clamp(60, 86_400)
    };
    state
        .set_sync_meta(KEY_AUTO_INTERVAL, Some(&interval_secs.to_string()))
        .map_err(err)?;
    // A fresh interval should take effect now, not after the old sleep.
    crate::sync_scheduler::request_sync();
    status(&state)
}

/// The items that need a decision, with the conflicting fields rendered.
#[tauri::command]
pub fn sync_conflicts(state: State<'_, VaultState>) -> Result<Vec<ConflictView>, String> {
    let server = configured_server(&state)?;
    state
        .with_unlocked(|store, master, meta| {
            let (client, account_id, device_id) = client(&server, store, master)?;
            let account_key = store.account_key(master)?;
            let ctx = SyncContext {
                store,
                master,
                meta,
                account_id: &account_id,
                account_key: &account_key,
                device_id: &device_id,
                client: &client,
            };
            Ok(kestrel_engine::conflict_views(&ctx).map_err(engine_error)?)
        })
        .map_err(err)
}

/// Resolve one conflict: keep this device's side, the other side, or both.
#[tauri::command]
pub fn sync_resolve(
    state: State<'_, VaultState>,
    item_id: String,
    choice: String,
) -> Result<SyncStatus, String> {
    let choice = match choice.as_str() {
        "mine" => ResolveChoice::Mine,
        "theirs" => ResolveChoice::Theirs,
        "both" => ResolveChoice::Both,
        other => return Err(format!("unknown choice {other:?}")),
    };
    let server = configured_server(&state)?;
    state
        .with_unlocked(|store, master, meta| {
            let (client, account_id, device_id) = client(&server, store, master)?;
            let account_key = store.account_key(master)?;
            let ctx = SyncContext {
                store,
                master,
                meta,
                account_id: &account_id,
                account_key: &account_key,
                device_id: &device_id,
                client: &client,
            };
            Ok(kestrel_engine::resolve_conflict(&ctx, &item_id, choice).map_err(engine_error)?)
        })
        .map_err(err)?;
    status(&state)
}

/* --------------------------------------------------- server-side enrolment */

/// Register this device with the service as the account's first device.
///
/// Idempotent: `409 account_exists` means the account is already registered,
/// which is the state this command wants, so it is success. Any other refusal
/// is reported. A device that joined an account uses [`sync_enroll_accept`]
/// instead — it cannot create an account it does not own.
#[tauri::command]
pub fn sync_register(state: State<'_, VaultState>) -> Result<SyncStatus, String> {
    let server = configured_server(&state)?;
    state
        .with_unlocked(|store, master, _meta| {
            let (client, _account_id, _device_id) = client(&server, store, master)?;
            let identity = store.device_identity(master)?;
            let agreement = hex_to_32(&identity.agreement_pub)?;
            let name = device_name();
            match client.create_account(agreement, &name) {
                Ok(_) => Ok(()),
                // The account exists but this device was never registered under
                // it: creating the account again cannot help, and pretending it
                // did would leave a vault that can never authenticate. Say what
                // actually has to happen.
                Err(kestrel_net::Error::Conflict {
                    code: kestrel_net::ConflictCode::AccountExists,
                    ..
                }) => {
                    // The account row exists. That is either a retry of this
                    // device's own registration (the response was lost) or a
                    // device that still has to be enrolled. Only the service can
                    // tell the two apart, so ask it with an authenticated call.
                    match client.state() {
                        Ok(_) => Ok(()),
                        Err(kestrel_net::Error::Unauthorized { .. }) => Err(VaultError::Invalid(
                            "this account is already on the service but this device is not;                              join it with the code from the device that has it"
                                .to_string(),
                        )),
                        Err(failure) => Err(wire_error(failure)),
                    }
                }
                Err(failure) => Err(wire_error(failure)),
            }
        })
        .map_err(err)?;
    status(&state)
}

/// The three values a hosting device reads out to a joining one.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteResult {
    pub code: String,
    pub sealed: String,
    pub sender_agreement_pub: String,
}

/// Mint an invitation for one device and upload the offer.
///
/// This is the hosting half of the join flow: the joining device shows its id
/// and its agreement key, this device seals the account key to that key and
/// uploads the envelope, and the person reads the three returned values back.
/// The code never reaches the service in the clear — it is uploaded as a digest
/// — and the account key leaves sealed to a keypair the service cannot open.
#[tauri::command]
pub fn sync_invite(
    state: State<'_, VaultState>,
    guest_device_id: String,
    guest_agreement_pub: String,
) -> Result<InviteResult, String> {
    let server = configured_server(&state)?;
    state
        .with_unlocked(|store, master, _meta| {
            let (client, _account_id, _device_id) = client(&server, store, master)?;
            let code = store.account_enrol_code();
            let sealed = store.account_seal_for_device(master, &code.code, &guest_agreement_pub)?;
            let bytes = decode_hex(&sealed.sealed)?;
            // The service refuses an expiry more than an hour ahead of its own
            // clock; stay a minute inside the cap.
            client
                .enroll_offer(&guest_device_id, &code.code, &bytes, now_seconds() + 3540)
                .map_err(wire_error)?;
            // `EnrolCode` and `SealedEnrolment` zeroize on drop, so the strings
            // are cloned out rather than moved.
            Ok(InviteResult {
                code: code.code.clone(),
                sealed: sealed.sealed.clone(),
                sender_agreement_pub: sealed.sender_agreement_pub.clone(),
            })
        })
        .map_err(err)
}

/// Offer this account's key to a device that asked for it, over the service.
///
/// `code` and `sealed` come from `account_enrol_code` and
/// `account_seal_for_device`; this command is only the upload, because the
/// service never sees the code itself (it gets a digest) and never sees the
/// account key. The offer expires within the hour, so a code read aloud on the
/// phone has a deadline.
#[tauri::command]
pub fn sync_enroll_offer(
    state: State<'_, VaultState>,
    guest_device_id: String,
    code: String,
    sealed: String,
) -> Result<(), String> {
    let server = configured_server(&state)?;
    let sealed_bytes = decode_hex(&sealed).map_err(err)?;
    state
        .with_unlocked(|store, master, _meta| {
            let (client, _account_id, _device_id) = client(&server, store, master)?;
            // The service refuses an expiry more than an hour ahead of *its*
            // clock, and a client a second ahead would otherwise fail every
            // offer. Stay a minute inside the cap.
            let expires_at = now_seconds() + 3540;
            client
                .enroll_offer(&guest_device_id, &code, &sealed_bytes, expires_at)
                .map_err(wire_error)
        })
        .map_err(err)
}

/// Confirm a claim, which is what lets the new device authenticate.
///
/// The offering device must call this after the guest redeemed the code; until
/// then the guest's requests are `unknown_device` by design, because a device
/// row the offering device has not confirmed is not trusted.
#[tauri::command]
pub fn sync_enroll_ack(
    state: State<'_, VaultState>,
    guest_device_id: String,
) -> Result<(), String> {
    let server = configured_server(&state)?;
    state
        .with_unlocked(|store, master, _meta| {
            let (client, _account_id, _device_id) = client(&server, store, master)?;
            client.enroll_ack(&guest_device_id).map_err(wire_error)
        })
        .map_err(err)
}

/// Receive an account on this device: redeem the code locally and with the
/// service, so this device both knows the account key and is known to it.
#[tauri::command]
pub fn sync_enroll_accept(
    state: State<'_, VaultState>,
    code: String,
    sealed: String,
    sender_agreement_pub: String,
) -> Result<SyncStatus, String> {
    let server = configured_server(&state)?;
    state
        .with_unlocked(|store, master, _meta| {
            let identity = store.device_identity(master)?;
            let agreement = hex_to_32(&identity.agreement_pub)?;
            let name = device_name();
            // Local first: the account key must be in the vault before this
            // device can act as a member, and the client is built from the
            // account id this call writes.
            //
            // A retry after a failed upload finds the account already here: the
            // claim is irreversible by design, so the second attempt goes
            // straight to the service instead of failing on a vault that is
            // already claimed.
            if !store.account_status()?.exists {
                store
                    .account_enroll_claim(master, &code, &sealed, &sender_agreement_pub)
                    .map_err(|failure| VaultError::Invalid(failure.to_string()))?;
            }
            let (client, _account_id, _device_id) = client(&server, store, master)?;
            let claimed = client
                .enroll_claim(&code, agreement, &name)
                .map_err(wire_error)?;
            // The service and the vault must agree on which account this device
            // just joined; a disagreement is a broken claim, not a warning.
            let local = store.account_status()?.account_id.unwrap_or_default();
            if claimed.account_id != local {
                return Err(VaultError::Invalid(
                    "the service returned a different account id than the envelope".to_string(),
                ));
            }
            Ok(())
        })
        .map_err(err)?;
    status(&state)
}

/// 32 bytes from a hex string, with the length checked: a short agreement key
/// would otherwise be padded or truncated silently.
fn hex_to_32(hex_text: &str) -> Result<[u8; 32], VaultError> {
    let bytes = decode_hex(hex_text)?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| VaultError::Invalid("a device public key must be 32 bytes".to_string()))
}

fn decode_hex(hex_text: &str) -> Result<Vec<u8>, VaultError> {
    if hex_text.len() % 2 != 0 {
        return Err(VaultError::Invalid(
            "hex text has an odd length".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(hex_text.len() / 2);
    let bytes = hex_text.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| VaultError::Invalid("hex text is not hex".to_string()))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| VaultError::Invalid("hex text is not hex".to_string()))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

/// The name this device registers under. It is what the other side's device
/// list shows, so it names the machine rather than the vault.
fn device_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "Kestrel".to_string())
}

/// Unix seconds without pulling in a date crate for one subtraction.
fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}
