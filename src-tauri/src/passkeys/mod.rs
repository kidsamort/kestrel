//! Passkey provider: item block, plugin registration and the CTAP2 service.
//!
//! The split is deliberate:
//!
//! * `registry` (in `kestrel-passkey`) writes the HKCU CLSID and calls
//!   `WebAuthnPlugin.dll`; it is reachable only from the two explicit commands
//!   below and never runs at install time;
//! * `pipe` owns `\\.\pipe\kestrel-passkeys` for the lifetime of a registration;
//! * `service` parses CTAP2, asks [`VaultState`] for the credential and signs —
//!   the vault's master key never leaves the core;
//! * this file is the Tauri surface and the honest status the Settings card
//!   renders.
//!
//! The renderer only ever receives credential metadata (public id, RP id,
//! timestamps) and the registration state. No command returns a private key and
//! no path logs one.

mod approval;
mod pipe;
mod service;

use kestrel_core::session::{PasskeyInfo, VaultState};
use kestrel_passkey::registry as reg;
use serde::Serialize;
use std::sync::{LazyLock, Mutex};
use tauri::{AppHandle, State};

/// The one server instance for this process. `None` until
/// `passkeys_register_plugin` starts it; unregistration takes it back out.
static SERVICE: LazyLock<Mutex<Option<pipe::Server>>> =
    LazyLock::new(|| Mutex::new(None));

fn service() -> &'static Mutex<Option<pipe::Server>> {
    &SERVICE
}

/// Registration state as the Settings card shows it. Every field is either a
/// path, a boolean or a Win32 status code: nothing here can be a secret.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyStatus {
    /// The CLSID key exists and names an `InprocServer32` DLL.
    pub registered: bool,
    /// The path read back from the registry, if any.
    pub registered_path: Option<String>,
    pub clsid: String,
    /// Where this build expects `kestrel_passkey.dll` (next to `kestrel.exe`).
    pub dll_path: String,
    pub dll_present: bool,
    /// `\\.\pipe\kestrel-passkeys`, the plugin's route to the vault.
    pub pipe: String,
    /// The pipe server is running in this process.
    pub pipe_running: bool,
    /// Windows' view: `Some(0)` disabled, `Some(1)` enabled, `None` when the
    /// API could not be queried.
    pub windows_state: Option<u32>,
    /// The HRESULT from the last add/remove call, if this command made one.
    pub windows_hresult: Option<i32>,
    /// Why the Windows plugin API is unavailable, when it is.
    pub windows_error: Option<String>,
    /// A registration or pipe error that makes the current state incomplete.
    pub error: Option<String>,
}

fn status_with(
    windows: Option<reg::WindowsRegistration>,
    error: Option<String>,
) -> PasskeyStatus {
    let dll = reg::plugin_dll_path();
    let dll_path = dll
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let dll_present = dll.as_ref().map(|path| path.is_file()).unwrap_or(false);
    let registered_path = match reg::registered_dll() {
        Ok(value) => value,
        Err(cause) => {
            return PasskeyStatus {
                registered: false,
                registered_path: None,
                clsid: kestrel_passkey::PLUGIN_CLSID_TEXT.to_string(),
                dll_path,
                dll_present,
                pipe: kestrel_passkey::PIPE_PATH.to_string(),
                pipe_running: service()
                    .lock()
                    .map(|slot| slot.is_some())
                    .unwrap_or(false),
                windows_state: None,
                windows_hresult: None,
                windows_error: None,
                error: Some(cause.to_string()),
            };
        }
    };
    let windows = windows.unwrap_or_else(reg::windows_state);
    PasskeyStatus {
        registered: registered_path.is_some(),
        registered_path,
        clsid: kestrel_passkey::PLUGIN_CLSID_TEXT.to_string(),
        dll_path,
        dll_present,
        pipe: kestrel_passkey::PIPE_PATH.to_string(),
        pipe_running: service()
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false),
        windows_state: windows.state,
        windows_hresult: windows.hresult,
        windows_error: windows.error,
        error,
    }
}

/// Bring the local server up at startup. Windows can call the registered DLL
/// before anyone opens Settings, and a DLL with no pipe to talk to fails the
/// ceremony. Writes nothing; a second call is a no-op.
pub fn start_server(app: &AppHandle) {
    let _ = ensure_pipe(app);
}

/// Start the pipe if this build is registered. Called from the explicit
/// register command and from the status read, so an app restart does not leave
/// Windows routing ceremonies to a registered DLL whose local server is down.
/// It never writes the registry; only `passkeys_register_plugin` does that.
fn ensure_pipe(app: &AppHandle) -> Option<String> {
    let mut slot = service().lock().expect("passkey service mutex");
    if slot.is_some() {
        return None;
    }
    match pipe::Server::start(app.clone()) {
        Ok(server) => {
            *slot = Some(server);
            None
        }
        Err(error) => Some(error.to_string()),
    }
}

/// Registration state. When HKCU already names a DLL, this also brings the
/// local server up; the read itself writes nothing.
/// `passkeys_answer_approval`: the person's answer to a pending assertion.
///
/// A late click for a request that is no longer waiting is refused rather than
/// applied to whatever is pending now.
#[tauri::command]
pub fn passkeys_answer_approval(id: u64, allow: bool) -> Result<bool, String> {
    Ok(approval::approval().answer(id, allow))
}

#[tauri::command]
pub fn passkeys_status(app: AppHandle) -> Result<PasskeyStatus, String> {
    // Serving is unconditional: the DLL is what Windows calls, and a packaged
    // registration lives in the package manifest, not in HKCU.
    let error = ensure_pipe(&app);
    Ok(status_with(None, error))
}

/// Write `HKCU\Software\Classes\CLSID\{…}` for this build's
/// `kestrel_passkey.dll`, start the pipe, and ask Windows to route WebAuthn to
/// the plugin. Does nothing until called.
#[tauri::command]
pub fn passkeys_register_plugin(app: AppHandle) -> Result<PasskeyStatus, String> {
    let dll = reg::plugin_dll_path().map_err(|error| error.to_string())?;
    if !dll.is_file() {
        return Err(format!(
            "{} is missing; build it with `cargo build -p kestrel-passkey` and place it next to kestrel.exe",
            dll.display()
        ));
    }
    reg::register(&dll).map_err(|error| error.to_string())?;

    let pipe_error = ensure_pipe(&app);
    let windows = reg::add_to_windows();
    Ok(status_with(Some(windows), pipe_error))
}

/// Stop serving, remove the CLSID tree and prove it is gone. The registry
/// delete is attempted even when the Windows API is missing, so a partial
/// registration can still be cleaned up.
#[tauri::command]
pub fn passkeys_unregister_plugin() -> Result<PasskeyStatus, String> {
    let windows = reg::remove_from_windows();
    let server = service()
        .lock()
        .expect("passkey service mutex")
        .take();
    if let Some(server) = server {
        server.stop();
    }
    reg::unregister().map_err(|error| error.to_string())?;
    Ok(status_with(Some(windows), None))
}

/// Credentials attached to one item. Metadata only; the credential id is the
/// public identifier in lower-case hex.
#[tauri::command]
pub fn passkeys_for_item(
    state: State<'_, VaultState>,
    item_id: String,
) -> Result<Vec<PasskeyInfo>, String> {
    state.passkeys_for_item(&item_id).map_err(|error| error.to_string())
}

/// Remove one credential from one item. `credential_id` is the hex string the
/// block displayed; a malformed value is refused before SQL sees it.
#[tauri::command]
pub fn passkeys_remove(
    state: State<'_, VaultState>,
    item_id: String,
    credential_id: String,
) -> Result<(), String> {
    let bytes = parse_credential_id(&credential_id)?;
    if state
        .passkey_remove(&item_id, &bytes)
        .map_err(|error| error.to_string())?
    {
        Ok(())
    } else {
        Err("no such passkey on this item".to_string())
    }
}

/// Parse the public credential id shown in the block. Refuses odd lengths and
/// non-hex instead of truncating.
fn parse_credential_id(text: &str) -> Result<Vec<u8>, String> {
    if text.is_empty() || text.len() % 2 != 0 {
        return Err("credential id is not valid hex".to_string());
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_digit(pair[0])?;
        let lo = hex_digit(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("credential id is not valid hex".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_credential_id;

    #[test]
    fn credential_hex_is_strict() {
        assert_eq!(parse_credential_id("000fa5ff").unwrap(), vec![0, 15, 165, 255]);
        assert_eq!(parse_credential_id("ABCD").unwrap(), vec![0xab, 0xcd]);
        assert!(parse_credential_id("abc").is_err());
        assert!(parse_credential_id("zz").is_err());
        assert!(parse_credential_id("").is_err());
    }
}
