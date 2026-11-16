//! Browser-extension bridge: native host registration, the token file and the
//! settings commands.
//!
//! # Shape
//!
//! * [`install`] writes the Chrome/Edge native messaging registration under
//!   HKCU and the host manifest next to the vault. It is reversible and names
//!   exactly one extension id.
//! * [`token`] writes the one `Browser`-scoped token to `bridge.token` with a
//!   protected DACL for the current user. The extension's host reads that file;
//!   the browser never receives the token.
//! * This module owns the commands behind Settings → Browser and the window
//!   focus used by the extension's locked chip.
//!
//! # What the bridge can and cannot do
//!
//! The host forwards JSON to `\\.\pipe\kestrel-sdk`, and the pipe answers only
//! `browser.*` ops for a Browser token. `browser.items` returns titles and
//! field names for items saved on the page's origin. `browser.reveal` returns
//! one value, and only when the origin's rule is `fill`, the item is saved on
//! that same origin, and the field is a username, password or email field.
//! Every reveal is appended to `mcp_audit` as `browser:<origin>` before the
//! value is returned. Nothing is filled without a click in the page, and the
//! extension never stores the value it receives.
//!
//! While the vault is locked, every browser op answers `locked`; the token file
//! alone grants nothing.

mod install;
mod token;

#[cfg(test)]
mod tests;

use kestrel_core::session::{BrowserRule, VaultState};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::sdk::SdkHandle;

/// The extension id is fixed by the `key` in `extension/manifest.json`, so the
/// native host manifest can name it before the extension is ever loaded.
pub const EXTENSION_ID: &str = "ippcgmeddpnhhbjllfkknhlilnaneclk";

/// Non-secret snapshot for the card and the `browser.status` pipe op.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BrowserSnapshot {
    pub installed: bool,
    pub host_name: String,
    pub manifest_path: String,
    pub host_binary: String,
    pub host_binary_present: bool,
    pub extension_id: String,
    pub allowed_origin: String,
    pub token_path: String,
    pub token_present: bool,
    /// Explicit `browser_sites` rows; a missing row is the implicit `ask`.
    pub rules: usize,
    pub chrome_registered: bool,
    pub edge_registered: bool,
    pub firefox_registered: bool,
}

pub fn token_path() -> Result<std::path::PathBuf, String> {
    Ok(install::data_dir()?.join("bridge.token"))
}

/// Read the persisted browser token for the SDK's startup restore.
pub fn read_token() -> Result<Option<String>, String> {
    token::read(&token_path()?).map_err(|error| error.to_string())
}

/// Build the card snapshot. `rules` comes from the vault (or a direct store
/// read while locked) so the count is always the live table.
pub fn snapshot(rules: usize) -> BrowserSnapshot {
    let (chrome, edge, firefox) = install::registrations();
    let binary = install::host_binary();
    let binary_present = binary.is_file();
    let manifest = install::manifest_path()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let token = token_path()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let token_present = !token.is_empty() && std::path::Path::new(&token).is_file();
    BrowserSnapshot {
        installed: (chrome || edge) && binary_present && !manifest.is_empty(),
        host_name: install::HOST_NAME.to_string(),
        manifest_path: manifest,
        host_binary: binary.display().to_string(),
        host_binary_present: binary_present,
        extension_id: EXTENSION_ID.to_string(),
        allowed_origin: format!("chrome-extension://{EXTENSION_ID}/"),
        token_path: token,
        token_present,
        rules,
        chrome_registered: chrome,
        edge_registered: edge,
        firefox_registered: firefox,
    }
}

/* ----------------------------------------------------------------- commands */

#[tauri::command]
pub fn browser_status(state: State<'_, VaultState>) -> Result<BrowserSnapshot, String> {
    let rules = state
        .browser_rules()
        .map_err(|error| error.to_string())?
        .len();
    Ok(snapshot(rules))
}

/// Install the host and mint the token the browser-started process reads.
///
/// The token is written first, then the registration. If registration fails the
/// token file is removed and the token is revoked, so a half-install leaves
/// neither an orphan secret nor a registry value pointing at a missing host.
#[tauri::command]
pub fn browser_install(
    state: State<'_, VaultState>,
    sdk: State<'_, SdkHandle>,
) -> Result<BrowserSnapshot, String> {
    let path = token_path()?;
    let token = sdk.pair_browser(&state)?;
    if let Err(error) = token::write(&path, &token) {
        sdk.revoke_browser();
        return Err(error.to_string());
    }
    if let Err(error) = install::register(EXTENSION_ID) {
        let _ = token::remove(&path);
        sdk.revoke_browser();
        return Err(error);
    }
    browser_status(state)
}

/// Remove the registration, the manifest and the token, and forget the token.
#[tauri::command]
pub fn browser_uninstall(
    state: State<'_, VaultState>,
    sdk: State<'_, SdkHandle>,
) -> Result<BrowserSnapshot, String> {
    let unregister = install::unregister();
    let remove = token_path().and_then(|path| {
        token::remove(&path)
            .map(|_| ())
            .map_err(|error| error.to_string())
    });
    sdk.revoke_browser();
    if let Err(error) = unregister {
        return Err(error);
    }
    remove?;
    browser_status(state)
}

#[tauri::command]
pub fn browser_rules(state: State<'_, VaultState>) -> Result<Vec<BrowserRule>, String> {
    state.browser_rules().map_err(|error| error.to_string())
}

#[tauri::command]
pub fn browser_set_rule(
    state: State<'_, VaultState>,
    origin: String,
    mode: String,
) -> Result<Vec<BrowserRule>, String> {
    state
        .browser_set_rule(&origin, &mode)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn browser_reset_rule(
    state: State<'_, VaultState>,
    origin: String,
) -> Result<Vec<BrowserRule>, String> {
    state
        .browser_clear_rule(&origin)
        .map_err(|error| error.to_string())
}

/* -------------------------------------------------------------------- focus */

/// Bring the main window forward for the extension's "locked" chip.
pub fn focus_main(app: &AppHandle) -> Result<(), String> {
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "the Kestrel window is not available".to_string())?;
    window
        .unminimize()
        .map_err(|error| format!("cannot restore Kestrel: {error}"))?;
    window
        .show()
        .map_err(|error| format!("cannot show Kestrel: {error}"))?;
    window
        .set_focus()
        .map_err(|error| format!("cannot focus Kestrel: {error}"))?;
    Ok(())
}

/// Test-friendly wrapper: the SDK's fake backend has no window.
pub fn focus_main_optional(app: Option<&AppHandle>) -> Result<(), String> {
    match app {
        Some(app) => focus_main(app),
        None => Ok(()),
    }
}
