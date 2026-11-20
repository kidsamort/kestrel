//! The bridge token file, read side.
//!
//! The host is started by the browser, not by Kestrel, so it cannot be handed a
//! token through a command line or an inherited handle. Kestrel writes the one
//! `Browser` token to `bridge.token` next to the vault with a user-only DACL
//! (`src-tauri/src/browser/token.rs`), and this process reads it.
//!
//! The path is derived from `%APPDATA%` + the Tauri identifier. That is the
//! same directory Tauri's `app_data_dir()` uses on Windows, so the file the app
//! wrote is the file this host reads. `KESTREL_BRIDGE_TOKEN_FILE` is a test and
//! development override; it is not set by the browser.

use std::path::PathBuf;

pub fn path() -> Result<PathBuf, String> {
    if let Some(explicit) = std::env::var_os("KESTREL_BRIDGE_TOKEN_FILE") {
        return Ok(PathBuf::from(explicit));
    }
    let appdata = std::env::var_os("APPDATA")
        .ok_or_else(|| "APPDATA is not set; cannot locate the Kestrel bridge token".to_string())?;
    Ok(PathBuf::from(appdata)
        .join("app.kestrel.vault")
        .join("bridge.token"))
}

/// Read the token, trimming whitespace. A missing or empty file is `Ok(None)`.
pub fn read() -> Result<Option<String>, String> {
    let path = path()?;
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let text = text.trim().to_string();
            Ok((!text.is_empty()).then_some(text))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot read {}: {error}", path.display())),
    }
}
