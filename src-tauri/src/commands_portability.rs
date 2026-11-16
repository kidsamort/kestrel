//! Import/export command surface.
//!
//! Four commands, all thin wrappers over [`kestrel_core::session::VaultState`]:
//! preview a file, import it, export JSON/CSV text, or export a 1PUX archive.
//! The core never writes an export to disk; `export_1pux` returns the raw bytes
//! as a binary IPC response so the renderer can hand them to the user.

use kestrel_core::portability::{ImportPreview, ImportReport};
use kestrel_core::session::VaultState;
use tauri::ipc::Response;
use tauri::State;

fn err(error: kestrel_core::VaultError) -> String {
    error.to_string()
}

#[tauri::command]
pub fn import_preview(
    state: State<'_, VaultState>,
    format: String,
    bytes: Vec<u8>,
) -> Result<ImportPreview, String> {
    state.import_preview(&format, bytes).map_err(err)
}

#[tauri::command]
pub fn import_items(
    state: State<'_, VaultState>,
    format: String,
    bytes: Vec<u8>,
) -> Result<ImportReport, String> {
    let count = state.import_items(&format, bytes).map_err(err)?;
    // An import is a bulk write: waiting out the whole interval would leave the
    // other devices a vault behind.
    crate::sync_scheduler::request_sync();
    Ok(count)
}

#[tauri::command]
pub fn export_items(
    state: State<'_, VaultState>,
    format: String,
    password: String,
) -> Result<String, String> {
    state.export_items(&format, &password).map_err(err)
}

#[tauri::command]
pub fn export_1pux(state: State<'_, VaultState>, password: String) -> Result<Response, String> {
    state.export_1pux(&password).map(Response::new).map_err(err)
}
