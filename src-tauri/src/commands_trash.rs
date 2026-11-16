//! Trash commands.
//!
//! Soft delete, restore, permanent purge and emptying the trash. Every command
//! is a thin pass-through to `kestrel_core`; nothing about the ciphertext ever
//! crosses the IPC boundary.

use kestrel_core::model::ItemSummary;
use kestrel_core::session::VaultState;
use tauri::State;

fn err(e: kestrel_core::VaultError) -> String {
    e.to_string()
}

#[tauri::command]
pub fn trash_list(state: State<'_, VaultState>) -> Result<Vec<ItemSummary>, String> {
    state.trash_list().map_err(err)
}

#[tauri::command]
pub fn trash_item(state: State<'_, VaultState>, id: String) -> Result<(), String> {
    state.trash_item(&id).map_err(err)?;
    crate::sync_scheduler::request_sync();
    Ok(())
}

#[tauri::command]
pub fn restore_item(state: State<'_, VaultState>, id: String) -> Result<(), String> {
    state.restore_item(&id).map_err(err)?;
    crate::sync_scheduler::request_sync();
    Ok(())
}

#[tauri::command]
pub fn purge_item(state: State<'_, VaultState>, id: String) -> Result<(), String> {
    state.purge_item(&id).map_err(err)?;
    crate::sync_scheduler::request_sync();
    Ok(())
}

#[tauri::command]
pub fn empty_trash(state: State<'_, VaultState>) -> Result<u64, String> {
    state.empty_trash().map_err(err)
}
