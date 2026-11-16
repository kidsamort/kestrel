//! History command surface: list archived versions, read one, restore it.

use kestrel_core::history::VersionSummary;
use kestrel_core::model::Item;
use kestrel_core::session::VaultState;
use tauri::State;

fn err(e: kestrel_core::VaultError) -> String {
    e.to_string()
}

#[tauri::command]
pub fn history_list(
    state: State<'_, VaultState>,
    item_id: String,
) -> Result<Vec<VersionSummary>, String> {
    state.history_list(&item_id).map_err(err)
}

#[tauri::command]
pub fn history_get(
    state: State<'_, VaultState>,
    item_id: String,
    version: i64,
) -> Result<Item, String> {
    state.history_get(&item_id, version).map_err(err)
}

#[tauri::command]
pub fn history_restore(
    state: State<'_, VaultState>,
    item_id: String,
    version: i64,
) -> Result<Item, String> {
    let item = state.history_restore(&item_id, version).map_err(err)?;
    crate::sync_scheduler::request_sync();
    Ok(item)
}
