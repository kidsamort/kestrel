//! Vault switching surface.
//!
//! Every vault is its own key derived from the same master password, so these
//! commands never carry key material: `vault_switch` only re-points the session
//! at another vault uuid, and the item commands read the new ciphertext.

use kestrel_core::session::{VaultState, VaultStateDto};
use kestrel_core::VaultSummary;
use tauri::State;

fn err(e: kestrel_core::VaultError) -> String {
    e.to_string()
}

#[tauri::command]
pub fn vaults_list(state: State<'_, VaultState>) -> Result<Vec<VaultSummary>, String> {
    state.vaults().map_err(err)
}

#[tauri::command]
pub fn vault_create(state: State<'_, VaultState>, name: String) -> Result<VaultSummary, String> {
    state.create_vault(&name).map_err(err)
}

#[tauri::command]
pub fn vault_switch(state: State<'_, VaultState>, uuid: String) -> Result<VaultStateDto, String> {
    state.switch_vault(&uuid).map_err(err)
}

#[tauri::command]
pub fn vault_rename(
    state: State<'_, VaultState>,
    uuid: String,
    name: String,
) -> Result<(), String> {
    state.rename_vault(&uuid, &name).map_err(err)
}
