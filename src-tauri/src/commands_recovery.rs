//! Recovery kit surface: the printable code, and the two-step unlock with it.
//!
//! No command returns a stored code — there is none to return. `recovery_create`
//! mints one and hands it over once; `recovery_unlock` accepts one and parks the
//! unwrapped key, `recovery_complete` re-keys the account under a new master
//! password, and `recovery_finish` opens the session only after the caller has
//! seen the replacement code.

use kestrel_core::session::{RecoveryCompletion, RecoveryOpen, VaultState, VaultStateDto};
use kestrel_core::store::{RecoveryKit, RecoveryStatus};
use tauri::State;

fn err(e: kestrel_core::VaultError) -> String {
    e.to_string()
}

/// Kit presence. Answers while locked; reads one row of public shape.
#[tauri::command]
pub fn recovery_status(state: State<'_, VaultState>) -> Result<RecoveryStatus, String> {
    state.recovery_status().map_err(err)
}

/// Mint a code from the unlocked session, replacing any previous row. The code
/// is only ever visible in this return value.
#[tauri::command]
pub fn recovery_create(state: State<'_, VaultState>) -> Result<RecoveryKit, String> {
    state.recovery_create().map_err(err)
}

/// Unwrap the master key from a printed code. The vault stays locked until a
/// new master password is set.
#[tauri::command]
pub fn recovery_unlock(state: State<'_, VaultState>, code: String) -> Result<RecoveryOpen, String> {
    state.recovery_unlock(&code).map_err(err)
}

/// Re-key the account under a new master password and mint the replacement code.
#[tauri::command]
pub fn recovery_complete(
    state: State<'_, VaultState>,
    new_password: String,
) -> Result<RecoveryCompletion, String> {
    state.recovery_complete(&new_password).map_err(err)
}

/// Acknowledge the replacement code and open the session.
#[tauri::command]
pub fn recovery_finish(state: State<'_, VaultState>) -> Result<VaultStateDto, String> {
    state.recovery_finish().map_err(err)
}
