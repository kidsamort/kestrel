//! Audit commands: the audit itself lives in the core so password
//! material never crosses IPC.

use kestrel_core::audit::AuditReport;
use kestrel_core::session::VaultState;
use tauri::State;

fn err(e: kestrel_core::VaultError) -> String {
    e.to_string()
}

#[tauri::command]
pub fn audit_report(state: State<'_, VaultState>) -> Result<AuditReport, String> {
    state.audit_report().map_err(err)
}

#[tauri::command]
pub fn audit_check_breaches(state: State<'_, VaultState>) -> Result<AuditReport, String> {
    state.audit_check_breaches().map_err(err)
}
