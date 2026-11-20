//! Tauri command surface.
//!
//! The only bridge between the React shell and the vault. Commands are
//! deliberately coarse-grained: the UI asks for a state snapshot or a list,
//! never for keys, and secrets are copied inside the core so they never have to
//! cross the IPC boundary just to reach the clipboard.

use crate::vault_location::VaultLocation;
use kestrel_core::generator::GenerateOptions;
use kestrel_core::hello::HelloStatus;
use kestrel_core::model::{Item, ItemSummary};
use kestrel_core::session::{TotpDto, VaultError, VaultState, VaultStateDto};
use std::path::{Path, PathBuf};
use tauri::State;

fn err(e: VaultError) -> String {
    e.to_string()
}

#[tauri::command]
pub fn vault_state(state: State<'_, VaultState>) -> Result<VaultStateDto, String> {
    state.state().map_err(err)
}

/// Where the vault choice stands: the file, its hint, and whether a password
/// still has to be created — enough for the first-run screen and the lock
/// screen without opening anything.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultLocationDto {
    /// The vault this app is pointed at: the open one, or the remembered path
    /// when it could not be opened. `None` only on a genuine first run.
    path: Option<String>,
    hint: Option<String>,
    initialized: bool,
    locked: bool,
    default_dir: String,
}

#[tauri::command]
pub fn vault_location(
    state: State<'_, VaultState>,
    location: State<'_, VaultLocation>,
) -> Result<VaultLocationDto, String> {
    // An open vault wins; otherwise the remembered path still names the file the
    // user expects, which is what the "this file is not here" screen is for.
    let open = state.path();
    let remembered = location.last();
    let path = open.clone().or_else(|| remembered.clone());
    // The hint is unsealed vault metadata. A vault that is not open has none to
    // read, and a hint that is not valid UTF-8 is not a reason to lock the gate
    // out of its own screen: it is treated as absent.
    let hint = match &open {
        Some(_) => state.password_hint().map_err(err)?,
        None => None,
    };
    let snapshot = state.state().map_err(err)?;
    Ok(VaultLocationDto {
        path: path.map(|path| path.to_string_lossy().into_owned()),
        hint,
        initialized: snapshot.initialized,
        locked: snapshot.locked,
        default_dir: location.default_dir().to_string_lossy().into_owned(),
    })
}

/// Turn a core refusal into the tokens the UI branches on. Everything else is a
/// message for the user.
fn vault_lifecycle_error(failure: VaultError) -> String {
    match failure {
        VaultError::AlreadyExists => "already_exists".to_string(),
        VaultError::WeakPassword => "weak_password".to_string(),
        other => other.to_string(),
    }
}

/// The file a create request names: `.db` is appended when the user typed no
/// extension, so "personal" and "personal.db" are the same vault.
fn vault_file_from_user(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("invalid_path".to_string());
    }
    let path = PathBuf::from(trimmed);
    // A relative path would resolve against whatever directory the app was
    // started from, and the config would then point somewhere else on the next
    // launch. The form asks for a full path; refuse anything else.
    if !path.is_absolute() {
        return Err("invalid_path".to_string());
    }
    let Some(name) = path.file_name() else {
        return Err("invalid_path".to_string());
    };
    if name == std::ffi::OsStr::new(".") || name == std::ffi::OsStr::new("..") {
        return Err("invalid_path".to_string());
    }
    if path.extension().is_none() {
        return Ok(path.with_extension("db"));
    }
    Ok(path)
}

/// Native folder picker for the create-vault screen, so a person does not have
/// to type a path. Deliberately stateless: choosing a folder touches no vault,
/// so this command never sees `VaultState`. `start` only tells the dialog where
/// to open, and the picker ignores it unless it is still a directory.
#[tauri::command]
pub fn vault_pick_folder(start: Option<String>) -> Result<Option<String>, String> {
    let start = start.map(PathBuf::from);
    let chosen = crate::dialogs::pick_folder("Choose a folder for the vault", start.as_deref())?;
    Ok(chosen.map(|path| path.to_string_lossy().into_owned()))
}

#[tauri::command]
pub fn vault_create_at(
    state: State<'_, VaultState>,
    location: State<'_, VaultLocation>,
    app: tauri::AppHandle,
    path: String,
    password: String,
    hint: Option<String>,
) -> Result<VaultStateDto, String> {
    let file = vault_file_from_user(&path)?;
    let previous = location.last();
    if let Some(parent) = file.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|failure| format!("cannot create {}: {failure}", parent.display()))?;
        }
    }
    // Persist the intent first, then switch: a crash between the two leaves a
    // config naming a file that exists (the create ran) rather than a core on a
    // file nothing remembers.
    location.remember(&file)?;
    let opened = match state.create_at(file.clone(), &password, hint.as_deref()) {
        Ok(opened) => opened,
        Err(failure) => {
            // The switch failed, so the config must not keep pointing at it.
            restore_remembered(&location, previous.as_deref());
            return Err(vault_lifecycle_error(failure));
        }
    };
    crate::autofill::reopen(&app, &file);
    Ok(opened)
}

#[tauri::command]
pub fn vault_open_at(
    state: State<'_, VaultState>,
    location: State<'_, VaultLocation>,
    app: tauri::AppHandle,
    path: String,
) -> Result<VaultStateDto, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("invalid_path".to_string());
    }
    let file = PathBuf::from(trimmed);
    if !file.is_absolute() {
        return Err("invalid_path".to_string());
    }
    match std::fs::metadata(&file) {
        Ok(metadata) if metadata.is_dir() => return Err("invalid_path".to_string()),
        Ok(_) => {}
        Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => {
            return Err("not_found".to_string())
        }
        Err(failure) => return Err(format!("cannot read {}: {failure}", file.display())),
    }
    let previous = location.last();
    location.remember(&file)?;
    let opened = match state.open_at(file.clone()) {
        Ok(opened) => opened,
        Err(failure) => {
            restore_remembered(&location, previous.as_deref());
            return Err(err(failure));
        }
    };
    // The rule table is a second connection to the vault's database; it has to
    // follow the switch or autofill serves the previous vault's policy.
    crate::autofill::reopen(&app, &file);
    Ok(opened)
}

/// Ask where to put the recovery kit, write the PDF there, return the path.
///
/// `Ok(None)` means the person cancelled the dialog. The code is already on
/// screen; this puts the same sheet in a file they chose, because "it saved
/// somewhere" is not the same as "I know where it is".
#[tauri::command]
pub fn recovery_save_pdf(
    vault_name: String,
    code: String,
    created_at: i64,
) -> Result<Option<String>, String> {
    // The kit reports **milliseconds**; the sheet wants a calendar date.
    let created_seconds = (created_at / 1_000).max(0);
    let suggested = crate::recovery_pdf::suggested_file_name(&vault_name, created_seconds);
    let Some(path) =
        crate::dialogs::save_file("Save the recovery kit", &suggested, "PDF document", "*.pdf")?
    else {
        return Ok(None);
    };
    crate::recovery_pdf::write_recovery_pdf_at(&path, &vault_name, &code, created_seconds)?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

/// Pick an existing vault file and return its path. `Ok(None)` is Cancel.
#[tauri::command]
pub fn vault_pick_file() -> Result<Option<String>, String> {
    let picked = crate::dialogs::pick_file("Open a vault file", "Kestrel vault", "*.db")?;
    Ok(picked.map(|path| path.to_string_lossy().into_owned()))
}

/// Read a saved recovery kit and return the code printed on it.
///
/// Only a kit this app wrote can be read this way: the code is literal text in
/// the PDF. A scan or a photo needs OCR and is not claimed here — the person can
/// still type the code.
#[tauri::command]
pub fn recovery_read_kit() -> Result<Option<String>, String> {
    let Some(path) = crate::dialogs::pick_file(
        "Open the recovery kit",
        "Recovery kit (PDF or text)",
        "*.pdf;*.txt",
    )?
    else {
        return Ok(None);
    };
    let bytes = std::fs::read(&path)
        .map_err(|failure| format!("cannot read {}: {failure}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    match crate::recovery_pdf::extract_code(&text) {
        Some(code) => Ok(Some(code)),
        None => Err("no recovery code was found in that file".to_string()),
    }
}

/// Open a folder in the file manager, for the create screen where the vault file
/// does not exist yet. Refuses anything that is not an existing directory: this
/// is a view, not a way to make paths.
#[tauri::command]
pub fn folder_reveal(path: String) -> Result<(), String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("invalid_path".to_string());
    }
    let dir = PathBuf::from(trimmed);
    if !dir.is_dir() {
        return Err("not_found".to_string());
    }
    reveal_directory(&dir)
}

#[tauri::command]
pub fn vault_reveal_folder(state: State<'_, VaultState>) -> Result<(), String> {
    let path = state.path().ok_or_else(|| "no_vault".to_string())?;
    reveal_in_file_manager(&path)
}

/// Put the remembered path back after a switch that failed, so the config never
/// names a vault the core is not on.
fn restore_remembered(location: &VaultLocation, previous: Option<&Path>) {
    match previous {
        Some(path) => {
            let _ = location.remember(path);
        }
        None => {
            let _ = location.forget();
        }
    }
}

/// Open a directory itself (not a selection inside it).
#[cfg(windows)]
fn reveal_directory(path: &Path) -> Result<(), String> {
    std::process::Command::new("explorer.exe")
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|failure| format!("cannot open {}: {failure}", path.display()))
}

#[cfg(not(windows))]
fn reveal_directory(_path: &Path) -> Result<(), String> {
    Err("opening a folder is Windows only".to_string())
}

/// Show the vault file in the system file manager. Windows uses Explorer's
/// `/select,<path>`; `Command` passes the whole selector as one argument and
/// quotes it when the path holds spaces, so nothing is ever built as a shell
/// string.
#[cfg(windows)]
fn reveal_in_file_manager(path: &Path) -> Result<(), String> {
    let selection = format!("/select,{}", path.display());
    std::process::Command::new("explorer.exe")
        .arg(&selection)
        .spawn()
        .map(|_| ())
        .map_err(|failure| format!("cannot open the vault folder: {failure}"))
}

#[cfg(not(windows))]
fn reveal_in_file_manager(path: &Path) -> Result<(), String> {
    let folder = path.parent().unwrap_or(path);
    std::process::Command::new("xdg-open")
        .arg(folder)
        .spawn()
        .map(|_| ())
        .map_err(|failure| format!("cannot open the vault folder: {failure}"))
}

#[tauri::command]
pub fn unlock_vault(
    state: State<'_, VaultState>,
    password: String,
) -> Result<VaultStateDto, String> {
    state.unlock(&password).map_err(err)
}

#[tauri::command]
pub fn lock_vault(state: State<'_, VaultState>) -> Result<VaultStateDto, String> {
    state.lock().map_err(err)
}

#[tauri::command]
pub fn touch_vault(state: State<'_, VaultState>) {
    state.touch();
}

#[tauri::command]
pub fn set_autolock(state: State<'_, VaultState>, seconds: u64) -> Result<VaultStateDto, String> {
    state.set_autolock(seconds).map_err(err)
}

#[tauri::command]
pub fn set_clipboard_clear(
    state: State<'_, VaultState>,
    seconds: u64,
) -> Result<VaultStateDto, String> {
    state.set_clipboard_clear(seconds).map_err(err)
}

#[tauri::command]
pub fn list_items_page(
    state: State<'_, VaultState>,
    query: String,
    category: Option<String>,
    favorites_only: bool,
    limit: usize,
    offset: usize,
) -> Result<kestrel_core::Page, String> {
    state
        .list_page(&query, category.as_deref(), favorites_only, limit, offset)
        .map_err(err)
}

#[tauri::command]
pub fn item_counts(state: State<'_, VaultState>) -> Result<kestrel_core::Counts, String> {
    state.counts().map_err(err)
}

#[tauri::command]
pub fn list_items(
    state: State<'_, VaultState>,
    query: String,
    category: Option<String>,
    favorites_only: bool,
) -> Result<Vec<ItemSummary>, String> {
    state
        .list(&query, category.as_deref(), favorites_only)
        .map_err(err)
}

#[tauri::command]
pub fn get_item(state: State<'_, VaultState>, id: String) -> Result<Item, String> {
    state.get(&id).map_err(err)
}

#[tauri::command]
pub fn create_item(state: State<'_, VaultState>, category: String) -> Result<Item, String> {
    let item = state.create_default(&category).map_err(err)?;
    crate::sync_scheduler::request_sync();
    Ok(item)
}

#[tauri::command]
pub fn save_item(state: State<'_, VaultState>, item: Item) -> Result<Item, String> {
    let saved = state.save(item).map_err(err)?;
    // A save is what a person means by "sync this": ask for a debounced run
    // instead of waiting for the timer.
    crate::sync_scheduler::request_sync();
    Ok(saved)
}

#[tauri::command]
pub fn item_totp(state: State<'_, VaultState>, id: String) -> Result<TotpDto, String> {
    state.totp(&id).map_err(err)
}

#[tauri::command]
pub fn copy_field(
    state: State<'_, VaultState>,
    item_id: String,
    field_id: String,
) -> Result<(), String> {
    state.copy_field(&item_id, &field_id).map_err(err)
}

#[tauri::command]
pub fn copy_text(state: State<'_, VaultState>, text: String) -> Result<(), String> {
    state.copy_text(text).map_err(err)
}

#[tauri::command]
pub fn generate_password(options: Option<GenerateOptions>) -> String {
    kestrel_core::generator::generate(&options.unwrap_or_default())
}

#[tauri::command]
pub fn change_password(
    state: State<'_, VaultState>,
    old_password: String,
    new_password: String,
) -> Result<VaultStateDto, String> {
    state
        .change_password(&old_password, &new_password)
        .map_err(err)
}

#[tauri::command]
pub fn hello_status(state: State<'_, VaultState>) -> Result<HelloStatus, String> {
    state.hello_status().map_err(err)
}

#[tauri::command]
pub fn hello_enroll(state: State<'_, VaultState>) -> Result<HelloStatus, String> {
    state.hello_enroll().map_err(err)
}

#[tauri::command]
pub fn hello_disable(state: State<'_, VaultState>) -> Result<HelloStatus, String> {
    state.hello_disable().map_err(err)
}

#[tauri::command]
pub fn hello_unlock(state: State<'_, VaultState>) -> Result<VaultStateDto, String> {
    state.hello_unlock().map_err(err)
}

#[tauri::command]
pub fn app_meta(state: State<'_, VaultState>) -> serde_json::Value {
    serde_json::json!({
        "name": "Kestrel",
        "version": env!("CARGO_PKG_VERSION"),
        "vaultFormat": 1,
        "vaultPath": state.vault_path().to_string_lossy(),
        "deviceName": device_name(),
    })
}

/// The machine name shown on About; `unknown` when the environment omits it.
fn device_name() -> String {
    match std::env::var("COMPUTERNAME") {
        Ok(name) if !name.trim().is_empty() => name,
        _ => "unknown".to_string(),
    }
}

/* ------------------------------------------------------------------ access */

/// One principal with a live token, as the item editor needs to draw it.
///
/// The token, its digest and the vault's values are absent. `scopeFields` is
/// the token's own allowlist for this item — a grant cannot exceed it, because
/// the client checks its own list before asking the vault. `grantedFields` is
/// the persisted authority, which can be narrower.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemAccessPrincipal {
    /// `mcp` or `cli`: the vocabulary the grants table stores.
    pub kind: String,
    /// The name grants and audit rows are recorded under. Empty only for the
    /// legacy unrestricted CLI pairing.
    pub client: String,
    /// The token carries no allowlist; it already reads every field.
    pub unrestricted: bool,
    /// Fields of this item the token was minted for.
    pub scope_fields: Vec<String>,
    /// Fields of this item the vault currently lets it read.
    pub granted_fields: Vec<String>,
    /// Unix seconds when this session minted the token.
    pub created_at: i64,
    /// Earliest deadline among the item's grants, when one is set.
    pub expires_at: Option<i64>,
    pub one_shot: bool,
}

/// One ticked field posted back by the item editor.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemGrantInput {
    pub kind: String,
    pub client: String,
    pub field: String,
}

/// One recorded read of this item. The value is deliberately absent.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemAuditRead {
    /// The audit label as stored: an MCP client name, `cli:<client>` or
    /// `browser:<origin>`.
    pub principal: String,
    pub field: String,
    pub at: i64,
}

/// Recent reads of one item. `truncated` means the store's recent-history cap
/// was reached, so the count is a lower bound rather than the whole history.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemAudit {
    pub reads: Vec<ItemAuditRead>,
    pub truncated: bool,
}

/// One CLI token as the SDK card may show it.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CliTokenDto {
    /// The principal name; `None` for the legacy unrestricted pairing.
    pub client: Option<String>,
    /// The token has no allowlist and reads every field while unlocked.
    pub unrestricted: bool,
    /// Persisted field grants the token currently holds.
    pub grants: usize,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub one_shot: bool,
}

/// The store caps one item's audit at this many rows; reaching it means the
/// caller cannot tell "exactly this many reads" from "at least this many".
const ITEM_AUDIT_CAP: usize = 500;

fn token_kind_name(kind: crate::sdk::TokenKind) -> &'static str {
    match kind {
        crate::sdk::TokenKind::Mcp => "mcp",
        crate::sdk::TokenKind::Cli => "cli",
    }
}

/// The live token behind a `(kind, client)` pair, or a refusal a person can act
/// on. An unrestricted CLI token has no name, so it is never found here.
fn live_token<'a>(
    tokens: &'a [crate::sdk::SessionToken],
    kind: &str,
    client: &str,
) -> Result<&'a crate::sdk::SessionToken, String> {
    let token = tokens.iter().find(|token| {
        token_kind_name(token.kind) == kind && token.client.as_deref() == Some(client)
    });
    token.ok_or_else(|| {
        format!("{kind} client {client:?} has no live token. Pair it again in Settings.")
    })
}

/// Everything the item editor's Access section draws: only principals that
/// hold a live token, and only what each token could actually read.
///
/// A grant that outlived its token is not reported as live access. The rows
/// stay in the vault (re-pairing replaces them) but a principal without a
/// token cannot authenticate, so offering them would be a promise no read path
/// keeps.
#[tauri::command]
pub fn item_grants(
    state: State<'_, VaultState>,
    sdk: State<'_, crate::sdk::SdkHandle>,
    item_id: String,
) -> Result<Vec<ItemAccessPrincipal>, String> {
    let item = state.get_quiet(&item_id).map_err(err)?;
    let grants = state.grants_for_item(&item.id).map_err(err)?;
    let live_field = |field: &str| item.fields.iter().any(|candidate| candidate.id == field);
    let mut principals = Vec::new();
    for token in sdk.access_tokens() {
        let kind = token_kind_name(token.kind);
        let client = token.client.clone().unwrap_or_default();
        let scope_fields: Vec<String> = token
            .scope
            .as_ref()
            .map(|scope| {
                scope
                    .iter()
                    .filter(|grant| grant.item == item.id && live_field(&grant.field))
                    .map(|grant| grant.field.clone())
                    .collect()
            })
            .unwrap_or_default();
        let mut matching: Vec<_> = grants
            .iter()
            .filter(|grant| {
                grant.principal_kind == kind
                    && grant.principal_id == client
                    && live_field(&grant.field)
            })
            .collect();
        matching.sort_by(|left, right| left.field.cmp(&right.field));
        matching.dedup_by(|left, right| left.field == right.field);
        principals.push(ItemAccessPrincipal {
            kind: kind.to_string(),
            unrestricted: token.scope.is_none(),
            granted_fields: matching.iter().map(|grant| grant.field.clone()).collect(),
            created_at: token.created_at,
            expires_at: matching.iter().filter_map(|grant| grant.expires_at).min(),
            one_shot: matching.iter().any(|grant| grant.one_shot),
            client,
            scope_fields,
        });
    }
    principals.sort_by(|left, right| {
        (left.kind.as_str(), left.client.as_str())
            .cmp(&(right.kind.as_str(), right.client.as_str()))
    });
    Ok(principals)
}

/// Replace this item's grants with exactly the ticked list.
///
/// Validation happens here, against the live tokens: a payload that names a
/// principal without a token, a field outside that token's pairing, or a field
/// the item does not have is refused instead of persisted. The vault write is
/// the core's atomic per-item replacement; the command adds no storage logic
/// of its own.
#[tauri::command]
pub fn item_set_grants(
    state: State<'_, VaultState>,
    sdk: State<'_, crate::sdk::SdkHandle>,
    item_id: String,
    grants: Vec<ItemGrantInput>,
) -> Result<(), String> {
    let item = state.get_quiet(&item_id).map_err(err)?;
    let tokens = sdk.access_tokens();
    let mut checked = Vec::with_capacity(grants.len());
    for grant in &grants {
        let field = item
            .fields
            .iter()
            .find(|candidate| candidate.id == grant.field)
            .ok_or_else(|| "That field is no longer in the item. Reload it.".to_string())?;
        let token = live_token(&tokens, &grant.kind, grant.client.trim())?;
        let scope = token.scope.as_ref().ok_or_else(|| {
            "An unrestricted CLI token already reads every field. Pair a scoped CLI to limit it."
                .to_string()
        })?;
        if !scope
            .iter()
            .any(|allowed| allowed.item == item.id && allowed.field == field.id)
        {
            return Err(format!(
                "“{}” was not part of {}’s pairing. Pair that client again with the field ticked.",
                field.label,
                grant.client.trim()
            ));
        }
        checked.push((
            grant.kind.clone(),
            grant.client.trim().to_string(),
            field.id.clone(),
        ));
    }
    state.set_item_grants(&item.id, &checked).map_err(err)
}

/// Recent reads of one item, newest first, with the store's cap made explicit.
#[tauri::command]
pub fn item_audit(state: State<'_, VaultState>, item_id: String) -> Result<ItemAudit, String> {
    let rows = state.audit_for_item(&item_id).map_err(err)?;
    let truncated = rows.len() >= ITEM_AUDIT_CAP;
    Ok(ItemAudit {
        reads: rows
            .into_iter()
            .map(|row| ItemAuditRead {
                principal: row.client,
                field: row.field,
                at: row.at,
            })
            .collect(),
        truncated,
    })
}

/// The CLI tokens this session minted, with the grants the vault still holds.
///
/// A vault lock revokes the tokens but leaves their grant rows; listing from
/// the token authority (not the rows) is what keeps this card from offering
/// access that no client can use.
#[tauri::command]
pub fn cli_tokens(
    state: State<'_, VaultState>,
    sdk: State<'_, crate::sdk::SdkHandle>,
) -> Result<Vec<CliTokenDto>, String> {
    let mut rows = Vec::new();
    for token in sdk
        .access_tokens()
        .into_iter()
        .filter(|token| token.kind == crate::sdk::TokenKind::Cli)
    {
        let grants = match token.client.as_deref() {
            Some(client) => state.grants_for("cli", client).map_err(err)?,
            None => Vec::new(),
        };
        rows.push(CliTokenDto {
            unrestricted: token.scope.is_none(),
            grants: grants.len(),
            created_at: token.created_at,
            expires_at: grants.iter().filter_map(|grant| grant.expires_at).min(),
            one_shot: grants.iter().any(|grant| grant.one_shot),
            client: token.client,
        });
    }
    Ok(rows)
}

/// Revoke one CLI token and drop the grants recorded under its name.
///
/// `client` is `None` for the unrestricted legacy pairing, which has no grant
/// rows. A name the session does not know is reported as not paired, while any
/// stale rows it left behind are still cleared.
#[tauri::command]
pub fn cli_revoke(
    state: State<'_, VaultState>,
    sdk: State<'_, crate::sdk::SdkHandle>,
    client: Option<String>,
) -> Result<(), String> {
    let client = client
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty());
    let had_token = sdk.revoke_cli(client.as_deref());
    if let Some(name) = &client {
        state.cli_set_grants(name, &[], None, false).map_err(err)?;
    }
    if !had_token {
        return Err("That CLI token is not paired.".into());
    }
    Ok(())
}

/// A URL that survived the opener allowlist.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OpenUrlError {
    #[error("url is empty")]
    Empty,
    #[error("url must be an absolute http(s) url")]
    Malformed,
    #[error("url scheme is not allowed: {0}")]
    Scheme(String),
    #[error("the system could not open the url")]
    Open,
}

/// Only `http` and `https` may leave the process; the renderer itself still
/// never navigates, it asks the shell to hand the URL to the system browser.
fn checked_url(raw: &str) -> Result<&str, OpenUrlError> {
    let url = raw.trim();
    if url.is_empty() {
        return Err(OpenUrlError::Empty);
    }
    let (scheme, rest) = url.split_once("://").ok_or(OpenUrlError::Malformed)?;
    match scheme.to_ascii_lowercase().as_str() {
        "http" | "https" => {}
        other => return Err(OpenUrlError::Scheme(other.to_string())),
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(OpenUrlError::Malformed);
    }
    Ok(url)
}

#[cfg(windows)]
fn shell_open(url: &str) -> Result<(), OpenUrlError> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let verb: Vec<u16> = "open\0".encode_utf16().collect();
    let target: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
    // ShellExecuteW returns a pseudo-HINSTANCE; values above 32 mean success.
    let rc = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if rc as isize > 32 {
        Ok(())
    } else {
        Err(OpenUrlError::Open)
    }
}

#[cfg(not(windows))]
fn shell_open(_url: &str) -> Result<(), OpenUrlError> {
    Err(OpenUrlError::Open)
}

#[tauri::command]
pub fn open_url(url: String) -> Result<(), String> {
    let url = checked_url(&url).map_err(|e| e.to_string())?;
    shell_open(url).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::{checked_url, OpenUrlError};

    #[test]
    fn accepts_absolute_http_and_https() {
        assert_eq!(
            checked_url("https://example.com/a?b=1").unwrap(),
            "https://example.com/a?b=1"
        );
        assert_eq!(
            checked_url("  HTTP://example.com  ").unwrap(),
            "HTTP://example.com"
        );
        assert_eq!(
            checked_url("http://localhost:8080/").unwrap(),
            "http://localhost:8080/"
        );
    }

    #[test]
    fn rejects_everything_else() {
        assert_eq!(checked_url(""), Err(OpenUrlError::Empty));
        assert_eq!(checked_url("   "), Err(OpenUrlError::Empty));
        assert_eq!(
            checked_url("file:///C:/secret.txt"),
            Err(OpenUrlError::Scheme("file".into()))
        );
        assert_eq!(
            checked_url("javascript://alert(1)"),
            Err(OpenUrlError::Scheme("javascript".into()))
        );
        assert_eq!(checked_url("not a url"), Err(OpenUrlError::Malformed));
        assert_eq!(checked_url("https://"), Err(OpenUrlError::Malformed));
        assert_eq!(checked_url("https:///path"), Err(OpenUrlError::Malformed));
    }
}
