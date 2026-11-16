//! Attachment commands: list, add, read, save-as, remove.
//!
//! The renderer only ever receives metadata, or — for "Save as" — the absolute
//! path of the file the core wrote outside the vault. Attachment bytes reach
//! the renderer exactly once, on add, and never come back from `read` in a
//! shipped flow.

use kestrel_core::attachments::AttachmentDto;
use kestrel_core::session::VaultState;
use tauri::State;

fn err(e: kestrel_core::VaultError) -> String {
    e.to_string()
}

#[tauri::command]
pub fn attachment_list(
    state: State<'_, VaultState>,
    item_id: String,
) -> Result<Vec<AttachmentDto>, String> {
    state.attachment_list(&item_id).map_err(err)
}

#[tauri::command]
pub fn attachment_add(
    state: State<'_, VaultState>,
    item_id: String,
    name: String,
    mime: String,
    bytes: Vec<u8>,
) -> Result<AttachmentDto, String> {
    state
        .attachment_add(&item_id, &name, &mime, bytes)
        .map_err(err)
}

#[tauri::command]
pub fn attachment_read(
    state: State<'_, VaultState>,
    item_id: String,
    attachment_id: String,
) -> Result<Vec<u8>, String> {
    state.attachment_read(&item_id, &attachment_id).map_err(err)
}

#[tauri::command]
pub fn attachment_save_as(
    state: State<'_, VaultState>,
    item_id: String,
    attachment_id: String,
) -> Result<String, String> {
    state
        .attachment_save_as(&item_id, &attachment_id)
        .map_err(err)
}

#[tauri::command]
pub fn attachment_remove(
    state: State<'_, VaultState>,
    item_id: String,
    attachment_id: String,
) -> Result<(), String> {
    state
        .attachment_remove(&item_id, &attachment_id)
        .map_err(err)
}
