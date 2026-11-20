//! CTAP2 operations served from the unlocked vault.
//!
//! The DLL forwards the bytes Windows produced; this module decodes them with
//! the engine, resolves the credential through [`VaultState`] (which holds the
//! only master key), signs, and returns the CTAP2 response. The response body
//! is the only thing that crosses the pipe.

use kestrel_core::model::{Category, Item, PasskeyRow};
use kestrel_core::session::{VaultError, VaultState};
use kestrel_passkey::cose::SigningMaterial;
use kestrel_passkey::ipc;
use kestrel_passkey::webauthn::{
    self, AuthenticatorData, GetAssertionRequest, MakeCredentialRequest, FLAG_AT, FLAG_UP,
};
use tauri::{AppHandle, Manager};

/// CTAP2 status bytes used by this engine.
const CTAP2_ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
const CTAP2_ERR_UNSUPPORTED_OPTION: u8 = 0x2b;
const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2e;
const CTAP2_ERR_OTHER: u8 = 0x7f;

/// One CTAP2 error is a bare status byte, not a CBOR map. Returning it as the
/// whole response body is what the spec wants.
fn ctap_error(code: u8) -> Vec<u8> {
    vec![code]
}

/// Handle one frame. A locked vault maps to `STATUS_LOCKED`; every other
/// failure is `STATUS_ERROR` with an empty body (no internal detail crosses the
/// pipe). CTAP2 errors are successful frame delivery of an error response.
pub fn handle(app: &AppHandle, op: u8, payload: &[u8]) -> (u8, Vec<u8>) {
    let state = app.state::<VaultState>();
    match op {
        ipc::OP_STATUS => (ipc::STATUS_OK, vec![if state.is_locked() { 1 } else { 0 }]),
        ipc::OP_MAKE_CREDENTIAL => respond(make_credential(&state, payload)),
        ipc::OP_GET_ASSERTION => respond(get_assertion(app, &state, payload)),
        _ => (ipc::STATUS_ERROR, Vec::new()),
    }
}

fn respond(result: Result<Vec<u8>, VaultError>) -> (u8, Vec<u8>) {
    match result {
        Ok(body) => (ipc::STATUS_OK, body),
        Err(VaultError::Locked) => (ipc::STATUS_LOCKED, Vec::new()),
        Err(_) => (ipc::STATUS_ERROR, Vec::new()),
    }
}

fn make_credential(state: &VaultState, payload: &[u8]) -> Result<Vec<u8>, VaultError> {
    let request: MakeCredentialRequest = match webauthn::parse_make_credential(payload) {
        Ok(request) => request,
        // A malformed request is the caller's problem; CTAP2 has a status for
        // it and the DLL passes it through unchanged.
        Err(_) => return Ok(ctap_error(CTAP2_ERR_OTHER)),
    };
    if request.require_uv {
        // The plugin does not perform a PIN or biometric gesture. Claiming UV
        // would tell the relying party a verification happened that did not.
        return Ok(ctap_error(CTAP2_ERR_UNSUPPORTED_OPTION));
    }
    if !request
        .algorithms
        .contains(&kestrel_passkey::cose::ALG_ES256)
    {
        return Ok(ctap_error(CTAP2_ERR_UNSUPPORTED_ALGORITHM));
    }
    for excluded in &request.exclude_list {
        if state.passkey_exists(excluded)? {
            return Ok(ctap_error(CTAP2_ERR_CREDENTIAL_EXCLUDED));
        }
    }

    let material = SigningMaterial::generate();
    let public = material.public_key();
    let secret = material.secret_bytes();
    let credential_id = webauthn::generate_credential_id();

    // A passkey registration has no item to attach to yet. The login the
    // relying party described becomes a new login item; the block in its detail
    // pane then lists this credential.
    let title = if request.rp_name.trim().is_empty() {
        request.rp_id.clone()
    } else {
        request.rp_name.clone()
    };
    let mut item = Item::new(Category::Login, title);
    for field in &mut item.fields {
        if field.kind == "username" {
            field.value = request.user_name.clone();
        }
        if field.kind == "url" {
            field.value = format!("https://{}", request.rp_id);
        }
    }
    item.urls.push(format!("https://{}", request.rp_id));
    let saved = state.save(item)?;

    let row = PasskeyRow {
        credential_id: credential_id.to_vec(),
        item_uuid: saved.id.clone(),
        rp_id: request.rp_id.clone(),
        created_at: saved.created_at,
        last_used_at: None,
    };
    if let Err(error) = state.passkey_insert(row, &secret, 0) {
        // Do not leave a login item behind for a credential that was never
        // written. The item is soft-deleted (the same path the UI uses).
        let _ = state.delete(&saved.id);
        return Err(error);
    }

    let auth_data = AuthenticatorData {
        rp_id_hash: webauthn::rp_id_hash(&request.rp_id),
        flags: FLAG_UP | FLAG_AT,
        sign_count: 0,
        attested: Some((&credential_id, &public)),
        extensions: None,
    };
    Ok(webauthn::make_credential_response(&auth_data.to_bytes()))
}

fn get_assertion(
    app: &AppHandle,
    state: &VaultState,
    payload: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let request: GetAssertionRequest = match webauthn::parse_get_assertion(payload) {
        Ok(request) => request,
        Err(_) => return Ok(ctap_error(CTAP2_ERR_OTHER)),
    };
    if request.require_uv {
        return Ok(ctap_error(CTAP2_ERR_UNSUPPORTED_OPTION));
    }
    let Some(material) = state.passkey_open_for_assertion(&request.rp_id, &request.allow_list)?
    else {
        return Ok(ctap_error(CTAP2_ERR_NO_CREDENTIALS));
    };
    // Nothing in the protocol proves the person asked for this signature, and
    // the pipe's DACL only proves the caller is this user. Ask in the app
    // before signing, and set the presence flag only after the answer.
    let account = state
        .get_quiet(&material.row.item_uuid)
        .map(|item| item.title)
        .unwrap_or_else(|_| request.rp_id.clone());
    if !super::approval::approval().request(app, &request.rp_id, &account) {
        return Ok(ctap_error(CTAP2_ERR_OPERATION_DENIED));
    }
    let Some(next) = material.sign_count.checked_add(1) else {
        // The counter would wrap; refusing beats replaying a counter value.
        return Ok(ctap_error(CTAP2_ERR_OTHER));
    };
    let signing = match SigningMaterial::from_bytes(&material.private_key) {
        Ok(signing) => signing,
        Err(_) => return Ok(ctap_error(CTAP2_ERR_OTHER)),
    };
    let auth_data = AuthenticatorData {
        rp_id_hash: webauthn::rp_id_hash(&request.rp_id),
        flags: FLAG_UP,
        sign_count: next,
        attested: None,
        extensions: None,
    }
    .to_bytes();
    let signature = match webauthn::sign_assertion(&signing, &auth_data, &request.client_data_hash)
    {
        Ok(signature) => signature,
        Err(_) => return Ok(ctap_error(CTAP2_ERR_OTHER)),
    };
    state.passkey_record_use(&material.row.credential_id, &material.private_key, next)?;
    Ok(webauthn::get_assertion_response(
        &material.row.credential_id,
        &auth_data,
        &signature,
        None,
    ))
}
