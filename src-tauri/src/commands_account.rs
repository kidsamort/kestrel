//! Sync account surface: identity, the Secret Key and device enrolment.
//!
//! No command returns the account key, and `account_create` is the only way the
//! Secret Key ever leaves the core. `account_secret_key` answers whether the
//! stored copy still opens; it never re-displays it. Both halves of an
//! enrolment are local work: `account_device_identity` hands the renderer this
//! device's public keys, `account_seal_for_device` mints the code and envelope,
//! and `account_enroll_claim` receives them. No command returns a device
//! private key; the net crate gets those in-process, not through the bridge.
//!
//! `account_revoke_device` is the one command here that talks to the sync
//! service: it withdraws another device's access with a signed request and then
//! records the revocation locally. It never rotates the account key, and the
//! card says so.

use kestrel_core::session::{VaultError, VaultState};
use kestrel_core::store::{
    AccountClaimed, AccountCreated, AccountDevice, AccountSecretKey, AccountStatus, DeviceIdentity,
    EnrolCode, SealedEnrolment,
};
use kestrel_net::{ClientConfig, SyncClient};
use serde::Serialize;
use tauri::State;

use crate::commands_sync::KEY_SERVER;

fn err(e: kestrel_core::VaultError) -> String {
    e.to_string()
}

/// Account presence, id, device count and Secret Key presence. Answers while
/// locked: it reads public shape only.
#[tauri::command]
pub fn account_status(state: State<'_, VaultState>) -> Result<AccountStatus, String> {
    state.account_status().map_err(err)
}

/// Create the account for this vault file. The Secret Key is in this return
/// value and nowhere else.
#[tauri::command]
pub fn account_create(state: State<'_, VaultState>) -> Result<AccountCreated, String> {
    state.account_create().map_err(err)
}

/// Verify the sealed Secret Key without returning it.
#[tauri::command]
pub fn account_secret_key(state: State<'_, VaultState>) -> Result<AccountSecretKey, String> {
    state.account_secret_key().map_err(err)
}

/// Mint a one-handover enrolment code.
#[tauri::command]
pub fn account_enrol_code(state: State<'_, VaultState>) -> Result<EnrolCode, String> {
    state.account_enrol_code().map_err(err)
}

/// Seal this account's key to another device's agreement public key (hex).
#[tauri::command]
pub fn account_seal_for_device(
    state: State<'_, VaultState>,
    code: String,
    device_agreement_pub: String,
) -> Result<SealedEnrolment, String> {
    state
        .account_seal_for_device(&code, &device_agreement_pub)
        .map_err(err)
}

/// Devices in the local mirror. Public keys only.
#[tauri::command]
pub fn account_devices(state: State<'_, VaultState>) -> Result<Vec<AccountDevice>, String> {
    state.account_devices().map_err(err)
}

/// This device's public keys, generating the keypair on first use. The joining
/// side of an enrolment shows these so the other device can seal to them.
#[tauri::command]
pub fn account_device_identity(state: State<'_, VaultState>) -> Result<DeviceIdentity, String> {
    state.device_identity().map_err(err)
}

/// Receive an account from the three values the sending device printed: the
/// code, the sealed blob and the sender's agreement key. The account key is
/// sealed into the database; only the account id comes back.
#[tauri::command]
pub fn account_enroll_claim(
    state: State<'_, VaultState>,
    code: String,
    sealed: String,
    sender_agreement_pub: String,
) -> Result<AccountClaimed, String> {
    state
        .account_enroll_claim(&code, &sealed, &sender_agreement_pub)
        .map_err(err)
}

/// What a revocation actually did. The UI composes its sentence from these
/// facts instead of promising an effect that did not happen.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountRevocation {
    pub device_id: String,
    /// Unix milliseconds when the local row was marked revoked; `None` when the
    /// row was removed because no service was configured.
    pub revoked_at: Option<u64>,
    /// The sync service recorded the revocation and will refuse the device.
    pub server_revoked: bool,
    /// The local mirror row was deleted because there was no service to tell.
    pub local_removed: bool,
}

/// Revoke one other device.
///
/// With a sync service configured this is a signed `DELETE /v1/devices/<id>`
/// followed by a local mark; the row stays so Settings can say "Revoked". With
/// no service there is nothing to withdraw remotely, so the only honest local
/// operation is to forget the mirror row, and the result says exactly that.
/// This device cannot revoke itself: it is the one that signs every request.
///
/// The account key is not rotated here. Data the revoked device already pulled
/// stays readable to it; what revocation withdraws is future access.
#[tauri::command]
pub fn account_revoke_device(
    state: State<'_, VaultState>,
    device_id: String,
) -> Result<AccountRevocation, String> {
    let device_id = device_id.trim().to_ascii_lowercase();
    if device_id.len() != 32 || !device_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("a device id is 32 hex characters".to_string());
    }

    let local_id = state
        .store()
        .map_err(err)?
        .local_device_id()
        .map_err(|failure| failure.to_string())?;
    if local_id.as_deref() == Some(device_id.as_str()) {
        return Err("this device cannot revoke itself".to_string());
    }

    // Only a device this vault mirrors can be revoked from here: the card's
    // list is the local mirror, and marking a row that does not exist would
    // silently do nothing.
    let mirrored = state
        .account_devices()
        .map_err(err)?
        .into_iter()
        .any(|device| device.device_id == device_id);
    if !mirrored {
        return Err("that device is not in this vault's mirror".to_string());
    }

    match state.sync_meta(KEY_SERVER).map_err(err)? {
        Some(server) => {
            state
                .with_unlocked(|store, master, _meta| {
                    let account_id = store.account_status()?.account_id.ok_or_else(|| {
                        VaultError::Invalid("this vault has no account".to_string())
                    })?;
                    let keys = store.device_secret_keys(master)?;
                    let client = SyncClient::new(ClientConfig {
                        base_url: server.clone(),
                        account_id,
                        device_id: keys.device_id().to_string(),
                        signing_key: *keys.signing_secret(),
                        allow_insecure: false,
                    })
                    .map_err(|failure| VaultError::Invalid(failure.to_string()))?;
                    client
                        .revoke_device(&device_id)
                        .map_err(|failure| VaultError::Invalid(failure.to_string()))
                })
                .map_err(err)?;

            let revoked_at = state
                .store()
                .map_err(err)?
                .mark_device_revoked(&device_id)
                .map_err(|failure| failure.to_string())?;
            Ok(AccountRevocation {
                device_id,
                revoked_at: Some(revoked_at),
                server_revoked: true,
                local_removed: false,
            })
        }
        None => {
            state
                .store()
                .map_err(err)?
                .forget_device(&device_id)
                .map_err(|failure| failure.to_string())?;
            Ok(AccountRevocation {
                device_id,
                revoked_at: None,
                server_revoked: false,
                local_removed: true,
            })
        }
    }
}
