//! Sealing and opening a [`SyncBody`] for the sync service.
//!
//! The plaintext JSON is sealed with XChaCha20-Poly1305, and the associated
//! data binds the account id, the item id and the **item clock**
//! (`kestrel/sync/v1|<account>|<item>|<clock>`). A blob therefore cannot be
//! replayed onto another item, another account, or under a different clock.
//!
//! Binding the clock is what stops a hostile service from rolling a password
//! back: it can withhold a newer blob, but it cannot present an old blob under a
//! clock that dominates the local one, because the AAD would no longer match and
//! the body would not open. The clock is the canonical JSON of the vector
//! (`BTreeMap`, so key order is stable); it travels beside the blob in the
//! protocol and is authenticated here rather than trusted.
//!
//! A body that fails to open, or whose `item.id` disagrees with the call, is an
//! error. Nothing here falls back to a best-effort parse.
//!
//! The body does **not** carry a vault id. `vault_uuid` is this file's local
//! identity, and two devices of one account never share it, so it could not be
//! compared across the wire. Sync is therefore one vault per account: the engine
//! refuses to run in a file that holds more than one vault rather than write a
//! pulled item into whichever vault happens to be unlocked.

use crate::crypto::{decrypt, encrypt, CryptoError, SymKey};
use crate::sync::merge::SyncBody;
use crate::sync::Clock;

/// Prefix of the associated data. The version marker lets a future body format
/// stop an old blob from being opened under the new rules.
const AAD_PREFIX: &[u8] = b"kestrel/sync/v1|";

/// The associated data for one item's sync blob at one clock.
///
/// Guarantees that a blob sealed for `(account, item_id, clock)` authenticates
/// only for that triple; concatenation is unambiguous because the account and
/// item ids are hex and the clock is JSON, so none of them can contain the `|`
/// separator, and the prefix has a fixed length.
pub fn sync_aad(account: &str, item_id: &str, clock: &Clock) -> Vec<u8> {
    let clock = serde_json::to_vec(clock).unwrap_or_default();
    let mut aad =
        Vec::with_capacity(AAD_PREFIX.len() + account.len() + item_id.len() + clock.len() + 3);
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(account.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(item_id.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(&clock);
    aad
}

/// Seal `body` for `(account, item_id)` at `clock` under `key`.
///
/// Rejects a body whose `item.id` is not `item_id`: such a blob could never be
/// opened again (the open path performs the same check), so refusing it here
/// keeps the invariant on the producer side too.
pub fn seal_body(
    key: &SymKey,
    account: &str,
    item_id: &str,
    clock: &Clock,
    body: &SyncBody,
) -> Result<Vec<u8>, CryptoError> {
    if body.item.id != item_id {
        return Err(CryptoError::Malformed);
    }
    let plain = serde_json::to_vec(body).map_err(|_| CryptoError::Malformed)?;
    encrypt(key, &sync_aad(account, item_id, clock), &plain)
}

/// Open a blob sealed by [`seal_body`] and verify it belongs to `item_id`.
///
/// Decryption failure (wrong key, wrong account, wrong item id, wrong clock or
/// tampering) is [`CryptoError::Decrypt`]; a blob that decrypts but is not a
/// body, or whose ids disagree with the call, is [`CryptoError::Malformed`].
pub fn open_body(
    key: &SymKey,
    account: &str,
    item_id: &str,
    clock: &Clock,
    blob: &[u8],
) -> Result<SyncBody, CryptoError> {
    let plain = decrypt(key, &sync_aad(account, item_id, clock), blob)?;
    let body: SyncBody = serde_json::from_slice(&plain).map_err(|_| CryptoError::Malformed)?;
    if body.item.id != item_id {
        return Err(CryptoError::Malformed);
    }
    Ok(body)
}
