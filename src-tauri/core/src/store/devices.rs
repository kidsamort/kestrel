//! This device's own keypairs and the account's device mirror.
//!
//! **Two independent keypairs per device.** Every device signs requests with
//! Ed25519 and receives sealed keys with X25519; neither key can do the other's
//! job, so a compromise of one is not a compromise of both. The private halves
//! are sealed under the master key with the same `object_aad` construction as
//! every other stored object, and the public halves sit in the clear in the
//! `devices` row, where the sync service and the other device read them:
//!
//! ```text
//! signing_key_wrapped   = XChaCha20-Poly1305(master, device-signing-key, seed(32))
//! agreement_key_wrapped = XChaCha20-Poly1305(master, device-agreement-key, secret(32))
//! ```
//!
//! The AAD binds each blob to the device id, the account and the vault, so a
//! row copied from one device to another does not open. The Ed25519 private
//! half is stored as the RFC 8032 seed, which is the whole private key; the
//! X25519 half is stored unclamped and clamped by the curve at use, exactly as
//! [`agreement_secret`] produces it.
//!
//! **Who owns a row.** The local device is the one row whose private halves
//! this vault file can open (`signing_key_wrapped IS NOT NULL`); there is at
//! most one per file by construction, and [`Store::rotate_device_keys`] keeps
//! it openable across a password change. Rows without private halves are the
//! account's other devices as the sync service reports them: public keys and a
//! label, nothing this device can spend.
//!
//! Nothing here logs a key or returns a private half to the renderer.
//! [`DeviceSecretKeys`] is the one in-process handover, for the net crate to
//! sign and unwrap with; it has no `Debug`, no `Serialize` and wipes itself on
//! drop.

use super::{Store, StoreError};
use crate::crypto::{self, object_aad, SymKey, KEY_LEN};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::SigningKey;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// `object_aad` kinds of the two sealed private halves. Distinct from the
/// account rows so a device key can never be replayed as an account key.
const SIGNING_KEY_KIND: &str = "device-signing-key";
const AGREEMENT_KEY_KIND: &str = "device-agreement-key";
/// 16 random bytes rendered as 32 lower-case hex characters, the protocol's
/// device id shape.
const DEVICE_ID_BYTES: usize = 16;
/// An X25519 public key (and an Ed25519 public key) is 32 bytes.
pub(super) const AGREEMENT_PUB_LEN: usize = 32;
/// A device label is bounded so a pasted name cannot bloat the mirror.
const DEVICE_NAME_MAX: usize = 128;
const DEFAULT_DEVICE_NAME: &str = "This device";

/// The public half of this device, as Settings → Account shows it and as the
/// other device needs it to seal the account key. Never any private material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceIdentity {
    /// 32 lower-case hex characters, chosen on this device.
    pub device_id: String,
    /// Human label the sync service and the other devices display.
    pub device_name: String,
    /// Ed25519 public key, 64 lower-case hex characters.
    pub signing_pub: String,
    /// X25519 agreement public key, 64 lower-case hex characters. This is what
    /// the sending device seals the account key to.
    pub agreement_pub: String,
    pub created_at: u64,
}

/// The local device's private halves, handed to the net crate in-process.
///
/// `signing_secret` is the Ed25519 RFC 8032 seed (the 32 bytes
/// `SigningKey::from_bytes` takes); `agreement_secret` is the unclamped X25519
/// scalar. No `Debug`, no `Serialize`, wiped on drop: the only way out of the
/// core is a caller that already holds the unlocked session.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceSecretKeys {
    device_id: String,
    signing_secret: [u8; KEY_LEN],
    agreement_secret: [u8; KEY_LEN],
}

impl DeviceSecretKeys {
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// The Ed25519 private seed. `SigningKey::from_bytes` accepts it directly.
    pub fn signing_secret(&self) -> &[u8; KEY_LEN] {
        &self.signing_secret
    }

    /// The X25519 agreement scalar, used to open an enrolment envelope.
    pub fn agreement_secret(&self) -> &[u8; KEY_LEN] {
        &self.agreement_secret
    }
}

struct LocalRow {
    device_id: String,
    signing_pub: Vec<u8>,
    agreement_pub: Vec<u8>,
    name: String,
    created_at: i64,
    signing_key_wrapped: Vec<u8>,
    agreement_key_wrapped: Vec<u8>,
}

fn now_millis() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

/// Lower-case hex. Device ids and public keys are hex because the renderer and
/// the wire carry them as text.
pub(super) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Parse exactly 64 hex characters into 32 bytes. The message never echoes the
/// input: these are public keys, but a pasted string may be anything.
pub(super) fn unhex32(text: &str) -> Result<[u8; 32], StoreError> {
    let text = text.trim();
    if text.len() != AGREEMENT_PUB_LEN * 2 {
        return Err(StoreError::Invalid(
            "a device key is 64 hex characters".into(),
        ));
    }
    let mut out = [0u8; AGREEMENT_PUB_LEN];
    for (index, pair) in text.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| StoreError::Invalid("the device key is not hex".into()))?;
        out[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| StoreError::Invalid("the device key is not hex".into()))?;
    }
    Ok(out)
}

/// Parse an even-length hex string of any size (an enrolment envelope). Same
/// no-echo rule as [`unhex32`].
pub(super) fn unhex(text: &str) -> Result<Vec<u8>, StoreError> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return Err(StoreError::Invalid("the value is not hex".into()));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| StoreError::Invalid("the value is not hex".into()))?;
        out.push(
            u8::from_str_radix(pair, 16)
                .map_err(|_| StoreError::Invalid("the value is not hex".into()))?,
        );
    }
    Ok(out)
}

/// The X25519 shared secret. Low-order public keys produce all zeros, which a
/// real peer never sends; refusing them here keeps the KDF input honest.
pub(super) fn shared_secret(secret: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], StoreError> {
    let shared = MontgomeryPoint(*public).mul_clamped(*secret).to_bytes();
    if shared == [0u8; 32] {
        return Err(StoreError::Invalid(
            "that device agreement key is not usable".into(),
        ));
    }
    Ok(shared)
}

/// The public half of an X25519 agreement keypair. `mul_base_clamped` is the
/// X25519 base-point multiplication, including the clamping of the scalar.
pub fn agreement_public(secret: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
}

/// A fresh X25519 agreement secret from the OS RNG.
pub fn agreement_secret() -> [u8; 32] {
    crypto::random_bytes::<32>()
}

/// AAD of a sealed device key: kind, account, vault, device id.
fn device_aad(meta: &super::VaultMeta, device_id: &str, kind: &str) -> Vec<u8> {
    object_aad(kind, &meta.account_uuid, &meta.vault_uuid, device_id, 1)
}

/// The label the local device registers under. `COMPUTERNAME`/`HOSTNAME` is a
/// real, useful name; the fallback keeps the insert valid when neither exists
/// or the value is all control characters.
fn default_device_name() -> String {
    let raw = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| DEFAULT_DEVICE_NAME.to_string());
    let cleaned: String = raw
        .chars()
        .filter(|ch| !ch.is_control())
        .take(DEVICE_NAME_MAX)
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        DEFAULT_DEVICE_NAME.to_string()
    } else {
        cleaned.to_string()
    }
}

impl Store {
    /// The local device row, if this vault file generated one.
    /// This device's id, or `None` before a keypair exists. Reads the row only:
    /// it needs no key, so the status line can name the device while the vault
    /// is locked instead of claiming there is none.
    pub fn local_device_id(&self) -> Result<Option<String>, StoreError> {
        Ok(self.local_device_row()?.map(|row| row.device_id))
    }

    fn local_device_row(&self) -> Result<Option<LocalRow>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT device_id, signing_pub, agreement_pub, name, created_at,
                        signing_key_wrapped, agreement_key_wrapped
                 FROM devices
                 WHERE signing_key_wrapped IS NOT NULL
                   AND agreement_key_wrapped IS NOT NULL
                 ORDER BY created_at, device_id
                 LIMIT 1",
                [],
                |row| {
                    Ok(LocalRow {
                        device_id: row.get(0)?,
                        signing_pub: row.get(1)?,
                        agreement_pub: row.get(2)?,
                        name: row.get(3)?,
                        created_at: row.get(4)?,
                        signing_key_wrapped: row.get(5)?,
                        agreement_key_wrapped: row.get(6)?,
                    })
                },
            )
            .optional()?)
    }

    fn identity_of(row: &LocalRow) -> DeviceIdentity {
        DeviceIdentity {
            device_id: row.device_id.clone(),
            device_name: row.name.clone(),
            signing_pub: hex(&row.signing_pub),
            agreement_pub: hex(&row.agreement_pub),
            created_at: row.created_at.max(0) as u64,
        }
    }

    /// This device's public keys, generating the keypair on first use.
    ///
    /// Generation happens here rather than at account creation because the
    /// *joining* device has no account yet and still has to show the sending
    /// device what to seal to. Whichever side of an enrolment this file ends
    /// up on, it has exactly one keypair and one device id for its lifetime.
    pub fn device_identity(&self, master: &SymKey) -> Result<DeviceIdentity, StoreError> {
        if let Some(row) = self.local_device_row()? {
            return Ok(Self::identity_of(&row));
        }
        let anchor = self.meta_identity()?;
        let device_id = hex(&crypto::random_bytes::<DEVICE_ID_BYTES>());
        let signing_secret = zeroize::Zeroizing::new(crypto::random_bytes::<KEY_LEN>());
        let agreement_private = zeroize::Zeroizing::new(agreement_secret());
        let signing_pub = SigningKey::from_bytes(&signing_secret)
            .verifying_key()
            .to_bytes();
        let agreement_pub = agreement_public(&agreement_private);
        let signing_key_wrapped = crypto::encrypt(
            master,
            &device_aad(&anchor, &device_id, SIGNING_KEY_KIND),
            &signing_secret[..],
        )?;
        let agreement_key_wrapped = crypto::encrypt(
            master,
            &device_aad(&anchor, &device_id, AGREEMENT_KEY_KIND),
            &agreement_private[..],
        )?;
        let name = default_device_name();
        let created_at = now_millis();
        self.conn().execute(
            "INSERT INTO devices(device_id, signing_pub, agreement_pub, name, created_at,
                                 last_seen, signing_key_wrapped, agreement_key_wrapped)
             VALUES(?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7)",
            params![
                device_id,
                &signing_pub[..],
                &agreement_pub[..],
                name,
                created_at as i64,
                signing_key_wrapped,
                agreement_key_wrapped
            ],
        )?;
        self.local_device_row()?
            .map(|row| Self::identity_of(&row))
            .ok_or_else(|| StoreError::Invalid("this device has no keypair".into()))
    }

    /// The local device's private halves, for the net crate.
    ///
    /// This is the only in-process handover of a device private key. It needs
    /// the unlocked master key, and the caller owns the returned value, which
    /// wipes itself on drop.
    pub fn device_secret_keys(&self, master: &SymKey) -> Result<DeviceSecretKeys, StoreError> {
        let anchor = self.meta_identity()?;
        let row = self
            .local_device_row()?
            .ok_or_else(|| StoreError::Invalid("this device has no keypair yet".into()))?;
        let signing_plain = zeroize::Zeroizing::new(
            crypto::decrypt(
                master,
                &device_aad(&anchor, &row.device_id, SIGNING_KEY_KIND),
                &row.signing_key_wrapped,
            )
            .map_err(|_| {
                StoreError::Invalid(
                    "this device's signing key does not open with this vault".into(),
                )
            })?,
        );
        let agreement_plain = zeroize::Zeroizing::new(
            crypto::decrypt(
                master,
                &device_aad(&anchor, &row.device_id, AGREEMENT_KEY_KIND),
                &row.agreement_key_wrapped,
            )
            .map_err(|_| {
                StoreError::Invalid(
                    "this device's agreement key does not open with this vault".into(),
                )
            })?,
        );
        if signing_plain.len() != KEY_LEN || agreement_plain.len() != KEY_LEN {
            return Err(StoreError::Invalid(
                "this device's key material is malformed".into(),
            ));
        }
        let mut signing_secret = [0u8; KEY_LEN];
        signing_secret.copy_from_slice(&signing_plain[..]);
        let mut agreement_secret = [0u8; KEY_LEN];
        agreement_secret.copy_from_slice(&agreement_plain[..]);
        Ok(DeviceSecretKeys {
            device_id: row.device_id,
            signing_secret,
            agreement_secret,
        })
    }

    /// Re-seal this device's private halves under a new master key. Called by
    /// [`Store::change_password`] inside the rotation transaction; a password
    /// change must not cost the device its identity.
    pub(crate) fn rotate_device_keys(
        &self,
        old_master: &SymKey,
        new_master: &SymKey,
    ) -> Result<(), StoreError> {
        let anchor = self.meta_identity()?;
        let rows: Vec<(String, Vec<u8>, Vec<u8>)> = {
            let mut stmt = self.conn().prepare(
                "SELECT device_id, signing_key_wrapped, agreement_key_wrapped
                 FROM devices
                 WHERE signing_key_wrapped IS NOT NULL
                   AND agreement_key_wrapped IS NOT NULL",
            )?;
            let mapped = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        for (device_id, signing, agreement) in rows {
            let signing_plain = crypto::decrypt(
                old_master,
                &device_aad(&anchor, &device_id, SIGNING_KEY_KIND),
                &signing,
            )?;
            let agreement_plain = crypto::decrypt(
                old_master,
                &device_aad(&anchor, &device_id, AGREEMENT_KEY_KIND),
                &agreement,
            )?;
            let sealed_signing = crypto::encrypt(
                new_master,
                &device_aad(&anchor, &device_id, SIGNING_KEY_KIND),
                &signing_plain,
            )?;
            let sealed_agreement = crypto::encrypt(
                new_master,
                &device_aad(&anchor, &device_id, AGREEMENT_KEY_KIND),
                &agreement_plain,
            )?;
            self.conn().execute(
                "UPDATE devices SET signing_key_wrapped = ?2, agreement_key_wrapped = ?3
                 WHERE device_id = ?1",
                params![device_id, sealed_signing, sealed_agreement],
            )?;
        }
        Ok(())
    }
}
