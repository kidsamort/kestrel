//! Vault cryptography.
//!
//! Public standards only, with the parameters stated here so they can be
//! audited without reading the rest of the file:
//!
//! * **Argon2id** (RFC 9106) turns the master password into a 32-byte master
//!   key: 64 MiB of memory, 3 passes, 1 lane, a 16-byte random salt and a
//!   32-byte output. No pepper, no secret parameter, no server pepper.
//! * **HKDF-SHA256** (RFC 5869) separates keys. Every derived key names its
//!   purpose (`kestrel/v1/items`, …) and salts the derivation with the owning
//!   vault id, so a subkey cannot be replayed against another vault.
//! * **XChaCha20-Poly1305** (draft-irtf-cfrg-xchacha) seals every stored
//!   object under a fresh 24-byte random nonce, with the object identity bound
//!   as associated data (`kestrel/v1|kind|account|vault|id|version`), so a
//!   ciphertext cannot be replayed into a different row or an older version.
//!
//! Nothing here ever leaves the process: the UI only ever receives plaintext
//! field values that the user is allowed to see at that moment.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Argon2id work factors. Chosen to be usable on a laptop while staying
/// comfortably above interactive-brute-force territory.
pub const ARGON_M_COST: u32 = 64 * 1024; // 64 MiB
pub const ARGON_T_COST: u32 = 3;
pub const ARGON_P_COST: u32 = 1;
pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key derivation failed")]
    Kdf,
    #[error("encryption failed")]
    Encrypt,
    #[error("authentication failed: wrong key or tampered data")]
    Decrypt,
    #[error("malformed ciphertext")]
    Malformed,
}

/// A 32-byte symmetric key that wipes itself on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymKey([u8; KEY_LEN]);

impl SymKey {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::Malformed);
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Copy the raw key bytes out for a wrapper that has to store them
    /// (Windows Hello enrolment). Crate-private on purpose: the shell crate and
    /// the renderer must never receive a master key in any shape, and the copy
    /// wipes itself when the wrapper is done with it.
    pub(crate) fn to_bytes(&self) -> zeroize::Zeroizing<[u8; KEY_LEN]> {
        zeroize::Zeroizing::new(self.0)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(&self.0).expect("32-byte key is always valid")
    }

    /// Derive a purpose-bound subkey. `salt` binds the subkey to a vault or
    /// item identity, so a ciphertext cannot be replayed into another object.
    pub fn derive(&self, salt: &[u8], purpose: &[u8]) -> Result<SymKey, CryptoError> {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.0);
        let mut out = [0u8; KEY_LEN];
        hk.expand(purpose, &mut out).map_err(|_| CryptoError::Kdf)?;
        Ok(SymKey(out))
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

/// Derive the master key from the user's password.
pub fn derive_master_key(password: &str, salt: &[u8]) -> Result<SymKey, CryptoError> {
    if salt.len() != SALT_LEN {
        return Err(CryptoError::Malformed);
    }
    let params = Params::new(ARGON_M_COST, ARGON_T_COST, ARGON_P_COST, Some(KEY_LEN))
        .map_err(|_| CryptoError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(SymKey(out))
}

/// Encrypt `plaintext` under `key` with additional authenticated data.
/// Output layout: nonce || ciphertext || tag.
pub fn encrypt(key: &SymKey, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let nonce_bytes: [u8; NONCE_LEN] = random_bytes();
    let nonce = XNonce::from_slice(&nonce_bytes);
    let body = key
        .cipher()
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + body.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decrypt(key: &SymKey, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() <= NONCE_LEN {
        return Err(CryptoError::Malformed);
    }
    let (nonce_bytes, body) = blob.split_at(NONCE_LEN);
    key.cipher()
        .decrypt(XNonce::from_slice(nonce_bytes), Payload { msg: body, aad })
        .map_err(|_| CryptoError::Decrypt)
}

/// Canonical additional-authenticated-data for a stored object.
pub fn object_aad(kind: &str, account: &str, vault: &str, id: &str, version: i64) -> Vec<u8> {
    format!("kestrel/v1|{kind}|{account}|{vault}|{id}|{version}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = SymKey::from_slice(&[7u8; KEY_LEN]).unwrap();
        let blob = encrypt(&key, b"aad", b"hello vault").unwrap();
        assert_eq!(decrypt(&key, b"aad", &blob).unwrap(), b"hello vault");
    }

    #[test]
    fn exported_bytes_rebuild_the_same_key() {
        let key = SymKey::from_slice(&[9u8; KEY_LEN]).unwrap();
        let bytes = key.to_bytes();
        assert_eq!(&bytes[..], &[9u8; KEY_LEN]);
        let rebuilt = SymKey::from_slice(&bytes[..]).unwrap();
        let blob = encrypt(&rebuilt, b"aad", b"wrapped").unwrap();
        assert_eq!(decrypt(&key, b"aad", &blob).unwrap(), b"wrapped");
    }

    #[test]
    fn wrong_aad_is_rejected() {
        let key = SymKey::from_slice(&[7u8; KEY_LEN]).unwrap();
        let blob = encrypt(&key, b"aad", b"secret").unwrap();
        assert!(decrypt(&key, b"other", &blob).is_err());
    }

    #[test]
    fn tamper_is_rejected() {
        let key = SymKey::from_slice(&[7u8; KEY_LEN]).unwrap();
        let mut blob = encrypt(&key, b"aad", b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(decrypt(&key, b"aad", &blob).is_err());
    }

    #[test]
    fn subkeys_are_purpose_separated() {
        let master = derive_master_key("correct horse battery staple", &[1u8; SALT_LEN]).unwrap();
        let a = master.derive(b"vault-a", b"kestrel/v1/items").unwrap();
        let b = master.derive(b"vault-b", b"kestrel/v1/items").unwrap();
        let blob = encrypt(&a, b"", b"payload").unwrap();
        assert!(decrypt(&b, b"", &blob).is_err());
    }

    #[test]
    fn kdf_is_deterministic_and_password_bound() {
        let salt = [3u8; SALT_LEN];
        let k1 = derive_master_key("pw-one", &salt).unwrap();
        let k2 = derive_master_key("pw-one", &salt).unwrap();
        let k3 = derive_master_key("pw-two", &salt).unwrap();
        let blob = encrypt(&k1, b"", b"x").unwrap();
        assert_eq!(decrypt(&k2, b"", &blob).unwrap(), b"x");
        assert!(decrypt(&k3, b"", &blob).is_err());
    }
}
