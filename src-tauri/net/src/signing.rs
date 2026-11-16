//! The signed request: the canonical string, the body digest and the header.
//!
//! A one-character mismatch anywhere here is a `401` with no clue, so the
//! canonical string lives in exactly one function, [`signing_string`], and a
//! unit test pins its bytes against the worked example in `PROTOCOL.md`.
//!
//! ```text
//! kestrel-sync/v1
//! <METHOD>
//! <path?query>
//! <hex(sha256(body))>
//! <unix_seconds>
//! <nonce>
//! ```
//!
//! No trailing newline: the nonce is the last field and cannot contain one.
//! The header is `Kestrel <device_id>.<unix_seconds>.<nonce>.<signature_hex>`.

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Domain separator for the signing string, so a signature minted for another
/// protocol can never be replayed here.
const SIGNING_CONTEXT: &str = "kestrel-sync/v1";
/// The protocol major version this crate implements.
pub(crate) const PROTOCOL_VERSION: &str = "1";
/// Header carrying [`PROTOCOL_VERSION`] on every request.
pub(crate) const PROTOCOL_HEADER: &str = "X-Kestrel-Protocol";
/// The nonce is 16 random bytes, lowercase hex.
const NONCE_BYTES: usize = 16;

/// The exact bytes the device signs. Fields are separated by one newline and
/// there is nothing after the nonce.
pub(crate) fn signing_string(
    method: &str,
    target: &str,
    body_digest_hex: &str,
    timestamp: i64,
    nonce: &str,
) -> String {
    format!("{SIGNING_CONTEXT}\n{method}\n{target}\n{body_digest_hex}\n{timestamp}\n{nonce}")
}

/// Lowercase hex SHA-256 of the raw request body; the digest of an empty body
/// is the SHA-256 of the empty string.
pub(crate) fn body_digest(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// A fresh 16-byte nonce as lowercase hex. Lowercase is required by the
/// service: it keys its replay set on the nonce string, and normalising case
/// would let a captured request be replayed with different capitalisation.
pub(crate) fn nonce() -> String {
    let mut bytes = [0u8; NONCE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub(crate) fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Builds the `Authorization` header for one request with a fresh timestamp
/// and nonce. `target` must be the exact request target that goes on the wire,
/// query included, starting with `/`.
pub(crate) fn authorization(
    key: &SigningKey,
    device_id: &str,
    method: &str,
    target: &str,
    body: &[u8],
) -> String {
    authorization_at(
        key,
        device_id,
        method,
        target,
        body,
        unix_seconds(),
        &nonce(),
    )
}

/// The deterministic core of [`authorization`], so a test can pin the header
/// for a fixed timestamp and nonce. Ed25519 signatures are deterministic.
fn authorization_at(
    key: &SigningKey,
    device_id: &str,
    method: &str,
    target: &str,
    body: &[u8],
    timestamp: i64,
    nonce: &str,
) -> String {
    let canonical = signing_string(method, target, &body_digest(body), timestamp, nonce);
    let signature = key.sign(canonical.as_bytes());
    format!(
        "Kestrel {device_id}.{timestamp}.{nonce}.{}",
        hex::encode(signature.to_bytes())
    )
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signature;

    use super::*;

    /// The worked example from `PROTOCOL.md`: `GET /v1/sync/pull?since=0&limit=200`
    /// with an empty body. This is the test that catches a separator, a
    /// context string or a digest that drifted.
    #[test]
    fn canonical_string_matches_the_protocol_vector() {
        let expected = concat!(
            "kestrel-sync/v1\n",
            "GET\n",
            "/v1/sync/pull?since=0&limit=200\n",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
            "1731686400\n",
            "9f2c4a1b8e6d0f3a5c7b9d1e2f4a6b8c",
        );

        let canonical = signing_string(
            "GET",
            "/v1/sync/pull?since=0&limit=200",
            &body_digest(b""),
            1731686400,
            "9f2c4a1b8e6d0f3a5c7b9d1e2f4a6b8c",
        );

        assert_eq!(canonical.as_bytes(), expected.as_bytes());
        // 15 (context) + 3 (method) + 31 (target) + 64 (digest) + 10 (timestamp)
        // + 32 (nonce) + 5 newlines.
        assert_eq!(canonical.len(), 160);
        assert!(!canonical.ends_with('\n'));
        assert_eq!(canonical.lines().count(), 6);
    }

    #[test]
    fn body_digest_matches_known_sha256_vectors() {
        assert_eq!(
            body_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            body_digest(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    /// The header has the exact shape the service parses, and the signature is
    /// over the vector above, not over a re-derived approximation of it.
    #[test]
    fn authorization_header_signs_the_canonical_bytes() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let device_id = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
        let authorization = authorization_at(
            &key,
            device_id,
            "GET",
            "/v1/sync/pull?since=0&limit=200",
            b"",
            1731686400,
            "9f2c4a1b8e6d0f3a5c7b9d1e2f4a6b8c",
        );

        let prefix =
            "Kestrel 0a1b2c3d4e5f60718293a4b5c6d7e8f9.1731686400.9f2c4a1b8e6d0f3a5c7b9d1e2f4a6b8c.";
        assert!(authorization.starts_with(prefix), "{authorization}");
        let signature_hex = &authorization[prefix.len()..];
        assert_eq!(signature_hex.len(), 128);
        assert!(signature_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));

        let signature = Signature::from_bytes(
            &<[u8; 64]>::try_from(hex::decode(signature_hex).expect("hex")).expect("64 bytes"),
        );
        let canonical = signing_string(
            "GET",
            "/v1/sync/pull?since=0&limit=200",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            1731686400,
            "9f2c4a1b8e6d0f3a5c7b9d1e2f4a6b8c",
        );
        key.verifying_key()
            .verify_strict(canonical.as_bytes(), &signature)
            .expect("the header signature verifies over the canonical string");
    }

    #[test]
    fn nonces_are_fresh_lowercase_hex() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let nonce = nonce();
            assert_eq!(nonce.len(), 32);
            assert!(nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
            assert!(seen.insert(nonce));
        }
    }
}
