//! Request authentication and replay protection.
//!
//! Every authenticated request carries
//!
//! ```text
//! Authorization: Kestrel <device_id>.<unix_seconds>.<nonce_hex>.<sig_hex>
//! ```
//!
//! and the signature covers the method, the exact request target (path and
//! query as sent), the SHA-256 of the body, the timestamp and the nonce. The
//! `kestrel-sync/v1` prefix is a domain separator: a signature minted for
//! another protocol can never be replayed here.
//!
//! Replay protection is in memory and bounded per device. It is not durable: a
//! request captured in the last [`MAX_SKEW_SECS`] seconds can be replayed once
//! after the service restarts, which is recorded in `PROTOCOL.md` rather than
//! hidden. Making it durable would put a write on the hot path of every read.

use std::collections::{HashMap, HashSet, VecDeque};

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Domain separator for the signing string.
pub const SIGNING_CONTEXT: &str = "kestrel-sync/v1";
/// Accepted clock skew, in seconds, in either direction.
pub const MAX_SKEW_SECS: i64 = 300;
/// The nonce is 16 random bytes, lowercase hex: 32 characters.
pub const NONCE_HEX_LEN: usize = 32;
/// Ids are 16 random bytes, lowercase hex: 32 characters.
pub const ID_HEX_LEN: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("the Authorization header is missing")]
    Missing,
    #[error("the Authorization header is malformed")]
    Malformed,
    #[error("the request timestamp is outside the {MAX_SKEW_SECS}s window")]
    Stale,
    #[error("this nonce was already used")]
    Replay,
    #[error("the device is unknown")]
    UnknownDevice,
    #[error("the signature does not verify")]
    BadSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub device_id: String,
    pub timestamp: i64,
    pub nonce: String,
    pub signature: [u8; 64],
}

/// Parses the header without touching the network or the database. Everything
/// here is shape checking; [`verify`] proves possession of the key.
pub fn parse(header: &str) -> Result<Credentials, AuthError> {
    let (scheme, token) = header.split_once(' ').ok_or(AuthError::Malformed)?;
    if !scheme.eq_ignore_ascii_case("Kestrel") {
        return Err(AuthError::Malformed);
    }
    let token = token.trim();

    let mut parts = token.split('.');
    let device_id = parts.next().ok_or(AuthError::Malformed)?;
    let timestamp = parts.next().ok_or(AuthError::Malformed)?;
    let nonce = parts.next().ok_or(AuthError::Malformed)?;
    let signature = parts.next().ok_or(AuthError::Malformed)?;
    if parts.next().is_some() {
        return Err(AuthError::Malformed);
    }

    if device_id.len() != ID_HEX_LEN || !device_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AuthError::Malformed);
    }
    let device_id = device_id.to_ascii_lowercase();
    let timestamp: i64 = timestamp.parse().map_err(|_| AuthError::Malformed)?;
    if timestamp < 0 {
        return Err(AuthError::Malformed);
    }
    if nonce.len() != NONCE_HEX_LEN || !is_lower_hex(nonce) {
        return Err(AuthError::Malformed);
    }
    if signature.len() != 128 {
        return Err(AuthError::Malformed);
    }
    let bytes = hex::decode(signature).map_err(|_| AuthError::Malformed)?;
    let signature: [u8; 64] = bytes.try_into().map_err(|_| AuthError::Malformed)?;

    Ok(Credentials {
        device_id,
        timestamp,
        nonce: nonce.to_string(),
        signature,
    })
}

/// The exact byte string that gets signed, one field per line. The trailing
/// newline is deliberately absent: the nonce is the final field and cannot
/// contain a newline, so the encoding stays unambiguous.
pub fn signing_string(
    method: &str,
    target: &str,
    body_sha256_hex: &str,
    timestamp: i64,
    nonce: &str,
) -> String {
    format!("{SIGNING_CONTEXT}\n{method}\n{target}\n{body_sha256_hex}\n{timestamp}\n{nonce}")
}

/// Lowercase hex SHA-256 of the raw request body.
pub fn body_digest(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// `verify_strict` rejects small-order public keys and non-canonical
/// signatures, so a device cannot register a key that verifies everything.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    key.verify_strict(message, &Signature::from_bytes(signature))
        .is_ok()
}

/// Also used to validate a key at registration time: `verify_strict` refuses
/// signatures under a small-order (weak) key, so such a key is refused before it
/// is stored. Otherwise the server would hold a device that can never
/// authenticate and give the client no explanation.
pub fn is_valid_public_key(bytes: &[u8; 32]) -> bool {
    match VerifyingKey::from_bytes(bytes) {
        Ok(key) => !key.is_weak(),
        Err(_) => false,
    }
}

pub fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Bounded per-device nonce memory.
///
/// `HashMap<device, VecDeque<(timestamp, nonce)>>` plus a `HashSet` for the
/// membership test. Entries older than the skew window are dead (a request
/// that old fails the timestamp check anyway) and are pruned on every insert;
/// the per-device cap is the second bound, for a device that floods requests.
pub struct ReplayCache {
    window_secs: i64,
    per_device_limit: usize,
    devices: HashMap<String, DeviceNonces>,
}

#[derive(Default)]
struct DeviceNonces {
    order: VecDeque<(i64, String)>,
    seen: HashSet<String>,
}

impl ReplayCache {
    pub fn new(window_secs: i64, per_device_limit: usize) -> Self {
        ReplayCache {
            window_secs,
            per_device_limit: per_device_limit.max(1),
            devices: HashMap::new(),
        }
    }

    /// True if this nonce was already accepted for this device. Prunes the
    /// window as a side effect, so the cache cannot grow with request count.
    pub fn contains(&mut self, device_id: &str, nonce: &str, now: i64) -> bool {
        let window = self.window_secs;
        match self.devices.get_mut(device_id) {
            None => false,
            Some(entry) => {
                entry.prune(now, window);
                entry.seen.contains(nonce)
            }
        }
    }

    /// Records a nonce that already passed signature verification.
    pub fn insert(&mut self, device_id: &str, timestamp: i64, nonce: String, now: i64) {
        let window = self.window_secs;
        let limit = self.per_device_limit;
        let entry = self.devices.entry(device_id.to_string()).or_default();
        entry.prune(now, window);
        while entry.order.len() >= limit {
            if let Some((_, evicted)) = entry.order.pop_front() {
                entry.seen.remove(&evicted);
            }
        }
        entry.seen.insert(nonce.clone());
        entry.order.push_back((timestamp, nonce));
    }

    #[cfg(test)]
    fn len(&self, device_id: &str) -> usize {
        self.devices
            .get(device_id)
            .map_or(0, |entry| entry.order.len())
    }
}

impl DeviceNonces {
    fn prune(&mut self, now: i64, window_secs: i64) {
        let oldest = now.saturating_sub(window_secs);
        while self
            .order
            .front()
            .is_some_and(|(timestamp, _)| *timestamp < oldest)
        {
            if let Some((_, nonce)) = self.order.pop_front() {
                self.seen.remove(&nonce);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const DEVICE: &str = "00112233445566778899aabbccddeeff";

    #[test]
    fn parses_a_well_formed_header() {
        let signature = "0".repeat(128);
        let header = format!(
            "Kestrel {DEVICE}.1700000000.{}.{signature}",
            "1".repeat(NONCE_HEX_LEN)
        );
        let parsed = parse(&header).expect("parses");
        assert_eq!(parsed.device_id, DEVICE);
        assert_eq!(parsed.timestamp, 1_700_000_000);
        assert_eq!(parsed.nonce.len(), NONCE_HEX_LEN);
    }

    #[test]
    fn rejects_short_nonce_and_wrong_scheme() {
        let signature = "0".repeat(128);
        let short = format!("Kestrel {DEVICE}.1.abc.{signature}");
        assert_eq!(parse(&short), Err(AuthError::Malformed));
        let basic = format!("Basic {DEVICE}.1.{}.{signature}", "1".repeat(NONCE_HEX_LEN));
        assert_eq!(parse(&basic), Err(AuthError::Malformed));
    }

    #[test]
    fn signature_round_trip() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let digest = body_digest(b"{}");
        let message = signing_string(
            "POST",
            "/v1/accounts",
            &digest,
            1_700_000_000,
            &"a".repeat(32),
        );
        let signature = key.sign(message.as_bytes());
        assert!(verify(
            &key.verifying_key().to_bytes(),
            message.as_bytes(),
            &signature.to_bytes()
        ));
        assert!(!verify(
            &key.verifying_key().to_bytes(),
            b"kestrel-sync/v1\nPOST\n/v1/accounts\nx\n1\nb",
            &signature.to_bytes()
        ));
    }

    #[test]
    fn replay_cache_bounds_and_prunes() {
        let mut cache = ReplayCache::new(MAX_SKEW_SECS, 2);
        cache.insert(DEVICE, 1000, "a".repeat(32), 1000);
        assert!(cache.contains(DEVICE, &"a".repeat(32), 1000));
        cache.insert(DEVICE, 1000, "b".repeat(32), 1000);
        cache.insert(DEVICE, 1000, "c".repeat(32), 1000);
        assert_eq!(cache.len(DEVICE), 2);
        // The oldest nonce was evicted to respect the cap.
        assert!(!cache.contains(DEVICE, &"a".repeat(32), 1000));
        // Far past the window, everything is pruned.
        assert!(!cache.contains(DEVICE, &"c".repeat(32), 10_000));
        assert_eq!(cache.len(DEVICE), 0);
    }
}
