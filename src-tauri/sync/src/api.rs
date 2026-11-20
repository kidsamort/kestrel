//! The wire surface: request shapes, response shapes, validation and the
//! error vocabulary.
//!
//! Every field is validated here, before any handler touches the database. A
//! rejected request never leaves a partial write behind: handlers validate the
//! whole body first and only then open a transaction.

use base64::Engine as _;
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::auth::{self, ID_HEX_LEN};
use crate::clock::Clock;

pub const MAX_PUSH_OPS: usize = 1000;
pub const MAX_CLOCK_ENTRIES: usize = 64;
pub const MAX_ITEM_ID_LEN: usize = 128;
pub const MAX_DEVICE_NAME_LEN: usize = 128;
pub const MAX_SEALED_BYTES: usize = 64 * 1024;
pub const MAX_OFFER_LIFETIME_SECS: i64 = 3600;
pub const MAX_ENROLL_CODE_LEN: usize = 256;
pub const MAX_SIGNING_PUB_HEX: usize = 64;
pub const CODE_HASH_HEX: usize = 64;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A handler failure. The JSON body is `{"error": <code>, "message": <text>}`;
/// the code is stable and is what clients branch on, the message is for a human
/// reading a log or a curl response.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    /// Set only by 405 responses, so the client learns what the route allows.
    pub allow: Option<&'static str>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            code,
            message: message.into(),
            allow: None,
        }
    }

    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        ApiError::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub fn unauthorized(code: &'static str, message: impl Into<String>) -> Self {
        ApiError::new(StatusCode::UNAUTHORIZED, code, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        ApiError::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        ApiError::new(StatusCode::CONFLICT, code, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
    }

    pub fn method_not_allowed(allow: &'static str) -> Self {
        let mut error = ApiError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            format!("this route accepts {allow}"),
        );
        error.allow = Some(allow);
        error
    }
}

impl From<&auth::AuthError> for ApiError {
    fn from(error: &auth::AuthError) -> Self {
        match error {
            auth::AuthError::Missing => ApiError::unauthorized("unauthorized", error.to_string()),
            auth::AuthError::Malformed => ApiError::unauthorized("unauthorized", error.to_string()),
            auth::AuthError::Stale => ApiError::unauthorized("stale_timestamp", error.to_string()),
            auth::AuthError::Replay => ApiError::unauthorized("replay", error.to_string()),
            auth::AuthError::UnknownDevice => {
                ApiError::unauthorized("unknown_device", error.to_string())
            }
            auth::AuthError::BadSignature => {
                ApiError::unauthorized("bad_signature", error.to_string())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAccountRequest {
    pub account_id: String,
    pub device_id: String,
    pub device_signing_pub: String,
    pub device_agreement_pub: String,
    pub device_name: String,
}

#[derive(Debug)]
pub struct NewAccount {
    pub account_id: String,
    pub device_id: String,
    pub signing_pub: [u8; 32],
    pub agreement_pub: [u8; 32],
    pub device_name: String,
}

impl CreateAccountRequest {
    pub fn validate(self) -> Result<NewAccount, ApiError> {
        let account_id = validate_id("account_id", &self.account_id)?;
        let device_id = validate_id("device_id", &self.device_id)?;
        let signing_pub = validate_public_key("device_signing_pub", &self.device_signing_pub)?;
        if !auth::is_valid_public_key(&signing_pub) {
            return Err(ApiError::bad_request(
                "invalid_field",
                "device_signing_pub is not a valid, non-weak Ed25519 public key",
            ));
        }
        let agreement_pub =
            validate_public_key("device_agreement_pub", &self.device_agreement_pub)?;
        let device_name = validate_device_name(self.device_name)?;
        Ok(NewAccount {
            account_id,
            device_id,
            signing_pub,
            agreement_pub,
            device_name,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferRequest {
    pub code_hash: String,
    pub sealed: String,
    pub expires_at: i64,
    pub new_device_id: String,
}

#[derive(Debug)]
pub struct NewOffer {
    pub code_hash: String,
    pub sealed: Vec<u8>,
    pub expires_at: i64,
    pub new_device_id: String,
}

impl OfferRequest {
    pub fn validate(self, now: i64) -> Result<NewOffer, ApiError> {
        let code_hash = validate_fixed_hex("code_hash", &self.code_hash, CODE_HASH_HEX)?;
        let sealed = validate_sealed(&self.sealed)?;
        let new_device_id = validate_id("new_device_id", &self.new_device_id)?;

        if self.expires_at <= now {
            return Err(ApiError::bad_request(
                "invalid_field",
                "expires_at must be in the future",
            ));
        }
        if self.expires_at > now + MAX_OFFER_LIFETIME_SECS {
            return Err(ApiError::bad_request(
                "invalid_field",
                format!("expires_at must be at most {MAX_OFFER_LIFETIME_SECS}s from now"),
            ));
        }

        Ok(NewOffer {
            code_hash,
            sealed,
            expires_at: self.expires_at,
            new_device_id,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRequest {
    pub code: String,
    pub device_id: String,
    pub device_signing_pub: String,
    pub device_agreement_pub: String,
    pub device_name: String,
}

#[derive(Debug)]
pub struct NewClaim {
    pub code: String,
    pub device_id: String,
    pub signing_pub: [u8; 32],
    pub agreement_pub: [u8; 32],
    pub device_name: String,
}

impl ClaimRequest {
    pub fn validate(self) -> Result<NewClaim, ApiError> {
        if self.code.is_empty() || self.code.len() > MAX_ENROLL_CODE_LEN {
            return Err(ApiError::bad_request(
                "invalid_field",
                format!("code must be 1..={MAX_ENROLL_CODE_LEN} characters"),
            ));
        }
        let device_id = validate_id("device_id", &self.device_id)?;
        let signing_pub = validate_public_key("device_signing_pub", &self.device_signing_pub)?;
        if !auth::is_valid_public_key(&signing_pub) {
            return Err(ApiError::bad_request(
                "invalid_field",
                "device_signing_pub is not a valid, non-weak Ed25519 public key",
            ));
        }
        let agreement_pub =
            validate_public_key("device_agreement_pub", &self.device_agreement_pub)?;
        let device_name = validate_device_name(self.device_name)?;
        Ok(NewClaim {
            code: self.code,
            device_id,
            signing_pub,
            agreement_pub,
            device_name,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckRequest {
    pub new_device_id: String,
}

impl AckRequest {
    pub fn validate(self) -> Result<String, ApiError> {
        validate_id("new_device_id", &self.new_device_id)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRequest {
    pub ops: Vec<PushOp>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushOp {
    pub item_id: String,
    pub clock: Clock,
    pub deleted: bool,
    #[serde(default)]
    pub ciphertext: String,
}

#[derive(Debug)]
pub struct IncomingOp {
    pub item_id: String,
    pub clock: Clock,
    pub deleted: bool,
    pub ciphertext: Vec<u8>,
}

impl PushRequest {
    /// Validates every operation before the caller opens a transaction: one bad
    /// op rejects the batch and nothing is written.
    pub fn validate(self) -> Result<Vec<IncomingOp>, ApiError> {
        if self.ops.is_empty() {
            return Err(ApiError::bad_request(
                "invalid_field",
                "ops must not be empty",
            ));
        }
        if self.ops.len() > MAX_PUSH_OPS {
            return Err(ApiError::bad_request(
                "invalid_field",
                format!("at most {MAX_PUSH_OPS} ops per push"),
            ));
        }
        self.ops.into_iter().map(PushOp::validate).collect()
    }
}

impl PushOp {
    fn validate(self) -> Result<IncomingOp, ApiError> {
        let item_id = validate_item_id(&self.item_id)?;
        let clock = validate_clock(self.clock)?;

        let ciphertext = if self.deleted {
            if !self.ciphertext.is_empty() {
                return Err(ApiError::bad_request(
                    "invalid_field",
                    "a tombstone must carry an empty ciphertext",
                ));
            }
            Vec::new()
        } else {
            decode_hex("ciphertext", &self.ciphertext)?
        };

        if !self.deleted && ciphertext.is_empty() {
            return Err(ApiError::bad_request(
                "invalid_field",
                "ciphertext must not be empty for a live op",
            ));
        }

        Ok(IncomingOp {
            item_id,
            clock,
            deleted: self.deleted,
            ciphertext,
        })
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct AccountView {
    pub account_id: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceView {
    pub device_id: String,
    pub device_name: String,
    pub created_at: u64,
    /// Unix seconds when the device was revoked; absent while it is live.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct RevokeView {
    pub device_id: String,
    /// Server time of the revocation, stable across retries.
    pub revoked_at: u64,
}

#[derive(Debug, Serialize)]
pub struct ClaimView {
    pub account_id: String,
    pub sealed: String,
    pub devices: Vec<DeviceView>,
}

#[derive(Debug, Serialize)]
pub struct PushView {
    pub applied: Vec<String>,
    pub conflicts: Vec<ConflictView>,
}

#[derive(Debug, Serialize)]
pub struct ConflictView {
    pub item_id: String,
    pub clock: Clock,
    pub deleted: bool,
    pub ciphertext: String,
}

#[derive(Debug, Serialize)]
pub struct PullView {
    pub ops: Vec<PullOpView>,
    pub next_seq: u64,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
pub struct PullOpView {
    pub seq: u64,
    pub item_id: String,
    pub clock: Clock,
    pub deleted: bool,
    pub ciphertext: String,
}

#[derive(Debug, Serialize)]
pub struct StateView {
    pub account_id: String,
    pub devices: Vec<DeviceView>,
    pub items: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct ErrorView {
    pub error: &'static str,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

pub fn parse_body<T>(body: &[u8]) -> Result<T, ApiError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice(body).map_err(|error| {
        ApiError::bad_request(
            "invalid_body",
            format!("request body is not valid JSON: {error}"),
        )
    })
}

/// Ids are 16 random bytes as lowercase hex, 32 characters. Uppercase is
/// accepted on input and normalised, because "32 hex characters" is how the
/// contract describes them and a client that shouts should not be a 401.
pub fn validate_id(field: &'static str, value: &str) -> Result<String, ApiError> {
    if value.len() != ID_HEX_LEN || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request(
            "invalid_field",
            format!("{field} must be {ID_HEX_LEN} hex characters"),
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_fixed_hex(field: &'static str, value: &str, len: usize) -> Result<String, ApiError> {
    if value.len() != len || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request(
            "invalid_field",
            format!("{field} must be {len} hex characters"),
        ));
    }
    Ok(value.to_ascii_lowercase())
}

pub fn validate_public_key(field: &'static str, value: &str) -> Result<[u8; 32], ApiError> {
    if value.len() != MAX_SIGNING_PUB_HEX {
        return Err(ApiError::bad_request(
            "invalid_field",
            format!("{field} must be {MAX_SIGNING_PUB_HEX} hex characters"),
        ));
    }
    let bytes = decode_hex(field, value)?;
    bytes
        .try_into()
        .map_err(|_| ApiError::bad_request("invalid_field", format!("{field} must be 32 bytes")))
}

fn validate_sealed(value: &str) -> Result<Vec<u8>, ApiError> {
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| ApiError::bad_request("invalid_field", "sealed must be base64"))?;
    if sealed.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_field",
            "sealed must not be empty",
        ));
    }
    if sealed.len() > MAX_SEALED_BYTES {
        return Err(ApiError::bad_request(
            "invalid_field",
            format!("sealed must be at most {MAX_SEALED_BYTES} bytes"),
        ));
    }
    Ok(sealed)
}

fn validate_device_name(value: String) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_field",
            "device_name must not be empty",
        ));
    }
    if trimmed.chars().count() > MAX_DEVICE_NAME_LEN {
        return Err(ApiError::bad_request(
            "invalid_field",
            format!("device_name must be at most {MAX_DEVICE_NAME_LEN} characters"),
        ));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "invalid_field",
            "device_name must not contain control characters",
        ));
    }
    Ok(trimmed.to_string())
}

/// Item ids are opaque client-chosen strings. They are restricted to a URL- and
/// JSON-safe alphabet so an id cannot smuggle a delimiter anywhere.
pub fn validate_item_id(value: &str) -> Result<String, ApiError> {
    if value.is_empty() || value.len() > MAX_ITEM_ID_LEN {
        return Err(ApiError::bad_request(
            "invalid_field",
            format!("item_id must be 1..={MAX_ITEM_ID_LEN} characters"),
        ));
    }
    let allowed = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if !allowed {
        return Err(ApiError::bad_request(
            "invalid_field",
            "item_id may contain only A-Z, a-z, 0-9, '-' and '_'",
        ));
    }
    Ok(value.to_string())
}

/// Normalises a clock: drops zero counters (a zero and an absent counter are
/// the same fact), lowercases device ids, and rejects anything that is not a
/// small map of device ids to counters.
pub fn validate_clock(clock: Clock) -> Result<Clock, ApiError> {
    let mut normalised = Clock::new();
    for (device, counter) in clock {
        if counter == 0 {
            continue;
        }
        if device.len() != ID_HEX_LEN || !device.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ApiError::bad_request(
                "invalid_field",
                "clock keys must be 32 hex characters (device ids)",
            ));
        }
        let device = device.to_ascii_lowercase();
        let entry = normalised.entry(device).or_insert(0);
        *entry = (*entry).max(counter);
    }
    if normalised.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_field",
            "clock must have at least one non-zero counter",
        ));
    }
    if normalised.len() > MAX_CLOCK_ENTRIES {
        return Err(ApiError::bad_request(
            "invalid_field",
            format!("clock must have at most {MAX_CLOCK_ENTRIES} entries"),
        ));
    }
    Ok(normalised)
}

pub fn decode_hex(field: &'static str, value: &str) -> Result<Vec<u8>, ApiError> {
    if value.is_empty() || value.len() % 2 != 0 {
        return Err(ApiError::bad_request(
            "invalid_field",
            format!("{field} must be non-empty, even-length hex"),
        ));
    }
    hex::decode(value)
        .map_err(|_| ApiError::bad_request("invalid_field", format!("{field} must be hex")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_normalised_and_length_checked() {
        let id = validate_id("device_id", "AABBCCDDEEFF00112233445566778899").expect("valid");
        assert_eq!(id, "aabbccddeeff00112233445566778899");
        assert!(validate_id("device_id", "abc").is_err());
        assert!(validate_id("device_id", "zzbbccddeeff00112233445566778899").is_err());
    }

    #[test]
    fn clocks_drop_zeros_and_merge_duplicates() {
        let clock = Clock::from([
            ("AABBCCDDEEFF00112233445566778899".to_string(), 0),
            ("aabbccddeeff00112233445566778899".to_string(), 3),
        ]);
        let clock = validate_clock(clock).expect("valid");
        assert_eq!(clock.len(), 1);
        assert_eq!(clock.values().next(), Some(&3));
        assert!(validate_clock(Clock::new()).is_err());
    }

    #[test]
    fn tombstones_must_not_carry_ciphertext() {
        let request = PushRequest {
            ops: vec![PushOp {
                item_id: "item-1".into(),
                clock: Clock::from([(String::from("aabbccddeeff00112233445566778899"), 1)]),
                deleted: true,
                ciphertext: "00".into(),
            }],
        };
        assert!(request.validate().is_err());
    }
}
