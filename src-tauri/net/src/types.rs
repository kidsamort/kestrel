//! Wire types, with the field names `PROTOCOL.md` uses.
//!
//! Request structs serialise to exactly the members the service accepts (it
//! rejects unknown request members, so a stray field is a `400`). Response
//! structs deliberately do **not** deny unknown fields: the protocol promises
//! that minor versions only add optional request members and new response
//! members, and a client that ignored a future member would be brittle for no
//! reason.
//!
//! Opaque values keep their wire encoding. `ciphertext` is lowercase hex and
//! `sealed` is standard base64, because the client's key hierarchy — not this
//! crate — is what turns them into bytes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A version vector: device id to logical counter.
///
/// `BTreeMap` keeps the JSON encoding canonical (sorted keys), so an item's
/// clock has one representation on the wire. Zero counters mean "nothing
/// written" and are dropped by the service; a client should not send them.
pub type Clock = BTreeMap<String, u64>;

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// `POST /v1/sync/push` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PushRequest {
    /// 1..=1000 operations. One invalid operation rejects the whole batch.
    pub ops: Vec<PushOp>,
}

/// One operation in a push.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PushOp {
    /// Opaque client-chosen id, 1..=128 characters `[A-Za-z0-9_-]`.
    pub item_id: String,
    pub clock: Clock,
    /// `true` is a tombstone and must carry an empty `ciphertext`.
    pub deleted: bool,
    /// The sealed item body as lowercase hex; empty for a tombstone.
    pub ciphertext: String,
}

impl PushOp {
    /// A live write: a non-empty ciphertext is required.
    pub fn live(item_id: impl Into<String>, clock: Clock, ciphertext: impl Into<String>) -> PushOp {
        PushOp {
            item_id: item_id.into(),
            clock,
            deleted: false,
            ciphertext: ciphertext.into(),
        }
    }

    /// A delete. The service rejects a tombstone carrying a ciphertext, so the
    /// constructor cannot build one.
    pub fn tombstone(item_id: impl Into<String>, clock: Clock) -> PushOp {
        PushOp {
            item_id: item_id.into(),
            clock,
            deleted: true,
            ciphertext: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// `POST /v1/accounts` response (`201`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CreateAccountResponse {
    pub account_id: String,
}

/// A device as `claim` and `state` report it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub created_at: u64,
    /// Unix seconds when the account owner revoked this device, absent while it
    /// is live. A server revision that predates the endpoint omits the member.
    #[serde(default)]
    pub revoked_at: Option<u64>,
}

/// `POST /v1/enroll/claim` response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct EnrollClaimResponse {
    pub account_id: String,
    /// The sealed account key exactly as offered, base64.
    pub sealed: String,
    /// The account's devices at claim time, excluding the claiming device.
    pub devices: Vec<DeviceInfo>,
}

/// `POST /v1/sync/push` response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PushResponse {
    /// Item ids whose stored state now equals the pushed operation.
    pub applied: Vec<String>,
    /// The stored operations the service kept because the clocks were
    /// concurrent. Merge, then push a clock that dominates both.
    pub conflicts: Vec<Conflict>,
}

/// A stored operation returned in [`PushResponse::conflicts`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Conflict {
    pub item_id: String,
    pub clock: Clock,
    pub deleted: bool,
    /// The stored row's ciphertext, hex; empty for a tombstone.
    pub ciphertext: String,
}

/// `GET /v1/sync/pull` response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PullResponse {
    pub ops: Vec<PullOp>,
    /// The last `seq` in the page, or `since` when the page is empty. Pass it
    /// as the next `since`.
    pub next_seq: u64,
    pub has_more: bool,
}

/// One change-log row.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PullOp {
    pub seq: u64,
    pub item_id: String,
    pub clock: Clock,
    pub deleted: bool,
    /// Hex; empty for a tombstone.
    pub ciphertext: String,
}

/// `GET /v1/sync/state` response: the settings-screen summary.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StateResponse {
    pub account_id: String,
    pub devices: Vec<DeviceInfo>,
    /// Row count, tombstones included.
    pub items: u64,
    /// Total ciphertext size in bytes.
    pub bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_ops_use_the_protocol_field_names() {
        let mut clock = Clock::new();
        clock.insert("0a1b2c3d4e5f60718293a4b5c6d7e8f9".to_string(), 3);

        let live = PushOp::live("item-1", clock.clone(), "aabb");
        assert_eq!(
            serde_json::to_string(&live).expect("serialises"),
            r#"{"item_id":"item-1","clock":{"0a1b2c3d4e5f60718293a4b5c6d7e8f9":3},"deleted":false,"ciphertext":"aabb"}"#
        );

        let tombstone = PushOp::tombstone("item-1", clock);
        assert_eq!(
            serde_json::to_string(&tombstone).expect("serialises"),
            r#"{"item_id":"item-1","clock":{"0a1b2c3d4e5f60718293a4b5c6d7e8f9":3},"deleted":true,"ciphertext":""}"#
        );
    }

    #[test]
    fn responses_ignore_members_from_a_newer_minor_version() {
        let response: PushResponse = serde_json::from_str(
            r#"{"applied":["a"],"conflicts":[],"retry_after":1}"#,
        )
        .expect("unknown response members are ignored");
        assert_eq!(response.applied, ["a"]);
    }
}
