//! Typed failures.
//!
//! The service answers with a status and a stable `error` code; clients branch
//! on the code, never on the human message. This module keeps that shape:
//! [`Error`] has one variant per failure class, the protocol's code is always
//! preserved (recognised ones as enums, unknown ones as [`UnauthorizedCode::Other`]
//! / [`ConflictCode::Other`]), and the server's own message is carried through
//! for a log line or a settings screen.
//!
//! The classification is:
//!
//! | status | variant |
//! |---|---|
//! | `400`, `403` | [`Error::Rejected`] |
//! | `401` | [`Error::Unauthorized`] |
//! | `409` | [`Error::Conflict`] |
//! | `426` | [`Error::ProtocolVersion`] |
//! | anything else non-2xx | [`Error::Server`] |
//! | no HTTP response at all | [`Error::Transport`] |

use std::fmt;

/// The `error` code of a `401`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnauthorizedCode {
    /// The header is missing or unparseable.
    Unauthorized,
    /// The device id is not registered.
    UnknownDevice,
    /// The signature does not verify.
    BadSignature,
    /// The timestamp is outside the 300-second window.
    StaleTimestamp,
    /// The nonce was already used by this device.
    Replay,
    /// A code from a newer revision of the protocol.
    Other(String),
}

impl UnauthorizedCode {
    pub fn as_str(&self) -> &str {
        match self {
            UnauthorizedCode::Unauthorized => "unauthorized",
            UnauthorizedCode::UnknownDevice => "unknown_device",
            UnauthorizedCode::BadSignature => "bad_signature",
            UnauthorizedCode::StaleTimestamp => "stale_timestamp",
            UnauthorizedCode::Replay => "replay",
            UnauthorizedCode::Other(code) => code,
        }
    }
}

impl From<&str> for UnauthorizedCode {
    fn from(code: &str) -> Self {
        match code {
            "unauthorized" => UnauthorizedCode::Unauthorized,
            "unknown_device" => UnauthorizedCode::UnknownDevice,
            "bad_signature" => UnauthorizedCode::BadSignature,
            "stale_timestamp" => UnauthorizedCode::StaleTimestamp,
            "replay" => UnauthorizedCode::Replay,
            other => UnauthorizedCode::Other(other.to_string()),
        }
    }
}

impl fmt::Display for UnauthorizedCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `error` code of a `409`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictCode {
    /// `create_account`: the account id is already registered.
    AccountExists,
    /// `create_account`: the device id belongs to another account.
    DeviceConflict,
    /// `offer` or `claim`: the device is (or was) already enrolled.
    AlreadyEnrolled,
    /// A code from a newer revision of the protocol.
    Other(String),
}

impl ConflictCode {
    pub fn as_str(&self) -> &str {
        match self {
            ConflictCode::AccountExists => "account_exists",
            ConflictCode::DeviceConflict => "device_conflict",
            ConflictCode::AlreadyEnrolled => "already_enrolled",
            ConflictCode::Other(code) => code,
        }
    }
}

impl From<&str> for ConflictCode {
    fn from(code: &str) -> Self {
        match code {
            "account_exists" => ConflictCode::AccountExists,
            "device_conflict" => ConflictCode::DeviceConflict,
            "already_enrolled" => ConflictCode::AlreadyEnrolled,
            other => ConflictCode::Other(other.to_string()),
        }
    }
}

impl fmt::Display for ConflictCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A call that never produced a protocol answer.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The request could not be sent or the connection failed. `ureq` also
    /// reports a malformed URL here, which construction already prevents.
    #[error("could not reach the sync service: {0}")]
    Io(#[from] ureq::Transport),
    /// The response body could not be read from the socket.
    #[error("could not read the response: {0}")]
    Read(#[from] std::io::Error),
    /// A `2xx` body was not the JSON the protocol promises.
    #[error("the response body is not valid JSON: {0}")]
    Decode(#[from] serde_json::Error),
    /// A request body could not be serialised. Every request type in this crate
    /// is a plain JSON object, so this is a bug rather than a server condition.
    #[error("the request body could not be serialised: {0}")]
    Encode(serde_json::Error),
}

/// Every way a call can fail.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `401`: the request was not authenticated.
    #[error("unauthorized ({code}): {message}")]
    Unauthorized {
        code: UnauthorizedCode,
        message: String,
    },
    /// `409`: the request collides with existing state.
    #[error("conflict ({code}): {message}")]
    Conflict { code: ConflictCode, message: String },
    /// `400` or `403`: the request was well-formed HTTP but refused.
    #[error("rejected ({code}): {message}")]
    Rejected { code: String, message: String },
    /// `426`: the service does not speak this protocol major version.
    #[error("protocol version mismatch: {message}")]
    ProtocolVersion {
        /// The stable `error` code, `unsupported_protocol` in v1.
        code: String,
        /// The version the service reported in `X-Kestrel-Protocol`, if any.
        server_protocol: Option<String>,
        message: String,
    },
    /// The request never reached the service, or its answer was unreadable.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// A value the caller supplied is not a valid client input. Endpoint methods
    /// that take an identifier validate it themselves; construction failures
    /// still return [`crate::ConfigError`] directly.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// Any other non-2xx answer, including `5xx`, `404`, `405` and `413`.
    #[error("the service answered HTTP {status} ({code}): {message}")]
    Server {
        status: u16,
        code: String,
        message: String,
    },
}
