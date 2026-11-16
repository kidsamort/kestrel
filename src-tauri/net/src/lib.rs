//! Client for the Kestrel sync protocol.
//!
//! This crate speaks `PROTOCOL.md` and nothing else: it signs requests, calls
//! the endpoints and returns typed results. It never touches a vault, a key
//! hierarchy or a SQLite file — the caller decides what to send and what to do
//! with what comes back.
//!
//! The client's identity lives in [`ClientConfig`]: an account id, a device id
//! and a 32-byte Ed25519 signing key. Every endpoint method fills the identity
//! fields from that config, so a caller cannot register one key and sign with
//! another. Requests are signed byte for byte the way the service verifies
//! them (`kestrel-sync/v1`, method, exact request target, body digest,
//! timestamp, single-use nonce) and every request carries
//! `X-Kestrel-Protocol: 1`.
//!
//! Transport is `ureq` over rustls. `https` is always allowed; `http` is
//! allowed only to a loopback host, or to any host when
//! [`ClientConfig::allow_insecure`] is set, because a plain-http remote would
//! put the vault's metadata and signatures — though not its plaintext — in the
//! clear, and the protocol's replay window only makes sense behind TLS.
//!
//! A failed call is an [`Error`], which distinguishes a rejected signature, a
//! merge conflict, an expired enrolment, a protocol-version mismatch and a
//! broken service. The stable discriminators are the protocol's `error` codes,
//! preserved verbatim.

#![forbid(unsafe_code)]

mod client;
mod config;
mod error;
mod signing;
mod types;

pub use client::SyncClient;
pub use config::{check_base_url, ClientConfig, ConfigError};
pub use error::{ConflictCode, Error, TransportError, UnauthorizedCode};
pub use types::{
    Clock, Conflict, CreateAccountResponse, DeviceInfo, EnrollClaimResponse, PullOp, PullResponse,
    PushOp, PushRequest, PushResponse, StateResponse,
};
