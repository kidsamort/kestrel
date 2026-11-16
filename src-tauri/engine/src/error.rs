//! The engine's failure vocabulary.
//!
//! Every failure is one of a handful of named causes: the vault refused a read
//! or a write, a key refused to open a blob, the service answered with an error,
//! or the engine was handed state it cannot use. Nothing here is a stringly
//! "something went wrong": a caller can tell an offline service from a corrupt
//! body from a missing account without parsing a message.

use kestrel_core::crypto::CryptoError;
use kestrel_core::store::StoreError;

/// Anything [`crate::sync_once`], [`crate::conflict_views`] or
/// [`crate::resolve_conflict`] can fail with.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The vault refused a read or a write.
    #[error("vault error: {0}")]
    Store(#[from] StoreError),
    /// A body or a key failed to open, or a body was malformed.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    /// The sync service answered with an error, or the transport failed. Boxed
    /// because the transport error is the largest thing the net crate produces
    /// and the enum is passed in every `Result` in this crate.
    #[error("sync service error: {0}")]
    Wire(Box<kestrel_net::Error>),
    /// The vault file has no account, so there is nothing to sync under.
    #[error("this vault has no sync account; create one or join one first")]
    NoAccount,
    /// The file holds more than one vault. Sync is one vault per account, and a
    /// pulled item cannot say which vault it belongs to, so the engine refuses
    /// rather than move items between vaults.
    #[error("sync needs a vault file with a single vault; this one holds several")]
    MultipleVaults,
    /// The account bound to the vault or the client is not the one the call is
    /// for. Sealing a body under the wrong account would produce a blob no
    /// device could open, so the mismatch is refused up front.
    #[error("account mismatch: this call is for {given}, the {bound_by} belongs to {found}")]
    AccountMismatch {
        /// The account id the caller passed in the context.
        given: String,
        /// Which side disagreed: `vault` or `client`.
        bound_by: &'static str,
        /// The account id that side is actually bound to.
        found: String,
    },
    /// The stored cursor is present but cannot be read as a sequence number.
    /// A malformed cursor is an error, never a silent `0`: restarting from zero
    /// would re-read the whole log and hide why the state was wrong.
    #[error("the stored sync cursor {0:?} is not a u64")]
    Cursor(String),
    /// A hex field (a ciphertext, a stored id) does not decode.
    #[error("invalid hex: {0}")]
    Hex(String),
    /// A value on the wire or in the store contradicts the protocol: a live op
    /// without a ciphertext, a tombstone with one, a `next_seq` that goes
    /// backwards, an id the service reports that was not in the batch.
    #[error("malformed sync payload: {0}")]
    Payload(String),
    /// [`crate::resolve_conflict`] was called for an item with no stored
    /// conflict. There is nothing to resolve.
    #[error("no unresolved conflict is stored for item {0}")]
    NoConflict(String),
}

impl From<kestrel_net::Error> for EngineError {
    fn from(error: kestrel_net::Error) -> Self {
        EngineError::Wire(Box::new(error))
    }
}
