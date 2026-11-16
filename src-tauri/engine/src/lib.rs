//! The sync engine: one vault file, one account, one server.
//!
//! This crate is the only place that holds both the vault (`kestrel-core`) and
//! the wire (`kestrel-net`) at once. It pulls remote operations, opens them
//! with the account key, merges them into the local items field by field, and
//! pushes what is left. Neither dependency knows about the other: the store has
//! no network code and the client has no vault code.
//!
//! Nothing here runs on its own. A caller decides when to sync and owns the
//! master key, the account key and the device identity for the length of the
//! call.
//!
//! # Timing
//!
//! The crate also carries the policy the background loop follows: how often an
//! idle vault syncs, how far a failing service backs off, and how long a burst
//! of local writes is coalesced ([`Schedule`], [`next_delay`],
//! [`write_debounce_secs`]). The loop itself belongs to the desktop shell,
//! because it needs the app handle and the command layer.
//!
//! # The loop
//!
//! [`sync_once`] runs at most three pull-then-push rounds and stops as soon as
//! a round changes nothing. A pull page is applied operation by operation
//! against the item-level clock; a push sends the dirty rows the store already
//! tracks. After the run the cursor, `last_sync_at` and the status line are
//! written.
//!
//! # What the engine guarantees
//!
//! * **No silent loss.** A local write that is pending stays pending until the
//!   server accepts it. A concurrent remote copy is never discarded: if the
//!   merge cannot settle every field, both sealed bodies are stored and the
//!   item is reported through [`conflict_views`].
//! * **No timestamp arbitration.** Only the version vectors decide; a device
//!   with a wrong system clock cannot roll back a password.
//! * **A merge dominates both sides.** The clock returned by the merge is the
//!   pointwise maximum of both item clocks plus one counter for this device, so
//!   the push that follows settles the server-side conflict.
//! * **Idempotence.** The cursor is exclusive and persisted after each page, so
//!   a second [`sync_once`] with nothing to do pulls nothing and pushes nothing.
//! * **Deletion is a field.** A tombstone applies only when it dominates the
//!   item; a delete concurrent with an edit is a conflict with "deleted" as the
//!   differing path.
//!
//! # Attribution and the baseline
//!
//! The store keeps the sealed body the server last acknowledged next to the
//! item's clock. A local edit only bumps the item clock, so the engine diffs
//! the current item against that baseline and gives the new clock only to the
//! paths whose value moved. Without it a disjoint edit would look like a change
//! to every field and would be reported as a conflict.

#![forbid(unsafe_code)]

mod codec;
mod conflict;
mod engine;
mod error;
mod schedule;

pub use conflict::{conflict_views, resolve_conflict, ConflictField, ConflictView, ResolveChoice};
pub use engine::{sync_once, SyncContext, SyncReport};
pub use error::EngineError;
pub use schedule::{next_delay, write_debounce_secs, Schedule};
