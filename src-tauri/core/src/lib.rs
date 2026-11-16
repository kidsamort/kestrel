//! Kestrel vault core.
//!
//! Deliberately free of any UI toolkit: the same crate backs the desktop app,
//! and can back a CLI or extension host later. Everything secret lives behind
//! this boundary.

pub mod attachments;
pub mod audit;
pub mod crypto;
pub mod generator;
pub mod hello;
pub mod history;
pub mod model;
pub mod portability;
pub mod session;
pub mod store;
pub mod sync;
pub mod totp;
pub mod trash;

pub use model::{Category, Field, Item, ItemSummary};
pub use session::{VaultError, VaultState, VaultStateDto};
pub use store::{Counts, Page, VaultSummary};
