//! Kestrel sync service.
//!
//! One binary, one SQLite file. It stores ciphertext and the minimum metadata a
//! merge needs — never a title, a URL, a username, a category, a tag or a field
//! name. The wire contract is `PROTOCOL.md` at the repository root; this crate
//! is the reference implementation of it.
//!
//! Layout:
//!
//! - [`config`] reads the environment, with defaults that work for a local run.
//! - [`clock`] is the vector-clock dominance rule, the whole merge policy.
//! - [`auth`] parses the `Authorization: Kestrel …` header and owns the bounded
//!   replay cache.
//! - [`api`] is the validated request/response surface and the error vocabulary.
//! - [`db`] is the SQLite schema and every query; nothing else touches SQL.
//! - [`service`] routes requests, authenticates and applies the handlers.
//! - [`server`] is the hyper glue: body limits, one task per connection.

pub mod api;
pub mod auth;
pub mod clock;
pub mod config;
pub mod db;
pub mod server;
pub mod service;

pub use config::Config;
pub use server::Server;
pub use service::App;
