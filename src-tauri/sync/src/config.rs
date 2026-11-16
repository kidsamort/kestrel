//! Process configuration.
//!
//! Configuration is environment-only on purpose: a container gets its settings
//! from the orchestrator's environment, and there is no second, shadowing
//! config file to keep in sync with it. Every key has a default that keeps a
//! local `cargo run -p kestrel-sync` safe: loopback only, one file in the
//! current directory, 4 MiB bodies, no account cap.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Loopback by default: a self-hoster who forgets to set the address does not
/// accidentally expose a plain-HTTP vault service on a public interface. The
/// container image overrides this with `0.0.0.0:8787`.
pub const DEFAULT_ADDR: &str = "127.0.0.1:8787";
pub const DEFAULT_DB: &str = "kestrel-sync.db";
pub const DEFAULT_BLOBS: &str = "blobs";
pub const DEFAULT_MAX_BODY: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_ACCOUNTS: u64 = 0;

pub const ADDR_ENV: &str = "KESTREL_SYNC_ADDR";
pub const DB_ENV: &str = "KESTREL_SYNC_DB";
pub const BLOBS_ENV: &str = "KESTREL_SYNC_BLOBS";
pub const MAX_BODY_ENV: &str = "KESTREL_SYNC_MAX_BODY";
pub const MAX_ACCOUNTS_ENV: &str = "KESTREL_SYNC_MAX_ACCOUNTS";

/// A body limit below this cannot hold a single reasonable push; a lower value
/// is far more likely to be a units mistake than an intention.
pub const MIN_MAX_BODY: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub addr: SocketAddr,
    pub db_path: PathBuf,
    /// Where ciphertext blobs live. Defaults to `blobs/` next to the database,
    /// so one mounted volume holds both halves of the state.
    pub blob_dir: PathBuf,
    pub max_body: usize,
    /// `0` means unlimited.
    pub max_accounts: u64,
}

impl Default for Config {
    fn default() -> Self {
        let db_path = PathBuf::from(DEFAULT_DB);
        Config {
            addr: DEFAULT_ADDR.parse().expect("valid default address"),
            blob_dir: default_blob_dir(&db_path),
            db_path,
            max_body: DEFAULT_MAX_BODY,
            max_accounts: DEFAULT_MAX_ACCOUNTS,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{key} must be <host>:<port>, got {value:?}")]
    Addr { key: &'static str, value: String },
    #[error("{key} must be a non-negative integer, got {value:?}")]
    Number { key: &'static str, value: String },
    #[error("{key} must be at least {MIN_MAX_BODY} bytes, got {value}")]
    TooSmall { key: &'static str, value: usize },
}

impl Config {
    /// Reads the four documented keys, falling back to [`Config::default`] for
    /// each one that is unset. An empty value is treated as unset so a
    /// `KESTREL_SYNC_MAX_ACCOUNTS=` line in a compose file is not an error.
    pub fn from_env() -> Result<Config, ConfigError> {
        let addr = match non_empty(ADDR_ENV) {
            Some(value) => value.parse().map_err(|_| ConfigError::Addr {
                key: ADDR_ENV,
                value,
            })?,
            None => DEFAULT_ADDR.parse().expect("valid default address"),
        };

        let db_path = non_empty(DB_ENV).map_or_else(|| PathBuf::from(DEFAULT_DB), PathBuf::from);
        let blob_dir = match non_empty(BLOBS_ENV) {
            Some(value) => PathBuf::from(value),
            None => default_blob_dir(&db_path),
        };

        let max_body = match non_empty(MAX_BODY_ENV) {
            Some(value) => {
                let parsed: usize = value.parse().map_err(|_| ConfigError::Number {
                    key: MAX_BODY_ENV,
                    value,
                })?;
                if parsed < MIN_MAX_BODY {
                    return Err(ConfigError::TooSmall {
                        key: MAX_BODY_ENV,
                        value: parsed,
                    });
                }
                parsed
            }
            None => DEFAULT_MAX_BODY,
        };

        let max_accounts = match non_empty(MAX_ACCOUNTS_ENV) {
            Some(value) => value.parse().map_err(|_| ConfigError::Number {
                key: MAX_ACCOUNTS_ENV,
                value,
            })?,
            None => DEFAULT_MAX_ACCOUNTS,
        };

        Ok(Config {
            addr,
            db_path,
            blob_dir,
            max_body,
            max_accounts,
        })
    }
}

/// `blobs/` beside the database, unless the database is a bare filename — then
/// it is relative to the working directory, like the database itself.
fn default_blob_dir(db_path: &Path) -> PathBuf {
    match db_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(DEFAULT_BLOBS),
        _ => PathBuf::from(DEFAULT_BLOBS),
    }
}

fn non_empty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        _ => None,
    }
}
