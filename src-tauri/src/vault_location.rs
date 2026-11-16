//! Which vault file the user picked last.
//!
//! A vault belongs to the user: they name it and place it. This module only
//! remembers where it is, in a tiny JSON record inside the app data directory.
//! The record lives outside the vault on purpose — it has to be readable before
//! any vault is open, and it carries no secret. A missing, unreadable or
//! malformed record simply means "no vault yet", so a hand-edited config can
//! never stop the app from starting.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The record's name. `last()` is the only reader, so the file can be a plain
/// JSON object a user can inspect.
const FILE_NAME: &str = "vault_location.json";

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredLocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_vault: Option<String>,
}

/// The remembered vault path, rooted at the app's data directory.
pub struct VaultLocation {
    config_dir: PathBuf,
}

impl VaultLocation {
    pub fn new(config_dir: PathBuf) -> VaultLocation {
        VaultLocation { config_dir }
    }

    fn config_file(&self) -> PathBuf {
        self.config_dir.join(FILE_NAME)
    }

    /// The vault the user opened last, or `None` when there is none yet.
    ///
    /// A pure read: it never creates, adopts or repairs anything, so calling it
    /// on every start is free and its answer is exactly what is on disk.
    pub fn last(&self) -> Option<PathBuf> {
        let text = std::fs::read_to_string(self.config_file()).ok()?;
        let stored: StoredLocation = serde_json::from_str(&text).ok()?;
        let path = PathBuf::from(stored.last_vault?);
        if path.as_os_str().is_empty() {
            return None;
        }
        Some(path)
    }

    /// Remember `path` as the vault to open next time.
    ///
    /// The record is written to a temporary file in the same directory and
    /// renamed over the old one, so an interrupted write leaves the previous
    /// record intact instead of a truncated path.
    pub fn remember(&self, path: &Path) -> Result<(), String> {
        let text = path
            .to_str()
            .ok_or_else(|| "the vault path is not valid unicode".to_string())?;
        std::fs::create_dir_all(&self.config_dir).map_err(|failure| {
            format!(
                "cannot create {}: {failure}",
                self.config_dir.display()
            )
        })?;
        let record = StoredLocation {
            last_vault: Some(text.to_string()),
        };
        let json = serde_json::to_vec(&record)
            .map_err(|failure| format!("cannot encode the vault location: {failure}"))?;
        let temp = self
            .config_dir
            .join(format!("{FILE_NAME}.{}.tmp", std::process::id()));
        std::fs::write(&temp, json).map_err(|failure| {
            let _ = std::fs::remove_file(&temp);
            format!("cannot write {}: {failure}", temp.display())
        })?;
        std::fs::rename(&temp, self.config_file()).map_err(|failure| {
            let _ = std::fs::remove_file(&temp);
            format!("cannot store the vault location: {failure}")
        })
    }

    /// Drop the remembered path. Used when a switch failed and there was no
    /// previous vault to restore: the config must not name a file the core is
    /// not on.
    pub fn forget(&self) -> Result<(), String> {
        std::fs::remove_file(self.config_file()).map_err(|failure| {
            if failure.kind() == std::io::ErrorKind::NotFound {
                String::new()
            } else {
                format!("cannot forget the vault location: {failure}")
            }
        })
    }

    /// Where a new vault should start: `Documents/Kestrel`, created if missing.
    ///
    /// Best effort by design — a folder that cannot be created still names the
    /// place the file picker should open at, and the picker reports the real
    /// error when the user actually creates the vault.
    pub fn default_dir(&self) -> PathBuf {
        let dir = documents_dir()
            .unwrap_or_else(|| self.config_dir.clone())
            .join("Kestrel");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }
}

/// The shell's Documents folder. Windows exposes it under the user profile,
/// which is where the picker should start; the config directory is the fallback
/// when the environment is stripped (a service or a test).
fn documents_dir() -> Option<PathBuf> {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))?;
    Some(PathBuf::from(home).join("Documents"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kestrel-location-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn a_missing_config_means_no_vault() {
        let dir = scratch("missing");
        let location = VaultLocation::new(dir.clone());
        assert_eq!(location.last(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_config_means_no_vault() {
        let dir = scratch("malformed");
        std::fs::write(dir.join(FILE_NAME), b"{ this is not json").expect("write config");
        let location = VaultLocation::new(dir.clone());
        assert_eq!(location.last(), None, "garbage must not crash or guess");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remember_round_trips_the_path() {
        let dir = scratch("roundtrip");
        let location = VaultLocation::new(dir.clone());
        let vault = dir.join("nested").join("personal.db");
        location.remember(&vault).expect("remember");
        assert_eq!(location.last(), Some(vault));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
