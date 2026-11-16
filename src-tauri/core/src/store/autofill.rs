//! Per-application autofill rules.
//!
//! One row per executable: `fill`, `ask` or `off`. A missing row is `ask` —
//! the picker never fills an application the user has not allowed, and it never
//! remembers an approval the user did not give.
//!
//! Table shape is in [`super::migrate`] (schema v6).
//!
//! # Why this is readable while the vault is locked
//!
//! A rule is policy, not content: it names an executable and says whether the
//! picker may offer a fill. Nothing here is encrypted or derived from a key, so
//! the settings surface can list rules before an unlock. The same is true of
//! the picker's on/off switch, stored under the `meta` table as
//! `autofill_enabled`.
//!
//! The keys are lower-case image names (`notepad.exe`). The Windows shell
//! normalises the path before it lands here; this module does not guess at
//! path syntax, it only rejects an empty key.

use super::{Store, StoreError};
use rusqlite::{params, OptionalExtension};

/// What the picker may do in one application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AutofillMode {
    /// Offer the overlay as soon as a fillable field gets focus.
    Fill,
    /// Offer only when the user asks with the shortcut. This is the default.
    Ask,
    /// Never offer; no shortcut either.
    Off,
}

impl AutofillMode {
    fn as_str(self) -> &'static str {
        match self {
            AutofillMode::Fill => "fill",
            AutofillMode::Ask => "ask",
            AutofillMode::Off => "off",
        }
    }

    /// Strict parse for a command argument. Unknown strings are an error, so a
    /// typo cannot silently downgrade a rule to the default.
    fn parse(raw: &str) -> Option<AutofillMode> {
        match raw {
            "fill" => Some(AutofillMode::Fill),
            "ask" => Some(AutofillMode::Ask),
            "off" => Some(AutofillMode::Off),
            _ => None,
        }
    }

    /// Tolerant parse for a stored value. A row written by an older build (or a
    /// hand-edited database) must not turn into permission to fill, so anything
    /// unrecognised degrades to [`AutofillMode::Ask`].
    fn from_row(raw: &str) -> AutofillMode {
        AutofillMode::parse(raw).unwrap_or(AutofillMode::Ask)
    }
}

const ENABLED_KEY: &str = "autofill_enabled";

impl Store {
    /// The rule for `exe`, with the documented default when no row exists.
    ///
    /// This is the only read path the picker uses, so "no row" and "ask" can
    /// never diverge. The return value is one of `fill`, `ask`, `off`; `exe` is
    /// matched exactly, so callers normalise first.
    pub fn autofill_rule(&self, exe: &str) -> Result<String, StoreError> {
        let stored: Option<String> = self
            .conn()
            .query_row(
                "SELECT mode FROM autofill_apps WHERE exe = ?1",
                params![exe],
                |row| row.get(0),
            )
            .optional()?;
        Ok(stored
            .as_deref()
            .map(AutofillMode::from_row)
            .unwrap_or(AutofillMode::Ask)
            .as_str()
            .to_string())
    }

    /// Every explicit rule as `(exe, mode, updated_at)`, alphabetically. A
    /// missing row is not listed: the settings table shows decisions the user
    /// made, not every executable on the machine.
    pub fn autofill_rules(&self) -> Result<Vec<(String, String, i64)>, StoreError> {
        let mut stmt = self
            .conn()
            .prepare("SELECT exe, mode, updated_at FROM autofill_apps ORDER BY exe")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                AutofillMode::from_row(&row.get::<_, String>(1)?)
                    .as_str()
                    .to_string(),
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut rules = Vec::new();
        for rule in rows {
            rules.push(rule?);
        }
        Ok(rules)
    }

    /// Upsert a rule. `mode` must be one of the three literals; `exe` must
    /// already be a lower-case image name. An empty one is rejected, because a
    /// rule without an application means nothing.
    pub fn set_autofill_rule(&self, exe: &str, mode: &str) -> Result<(), StoreError> {
        if exe.trim().is_empty() {
            return Err(StoreError::Invalid(
                "an autofill rule needs an executable name".to_string(),
            ));
        }
        let mode = AutofillMode::parse(mode).ok_or_else(|| {
            StoreError::Invalid(format!(
                "{mode} is not an autofill mode; expected fill, ask or off"
            ))
        })?;
        self.conn().execute(
            "INSERT INTO autofill_apps(exe, mode, updated_at) VALUES(?1, ?2, ?3)
             ON CONFLICT(exe) DO UPDATE SET
                mode = excluded.mode,
                updated_at = excluded.updated_at",
            params![exe, mode.as_str(), now_secs()],
        )?;
        Ok(())
    }

    /// Drop a rule so the application falls back to the default (`ask`).
    pub fn clear_autofill_rule(&self, exe: &str) -> Result<bool, StoreError> {
        let changed = self.conn().execute(
            "DELETE FROM autofill_apps WHERE exe = ?1",
            params![exe],
        )?;
        Ok(changed > 0)
    }

    /// Whether the picker is enabled at all. Defaults to **enabled**: the
    /// per-app rule still gates every offer, and a feature that needs a trip to
    /// Settings before it ever runs reads as broken.
    pub fn autofill_enabled(&self) -> Result<bool, StoreError> {
        let stored = self.meta(ENABLED_KEY)?;
        Ok(match stored.as_deref() {
            Some(value) => value == b"1",
            None => true,
        })
    }

    pub fn set_autofill_enabled(&self, enabled: bool) -> Result<(), StoreError> {
        self.set_meta(ENABLED_KEY, if enabled { b"1" } else { b"0" })
    }
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A throwaway database. `Store::open` migrates it, so the test exercises
    /// the real table rather than a hand-built fixture.
    struct TempStore {
        path: PathBuf,
        store: Store,
    }

    impl TempStore {
        fn new() -> TempStore {
            let path = std::env::temp_dir().join(format!(
                "kestrel-autofill-{}.db",
                uuid::Uuid::new_v4()
            ));
            let store = Store::open(&path).expect("store opens");
            TempStore { path, store }
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(self.path.with_extension("db-wal"));
            let _ = std::fs::remove_file(self.path.with_extension("db-shm"));
        }
    }

    #[test]
    fn missing_row_is_ask() {
        let temp = TempStore::new();
        assert_eq!(temp.store.autofill_rule("notepad.exe").unwrap(), "ask");
    }

    #[test]
    fn rules_round_trip_and_clear_back_to_ask() {
        let temp = TempStore::new();
        temp.store.set_autofill_rule("acme.exe", "off").unwrap();
        assert_eq!(temp.store.autofill_rule("acme.exe").unwrap(), "off");
        assert_eq!(temp.store.autofill_rules().unwrap().len(), 1);
        assert!(temp.store.clear_autofill_rule("acme.exe").unwrap());
        assert_eq!(temp.store.autofill_rule("acme.exe").unwrap(), "ask");
        assert!(temp.store.autofill_rules().unwrap().is_empty());
    }

    #[test]
    fn an_unknown_stored_mode_degrades_to_ask() {
        let temp = TempStore::new();
        temp.store
            .conn()
            .execute(
                "INSERT INTO autofill_apps(exe, mode, updated_at) VALUES('x.exe', 'fill-everything', 0)",
                [],
            )
            .unwrap();
        assert_eq!(temp.store.autofill_rule("x.exe").unwrap(), "ask");
    }

    #[test]
    fn empty_executable_is_rejected() {
        let temp = TempStore::new();
        assert!(temp.store.set_autofill_rule("  ", "fill").is_err());
        assert!(temp.store.set_autofill_rule("x.exe", "sometimes").is_err());
    }

    #[test]
    fn enabled_defaults_to_on_and_persists_the_off_choice() {
        let temp = TempStore::new();
        assert!(temp.store.autofill_enabled().unwrap());
        temp.store.set_autofill_enabled(false).unwrap();
        assert!(!temp.store.autofill_enabled().unwrap());
        temp.store.set_autofill_enabled(true).unwrap();
        assert!(temp.store.autofill_enabled().unwrap());
    }
}
