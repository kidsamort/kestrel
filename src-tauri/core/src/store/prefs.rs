//! Device preferences that outlive a restart.
//!
//! The auto-lock interval, the clipboard wipe and the Quick access switch used
//! to live only in memory: a restart reset them to their defaults, so a setting
//! the user made was a setting the user lost. They are policy, not content —
//! nothing here is encrypted or derived from a key — so they sit in `meta`
//! beside `autofill_enabled` and stay readable before an unlock.
//!
//! A corrupt or missing row reads as "never set" and the caller falls back to
//! its default. Guessing a value from a damaged row would be worse than
//! starting from the documented default.

use super::{Store, StoreError};

const AUTOLOCK_KEY: &str = "autolock_seconds";
const CLIPBOARD_KEY: &str = "clipboard_clear_seconds";
const QUICK_ACCESS_KEY: &str = "quick_access_enabled";
const QUICK_SHORTCUT_KEY: &str = "quick_access_shortcut";
const AUTOFILL_SHORTCUT_KEY: &str = "autofill_shortcut";

impl Store {
    /// The stored auto-lock interval, or `None` when the vault never had one.
    pub fn autolock_seconds(&self) -> Result<Option<u64>, StoreError> {
        Ok(self.meta(AUTOLOCK_KEY)?.as_deref().and_then(parse_u64))
    }

    pub fn set_autolock_seconds(&self, seconds: u64) -> Result<(), StoreError> {
        self.set_meta(AUTOLOCK_KEY, seconds.to_string().as_bytes())
    }

    /// The stored clipboard wipe interval, or `None` when never set.
    pub fn clipboard_clear_seconds(&self) -> Result<Option<u64>, StoreError> {
        Ok(self.meta(CLIPBOARD_KEY)?.as_deref().and_then(parse_u64))
    }

    pub fn set_clipboard_clear_seconds(&self, seconds: u64) -> Result<(), StoreError> {
        self.set_meta(CLIPBOARD_KEY, seconds.to_string().as_bytes())
    }

    /// Whether the Quick access chord is bound. Defaults to **on**: a password
    /// manager whose palette needs a trip to Settings first is a worse product
    /// than one with a hotkey, and the switch is one click away.
    pub fn quick_access_enabled(&self) -> Result<bool, StoreError> {
        Ok(match self.meta(QUICK_ACCESS_KEY)?.as_deref() {
            Some(value) => value == b"1",
            None => true,
        })
    }

    pub fn set_quick_access_enabled(&self, enabled: bool) -> Result<(), StoreError> {
        self.set_meta(QUICK_ACCESS_KEY, if enabled { b"1" } else { b"0" })
    }

    /// The chord the palette is bound to, or `None` when the default applies.
    pub fn quick_shortcut(&self) -> Result<Option<String>, StoreError> {
        Ok(self
            .meta(QUICK_SHORTCUT_KEY)?
            .and_then(|raw| String::from_utf8(raw).ok())
            .filter(|chord| !chord.trim().is_empty()))
    }

    pub fn set_quick_shortcut(&self, chord: &str) -> Result<(), StoreError> {
        self.set_meta(QUICK_SHORTCUT_KEY, chord.as_bytes())
    }

    /// The chord that offers the autofill picker, or `None` for the default.
    pub fn autofill_shortcut(&self) -> Result<Option<String>, StoreError> {
        Ok(self
            .meta(AUTOFILL_SHORTCUT_KEY)?
            .and_then(|raw| String::from_utf8(raw).ok())
            .filter(|chord| !chord.trim().is_empty()))
    }

    pub fn set_autofill_shortcut(&self, chord: &str) -> Result<(), StoreError> {
        self.set_meta(AUTOFILL_SHORTCUT_KEY, chord.as_bytes())
    }
}

fn parse_u64(raw: &[u8]) -> Option<u64> {
    std::str::from_utf8(raw).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempStore {
        path: PathBuf,
        store: Store,
    }

    impl TempStore {
        fn new(name: &str) -> TempStore {
            let path = std::env::temp_dir()
                .join(format!("kestrel-prefs-{}-{name}.db", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let store = Store::open(&path).expect("store opens");
            TempStore { path, store }
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn unset_preferences_read_as_absent() {
        let temp = TempStore::new("absent");
        assert_eq!(temp.store.autolock_seconds().unwrap(), None);
        assert_eq!(temp.store.clipboard_clear_seconds().unwrap(), None);
        assert!(temp.store.quick_access_enabled().unwrap());
    }

    #[test]
    fn every_preference_round_trips_through_a_reopen() {
        let temp = TempStore::new("roundtrip");
        temp.store.set_autolock_seconds(900).unwrap();
        temp.store.set_clipboard_clear_seconds(45).unwrap();
        temp.store.set_quick_access_enabled(false).unwrap();

        let store = Store::open(&temp.path).expect("store reopens");
        assert_eq!(store.autolock_seconds().unwrap(), Some(900));
        assert_eq!(store.clipboard_clear_seconds().unwrap(), Some(45));
        assert!(!store.quick_access_enabled().unwrap());
    }

    #[test]
    fn a_corrupt_row_falls_back_instead_of_guessing() {
        let temp = TempStore::new("corrupt");
        temp.store
            .set_meta(AUTOLOCK_KEY, b"fifteen minutes")
            .unwrap();
        assert_eq!(temp.store.autolock_seconds().unwrap(), None);
    }
}
