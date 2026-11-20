//! End-to-end vault behaviour, exercised against the same code the app runs.

use kestrel_core::model::{Category, Field, Item};
use kestrel_core::session::VaultState;

fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kestrel.db");
    (dir, path)
}

const PW: &str = "correct horse battery staple";

#[test]
fn create_unlock_and_read_back_an_item() {
    let (_dir, path) = scratch();
    {
        let state = VaultState::open(path.clone()).unwrap();
        assert!(!state.state().unwrap().initialized);
        let created = state.create(PW).unwrap();
        assert!(created.initialized && !created.locked);

        let mut item = Item::new(Category::Login, "GitHub".into());
        for field in item.fields.iter_mut() {
            match field.kind.as_str() {
                "username" => field.value = "alice".into(),
                "password" => field.value = "s3cr3t-value".into(),
                "url" => field.value = "https://github.com".into(),
                _ => {}
            }
        }
        item.tags = vec!["work".into()];
        item.favorite = true;
        let saved = state.save(item).unwrap();
        assert_eq!(saved.title, "GitHub");

        let listed = state.list("", None, false).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].username, "alice");
        assert!(listed[0].has_totp == false);
        assert!(listed[0].favorite);

        // Summaries must never carry the secret.
        let summary = serde_json::to_string(&listed).unwrap();
        assert!(!summary.contains("s3cr3t-value"));
    }

    // Reopen: ciphertext survives a process restart and decrypts again.
    let state = VaultState::open(path).unwrap();
    assert!(state.state().unwrap().initialized);
    assert!(state.state().unwrap().locked);
    assert!(
        state.list("", None, false).is_err(),
        "locked vault refuses reads"
    );

    state.unlock(PW).unwrap();
    let items = state.list("", None, false).unwrap();
    assert_eq!(items.len(), 1);
    let full = state.get(&items[0].id).unwrap();
    assert_eq!(
        full.fields
            .iter()
            .find(|f| f.kind == "password")
            .unwrap()
            .value,
        "s3cr3t-value"
    );
}

#[test]
fn wrong_password_cannot_unlock() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(PW).unwrap();
    state.lock().unwrap();
    let err = state.unlock("wrong password here").unwrap_err();
    assert!(err.to_string().contains("authentication failed"), "{err}");
    assert!(state.state().unwrap().locked);
}

/// Concatenated bytes of the database and its WAL: recent rows live in the WAL
/// until a checkpoint, so a check of the main file alone would be misleading.
fn all_db_bytes(path: &std::path::Path) -> Vec<u8> {
    let mut bytes = std::fs::read(path).unwrap();
    let wal = path.with_extension("db-wal");
    if let Ok(mut tail) = std::fs::read(&wal) {
        bytes.append(&mut tail);
    }
    bytes
}

#[test]
fn database_holds_only_ciphertext() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(PW).unwrap();
    let mut item = Item::new(Category::Password, "Bank".into());
    item.fields.push(Field {
        id: "f1".into(),
        label: "password".into(),
        kind: "password".into(),
        value: "PLAINTEXT-CANARY-42".into(),
        sensitive: true,
    });
    let saved = state.save(item).unwrap();

    let raw = all_db_bytes(&path);
    let needle = b"PLAINTEXT-CANARY-42";
    assert!(
        !raw.windows(needle.len()).any(|w| w == needle),
        "plaintext leaked into the database file"
    );
    // The item id is stored in the clear on purpose (indexing), the value is not.
    let raw_text = String::from_utf8_lossy(&raw);
    assert!(raw_text.contains(&saved.id));
}

#[test]
fn tampering_with_a_row_is_detected() {
    let (_dir, path) = scratch();
    {
        let state = VaultState::open(path.clone()).unwrap();
        state.create(PW).unwrap();
        let item = Item::new(Category::SecureNote, "Note".into());
        state.save(item).unwrap();
    }
    // Flip one byte of the ciphertext.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "journal_mode", "DELETE").ok();
    let mut blob: Vec<u8> = conn
        .query_row("SELECT data FROM items LIMIT 1", [], |r| r.get(0))
        .unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    conn.execute("UPDATE items SET data = ?1", rusqlite::params![blob])
        .unwrap();

    let state = VaultState::open(path).unwrap();
    state.unlock(PW).unwrap();
    let err = state.list("", None, false).unwrap_err();
    assert!(err.to_string().contains("authentication failed"), "{err}");
}

#[test]
fn search_skips_sensitive_fields_and_honours_filters() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(PW).unwrap();

    let mut login = Item::new(Category::Login, "Acme".into());
    for field in login.fields.iter_mut() {
        if field.kind == "password" {
            field.value = "hunter2-unique".into();
        }
        if field.kind == "username" {
            field.value = "bob".into();
        }
    }
    state.save(login).unwrap();
    state
        .save(Item::new(Category::SecureNote, "Grocery list".into()))
        .unwrap();

    assert_eq!(state.list("acme", None, false).unwrap().len(), 1);
    assert_eq!(
        state.list("hunter2", None, false).unwrap().len(),
        0,
        "secret values must not be searchable"
    );
    assert_eq!(state.list("", Some("secureNote"), false).unwrap().len(), 1);
    assert_eq!(state.list("", None, true).unwrap().len(), 0);
}

#[test]
fn updates_bump_versions_and_each_edit_reencrypts() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(PW).unwrap();
    let mut item = Item::new(Category::Login, "Rotate".into());
    let first = state.save(item.clone()).unwrap();
    let before = all_db_bytes(&path);

    item.title = "Rotate 2".into();
    let second = state.save(item).unwrap();
    let after = all_db_bytes(&path);

    assert_eq!(second.id, first.id);
    assert_ne!(
        before, after,
        "an edit must rewrite ciphertext, not reuse the old blob"
    );
    assert_eq!(state.list("", None, false).unwrap().len(), 1);
    assert_eq!(state.get(&first.id).unwrap().title, "Rotate 2");
}

#[test]
fn delete_removes_the_row() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(PW).unwrap();
    let item = state
        .save(Item::new(Category::Login, "Temp".into()))
        .unwrap();
    state.delete(&item.id).unwrap();
    assert_eq!(state.list("", None, false).unwrap().len(), 0);
    assert!(state.get(&item.id).is_err());
}

#[test]
fn totp_and_generator_are_wired_into_the_session() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(PW).unwrap();
    let mut item = Item::new(Category::Login, "Acme SSO".into());
    item.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
    let saved = state.save(item).unwrap();
    let totp = state.totp(&saved.id).unwrap();
    assert_eq!(totp.code.len(), 6);
    assert!(totp.code.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(totp.period, 30, "a bare secret uses the 30 s default");
    assert!(totp.seconds_remaining >= 1 && totp.seconds_remaining <= totp.period);

    let password = state.generate_password(Default::default());
    assert_eq!(password.chars().count(), 20);
}

#[test]
fn totp_honours_the_otpauth_period() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(PW).unwrap();
    let mut item = Item::new(Category::Login, "Long cycle".into());
    item.totp_secret =
        Some("otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=60".into());
    let saved = state.save(item).unwrap();
    let totp = state.totp(&saved.id).unwrap();
    assert_eq!(totp.period, 60);
    assert!(totp.seconds_remaining >= 1 && totp.seconds_remaining <= 60);
}

#[test]
fn clipboard_clear_interval_is_configurable_and_clamped() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    assert_eq!(
        state.state().unwrap().clipboard_clear_seconds,
        kestrel_core::session::CLIPBOARD_CLEAR_SECS
    );

    assert_eq!(
        state
            .set_clipboard_clear(45)
            .unwrap()
            .clipboard_clear_seconds,
        45
    );
    assert_eq!(
        state
            .set_clipboard_clear(9_999)
            .unwrap()
            .clipboard_clear_seconds,
        300,
        "no copy may outlive five minutes"
    );
    assert_eq!(
        state
            .set_clipboard_clear(0)
            .unwrap()
            .clipboard_clear_seconds,
        0,
        "zero wipes immediately instead of being rejected"
    );
}

#[test]
fn vault_path_is_the_resolved_database_file() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    assert_eq!(state.vault_path(), path);
}

#[test]
fn lock_at_is_an_absolute_deadline_only_while_unlocked() {
    fn unix_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    assert_eq!(
        state.state().unwrap().lock_at,
        None,
        "a locked vault has no deadline"
    );

    state.create(PW).unwrap();
    state.set_autolock(60).unwrap();
    state.touch();
    let before = unix_ms();
    let dto = state.state().unwrap();
    let after = unix_ms();
    let lock_at = dto.lock_at.expect("an unlocked vault exposes its deadline");
    assert!(
        lock_at > before + 59_000,
        "deadline must be a full minute away, not a running countdown"
    );
    assert!(
        lock_at <= after + 60_000,
        "deadline must sit on the absolute last_activity + autolock instant"
    );

    state.lock().unwrap();
    assert_eq!(state.state().unwrap().lock_at, None);
}

#[test]
fn password_change_reencrypts_every_item() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(PW).unwrap();
    state
        .save(Item::new(Category::Login, "Survivor".into()))
        .unwrap();
    state
        .change_password(PW, "a brand new master passphrase")
        .unwrap();
    state.lock().unwrap();
    assert!(state.unlock(PW).is_err(), "old password must stop working");
    state.unlock("a brand new master passphrase").unwrap();
    assert_eq!(state.list("", None, false).unwrap().len(), 1);
}

#[test]
fn short_master_password_is_refused() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    assert!(state.create("short").is_err());
    assert!(!state.state().unwrap().initialized);
}

#[test]
fn autolock_timeout_is_configurable() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(PW).unwrap();
    let dto = state.set_autolock(900).unwrap();
    assert_eq!(dto.autolock_seconds, 900);
    assert_eq!(
        state.set_autolock(1).unwrap().autolock_seconds,
        15,
        "clamped"
    );
}

#[test]
fn intervals_survive_a_reopen() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(PW).unwrap();
    state.set_autolock(900).unwrap();
    state.set_clipboard_clear(45).unwrap();
    drop(state);

    // A second launch must start where the first one ended, not from the
    // documented defaults.
    let reopened = VaultState::open(path).unwrap();
    let dto = reopened.state().unwrap();
    assert_eq!(dto.autolock_seconds, 900);
    assert_eq!(dto.clipboard_clear_seconds, 45);
}

#[test]
fn a_vault_that_never_saved_an_interval_keeps_the_default() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(PW).unwrap();
    drop(state);

    let reopened = VaultState::open(path).unwrap();
    let dto = reopened.state().unwrap();
    assert_eq!(dto.autolock_seconds, 300, "auto-lock stays at five minutes");
    assert_eq!(
        dto.clipboard_clear_seconds, 30,
        "the clipboard wipe stays at 30s"
    );
}

#[test]
fn a_new_item_is_a_draft_until_it_is_saved() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(PW).unwrap();

    let draft = state.create_default("login").unwrap();
    assert!(
        !draft.id.is_empty(),
        "the draft carries the id it will save under"
    );
    assert_eq!(
        draft.fields.len(),
        Category::Login.default_fields().len(),
        "the field template still comes from the core"
    );

    // Nothing is written: no list row, no counter, no history, no search entry.
    assert!(state.list("", None, false).unwrap().is_empty());
    assert_eq!(state.state().unwrap().item_count, 0);
    assert!(
        state.history_list(&draft.id).is_err(),
        "a draft has no row, so it has no history to list"
    );

    let id = draft.id.clone();
    let saved = state.save(draft).unwrap();
    assert_eq!(saved.id, id, "the draft keeps its id through the save");
    assert_eq!(state.list("", None, false).unwrap().len(), 1);
    assert!(
        state.history_list(&saved.id).unwrap().is_empty(),
        "a first save has nothing to archive"
    );
}
