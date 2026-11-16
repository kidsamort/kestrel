//! The printable recovery kit, end to end.
//!
//! A kit is one shot by construction: the row holds the master key sealed under
//! a key derived from the printed code, and completing a recovery replaces the
//! row. These tests drive the whole path — create, lock, unlock with the code,
//! forced rotation, new code — and check that every kind of ciphertext survives
//! the re-key: live items, archived versions, attachments and passkeys.

use kestrel_core::model::PasskeyRow;
use kestrel_core::session::{VaultError, VaultState};
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;

const OLD: &str = "correct horse battery staple";
const NEW: &str = "a brand new long passphrase";
const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kestrel.db");
    (dir, path)
}

/// The sealed master key as it sits on disk. `None` when no kit exists.
fn wrapped(path: &Path) -> Option<Vec<u8>> {
    Connection::open(path)
        .expect("second connection")
        .query_row("SELECT wrapped FROM recovery", [], |row| row.get(0))
        .optional()
        .expect("recovery row query")
}

/// A code of the right shape whose checksum byte is deliberately different.
fn broken_checksum(code: &str) -> String {
    let mut chars: Vec<char> = code.chars().collect();
    let last = chars.len() - 1;
    let replacement = ALPHABET
        .chars()
        .find(|candidate| *candidate != chars[last])
        .expect("alphabet has more than one character");
    chars[last] = replacement;
    chars.into_iter().collect()
}

#[test]
fn recovery_forces_a_new_password_and_rekeys_everything() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(OLD).unwrap();

    // One item of every shape the rotation has to carry: a live item with an
    // archived version, an attachment, and a credential sealed under the item
    // key.
    let mut login = state.create_default("login").unwrap();
    login.title = "first version".into();
    let mut login = state.save(login).unwrap();
    login.title = "second version".into();
    let login = state.save(login).unwrap();
    let archived = state.history_list(&login.id).unwrap();
    assert_eq!(archived.len(), 1, "one save archives the version it replaced");

    let payload = vec![1u8, 2, 3, 4];
    let attachment = state
        .attachment_add(&login.id, "note.txt", "text/plain", payload.clone())
        .unwrap();

    let credential = vec![0xcdu8; 32];
    state
        .passkey_insert(
            PasskeyRow {
                credential_id: credential.clone(),
                item_uuid: login.id.clone(),
                rp_id: "example.com".into(),
                created_at: login.created_at,
                last_used_at: None,
            },
            &[0x5a; 32],
            7,
        )
        .unwrap();

    let kit = state.recovery_create().unwrap();
    assert_eq!(kit.vault_name, "Personal");
    assert_eq!(
        kit.code.split('-').count(),
        14,
        "13 groups of four plus the checksum character"
    );
    assert!(state.recovery_status().unwrap().enrolled);

    state.lock().unwrap();
    assert!(matches!(state.list("", None, false), Err(VaultError::Locked)));

    // The code opens the key, but not the session: until a new password exists
    // nothing else in the core may read or write.
    let opened = state.recovery_unlock(&kit.code).unwrap();
    assert_eq!(opened.vault_name, "Personal");
    assert!(state.is_locked(), "a pending recovery is not an open session");
    assert!(matches!(state.list("", None, false), Err(VaultError::Locked)));
    assert!(matches!(state.recovery_create(), Err(VaultError::Locked)));
    assert!(matches!(state.get(&login.id), Err(VaultError::Locked)));

    // A short password is refused before an expensive rotation, and the
    // pending key survives the refusal so the user can simply retype.
    assert!(matches!(
        state.recovery_complete("short"),
        Err(VaultError::WeakPassword)
    ));

    let done = state.recovery_complete(NEW).unwrap();
    assert_eq!(done.vault_name, "Personal");
    let new_kit = done.kit.expect("a fresh code for the new key");
    assert_ne!(new_kit.code, kit.code, "the used code is replaced");
    assert_eq!(new_kit.vault_name, "Personal");
    // The rotation committed, but the new key is still pending: the vault only
    // opens once the user acknowledges the replacement code.
    assert!(state.is_locked());
    assert!(matches!(state.list("", None, false), Err(VaultError::Locked)));
    assert!(!state.recovery_finish().unwrap().locked);

    // The code that opened the vault no longer opens anything: its row was
    // replaced, and the master key it wrapped no longer exists.
    state.lock().unwrap();
    let stale = state.recovery_unlock(&kit.code).unwrap_err();
    assert!(
        stale.to_string().contains("does not open this vault"),
        "the used code must fail on the cipher, not the format: {stale}"
    );
    assert!(state.is_locked());
    // The new code does open it (checked by `recovery_unlock` succeeding); drop
    // the pending key again so the password door is what the rest of the test
    // exercises.
    state.recovery_unlock(&new_kit.code).unwrap();
    state.lock().unwrap();

    // The old password is gone by definition, the new one opens the vault, and
    // every ciphertext was re-sealed.
    assert!(state.unlock(OLD).is_err());
    state.unlock(NEW).unwrap();
    assert_eq!(state.list("", None, false).unwrap().len(), 1);
    assert_eq!(state.get(&login.id).unwrap().title, "second version");
    assert_eq!(
        state.history_get(&login.id, archived[0].version).unwrap().title,
        "first version"
    );
    assert_eq!(
        state.attachment_read(&login.id, &attachment.id).unwrap(),
        payload
    );
    let assertion = state
        .passkey_open_for_assertion("example.com", &[credential])
        .unwrap()
        .expect("the credential survives the rotation");
    assert_eq!(assertion.private_key, vec![0x5a; 32]);
    assert_eq!(assertion.sign_count, 7);
}

#[test]
fn a_bad_checksum_is_refused_before_any_database_read() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(OLD).unwrap();
    state.lock().unwrap();

    // With no kit on disk at all, exactly one of the 32 checksum characters can
    // get past the format check: every other one must be reported as a checksum
    // failure, never as "no recovery code is set". The checksum is therefore
    // settled before the row lookup, and no key is derived for a mistyped code.
    let body = "A".repeat(52);
    let mut checksum_failures = 0;
    let mut row_lookups = 0;
    for candidate in ALPHABET.chars() {
        match state.recovery_unlock(&format!("{body}{candidate}")) {
            Ok(_) => panic!("no kit exists, so no code can unwrap one"),
            Err(error) => {
                let text = error.to_string();
                if text.contains("checksum") {
                    checksum_failures += 1;
                } else if text.contains("no recovery code is set") {
                    row_lookups += 1;
                } else {
                    panic!("unexpected failure: {text}");
                }
            }
        }
    }
    assert_eq!(checksum_failures, 31, "a typo never reaches the database");
    assert_eq!(row_lookups, 1, "only the right checksum reads the row");

    // A real kit: the row must be byte-identical after a rejected attempt, and
    // the vault must stay locked.
    state.unlock(OLD).unwrap();
    let kit = state.recovery_create().unwrap();
    let before = wrapped(&path).expect("the kit is on disk");
    state.lock().unwrap();

    let error = state
        .recovery_unlock(&broken_checksum(&kit.code))
        .unwrap_err();
    assert!(
        error.to_string().contains("checksum"),
        "a typo must be refused by the checksum: {error}"
    );
    assert!(state.is_locked());
    assert_eq!(wrapped(&path).as_deref(), Some(before.as_slice()));
    assert!(state.recovery_status().unwrap().enrolled);
}

#[test]
fn a_second_kit_replaces_the_row_and_the_first_code() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(OLD).unwrap();

    let first = state.recovery_create().unwrap();
    let second = state.recovery_create().unwrap();
    assert_ne!(first.code, second.code);

    let rows: i64 = Connection::open(state.vault_path())
        .unwrap()
        .query_row("SELECT COUNT(*) FROM recovery", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 1, "one row per vault, always the newest code");

    state.lock().unwrap();
    assert!(
        state.recovery_unlock(&first.code).is_err(),
        "the replaced code is dead on disk, not merely discouraged"
    );
    assert!(state.recovery_unlock(&second.code).is_ok());
}

#[test]
fn locking_between_attempts_clears_the_pending_key() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(OLD).unwrap();
    let kit = state.recovery_create().unwrap();
    state.lock().unwrap();

    // A rejected code leaves the door where it was.
    assert!(state.recovery_unlock(&broken_checksum(&kit.code)).is_err());
    assert!(state.is_locked());

    // A good code arms the forced change; locking discards the unwrapped key.
    state.recovery_unlock(&kit.code).unwrap();
    // The vault cannot be opened before the password is replaced.
    assert!(matches!(
        state.recovery_finish(),
        Err(VaultError::Invalid(_))
    ));
    state.lock().unwrap();
    assert!(matches!(
        state.recovery_complete(NEW),
        Err(VaultError::Invalid(_))
    ));

    // The printed code was not consumed by the cancelled attempt.
    assert!(state.recovery_unlock(&kit.code).is_ok());
    assert!(state.recovery_complete(NEW).is_ok());
}
