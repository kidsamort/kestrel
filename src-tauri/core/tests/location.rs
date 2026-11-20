//! Where a vault lives: creating one at a path the user chose, pointing the
//! session at another file, and the hint that travels inside the vault.

use kestrel_core::model::{Category, Item};
use kestrel_core::session::{VaultError, VaultState};
use kestrel_core::store::StoreError;

const PW: &str = "correct horse battery staple";

fn scratch(tag: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join(format!("{tag}.db"));
    (dir, path)
}

#[test]
fn create_at_makes_a_new_unlocked_vault() {
    let (_dir, path) = scratch("personal");
    let state = VaultState::unselected().expect("empty state");
    assert!(state.path().is_none());

    let opened = state.create_at(path.clone(), PW, None).expect("created");

    assert!(opened.initialized, "a new vault is initialised");
    assert!(!opened.locked, "creating opens it");
    assert_eq!(state.path(), Some(path.clone()));
    assert!(path.is_file(), "the file is where the user asked for it");
    // The session is live: an item read does not need a second unlock.
    let saved = state
        .save(state.create_default("login").expect("default item"))
        .expect("save");
    assert_eq!(state.get(&saved.id).expect("read back").id, saved.id);
}

#[test]
fn create_at_refuses_an_existing_file_and_leaves_it_byte_identical() {
    let (_dir, path) = scratch("taken");
    let original = b"not a vault, just a file".to_vec();
    std::fs::write(&path, &original).expect("seed the file");

    let state = VaultState::unselected().expect("empty state");
    let failure = state
        .create_at(path.clone(), PW, Some("hint"))
        .expect_err("an existing file must not be overwritten");

    assert!(
        matches!(failure, VaultError::AlreadyExists),
        "expected a collision, got {failure}"
    );
    assert_eq!(
        std::fs::read(&path).expect("read back"),
        original,
        "the refusing call must not touch the file"
    );
    assert!(state.path().is_none(), "a refusal selects nothing");
}

#[test]
fn a_weak_password_is_refused_before_anything_is_written() {
    let (_dir, path) = scratch("weak");
    let state = VaultState::unselected().expect("empty state");

    let failure = state
        .create_at(path.clone(), "short", None)
        .expect_err("nine characters is not enough");

    assert!(matches!(failure, VaultError::WeakPassword), "got {failure}");
    assert!(!path.exists(), "a rejected password creates no file");
}

#[test]
fn the_hint_travels_with_the_file_and_reads_before_unlock() {
    let (_dir, path) = scratch("hinted");
    let state = VaultState::unselected().expect("empty state");
    state
        .create_at(path.clone(), PW, Some("first pet"))
        .expect("created");
    assert_eq!(
        state.password_hint().expect("hint"),
        Some("first pet".to_string())
    );
    drop(state);

    let reopened = VaultState::open(path).expect("reopens");
    assert!(reopened.is_locked());
    assert_eq!(
        reopened.password_hint().expect("hint"),
        Some("first pet".to_string()),
        "the hint is readable without the master password"
    );
    reopened
        .unlock(PW)
        .expect("the hint did not disturb unlock");
}

#[test]
fn a_vault_made_without_a_hint_reports_none() {
    let (_dir, path) = scratch("plain");
    let state = VaultState::unselected().expect("empty state");
    state.create_at(path.clone(), PW, None).expect("created");
    drop(state);

    let reopened = VaultState::open(path).expect("reopens");
    assert_eq!(reopened.password_hint().expect("hint"), None);
}

#[test]
fn open_at_swaps_the_store_without_touching_the_first_vault() {
    let (_first_dir, first) = scratch("first");
    let (_second_dir, second) = scratch("second");

    let state = VaultState::unselected().expect("empty state");
    state
        .create_at(first.clone(), PW, None)
        .expect("first vault");
    let saved = state
        .save(state.create_default("login").expect("default item"))
        .expect("save");
    state.lock().expect("lock");

    // A second vault, made through its own session so the two files are
    // independent.
    {
        let other = VaultState::unselected().expect("empty state");
        other
            .create_at(second.clone(), PW, None)
            .expect("second vault");
    }

    let swapped = state.open_at(second.clone()).expect("switched files");

    assert!(swapped.locked, "pointing at another file drops the session");
    assert_eq!(state.path(), Some(second.clone()));
    state.unlock(PW).expect("unlock the second vault");
    assert!(
        matches!(
            state.get(&saved.id),
            Err(VaultError::Store(StoreError::NotFound))
        ),
        "the first vault's item must not exist in the second"
    );
    assert!(
        first.is_file(),
        "switching away must not move or delete the first file"
    );
    // The first vault still holds its item when selected again. (Comparing the
    // raw bytes would be meaningless: closing a WAL database checkpoints it.)
    state
        .open_at(first.clone())
        .expect("back to the first vault");
    state.unlock(PW).expect("unlock the first vault");
    assert_eq!(state.get(&saved.id).expect("still there").id, saved.id);
}

#[test]
fn open_at_refuses_a_missing_file_and_keeps_the_current_vault() {
    let (_dir, path) = scratch("kept");
    let missing = path.with_file_name("gone.db");
    let state = VaultState::unselected().expect("empty state");
    state.create_at(path.clone(), PW, None).expect("created");

    assert!(
        state.open_at(missing).is_err(),
        "a missing file cannot open"
    );
    assert_eq!(
        state.path(),
        Some(path),
        "a failed switch must not drop the open vault"
    );
}

#[test]
fn before_a_vault_is_selected_every_data_command_says_so() {
    let state = VaultState::unselected().expect("empty state");
    assert!(state.path().is_none());
    assert!(state.is_locked());

    let failures = [
        state.list("", None, false).expect_err("list"),
        state.counts().expect_err("counts"),
        state.get("anything").expect_err("get"),
        state.create_default("login").expect_err("default item"),
        state
            .save(Item::new(Category::Login, "x".into()))
            .expect_err("save"),
        state.vaults().expect_err("vaults"),
        state.sync_meta("key").expect_err("sync meta"),
        state.password_hint().expect_err("hint"),
        state.browser_rules().expect_err("browser rules"),
        state.store().err().expect("store"),
    ];
    for failure in failures {
        assert_eq!(failure.to_string(), "no vault is open");
    }

    // Status-style reads stay usable: the first-run screen needs a shape, not
    // an error, before any file exists.
    let snapshot = state.state().expect("status");
    assert!(!snapshot.initialized && snapshot.locked);
}
