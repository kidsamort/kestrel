//! Password rotation must leave the vault fully readable: live items, archived
//! versions and attachments are all re-encrypted under the new key, and the
//! version sequence must continue rather than restart (a restart would make the
//! next save overwrite archived history).

use kestrel_core::session::VaultState;

const OLD: &str = "correct horse battery staple";
const NEW: &str = "another long passphrase for rotation";

fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kestrel.db");
    (dir, path)
}

#[test]
fn rotation_keeps_history_readable_and_versions_monotonic() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(OLD).unwrap();

    let mut item = state.create_default("login").unwrap();
    item.title = "first".into();
    let created = state.save(item.clone()).unwrap();

    item.title = "second".into();
    state.save(item.clone()).unwrap();

    // A draft is not stored, so the first save is v1 ("first") and the second
    // archives it: one archived version, v2 live.
    let before = state.history_list(&created.id).unwrap();
    assert_eq!(
        before.len(),
        1,
        "each save archives the version it replaced"
    );
    assert_eq!(before[0].title, "first");

    state.change_password(OLD, NEW).unwrap();

    // The archived ciphertext was rewritten under the new key.
    let after = state.history_list(&created.id).unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(
        state
            .history_get(&created.id, after[0].version)
            .unwrap()
            .title,
        "first"
    );
    assert_eq!(state.get(&created.id).unwrap().title, "second");

    // The live item keeps its version, so the next edit appends version 3
    // instead of colliding with the archived v1/v2 rows.
    let mut third = state.get(&created.id).unwrap();
    third.title = "third".into();
    state.save(third).unwrap();
    let versions: Vec<i64> = state
        .history_list(&created.id)
        .unwrap()
        .iter()
        .map(|v| v.version)
        .collect();
    assert_eq!(versions, vec![2, 1]);
    assert_eq!(state.get(&created.id).unwrap().title, "third");
}

#[test]
fn rotation_requires_the_current_password() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(OLD).unwrap();
    assert!(state.change_password("wrong password here", NEW).is_err());
    // The vault still opens with the original password.
    state.lock().unwrap();
    assert!(state.unlock(OLD).is_ok());
}

#[test]
fn rotation_keeps_trashed_items_in_the_trash() {
    // The projection is rebuilt from the blob on rotation, but the trash marker
    // lives beside it: a rotation must not resurrect deleted rows.
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(OLD).unwrap();

    let mut kept = state.create_default("login").unwrap();
    kept.title = "kept".into();
    state.save(kept).unwrap();

    let mut binned = state.create_default("login").unwrap();
    binned.title = "binned".into();
    let binned = state.save(binned).unwrap();
    state.trash_item(&binned.id).unwrap();
    assert_eq!(state.trash_count().unwrap(), 1);

    state.change_password(OLD, NEW).unwrap();

    assert_eq!(
        state.trash_count().unwrap(),
        1,
        "the trashed row must stay in the trash after a rotation"
    );
    let live = state.list("", None, false).unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].title, "kept");
}
