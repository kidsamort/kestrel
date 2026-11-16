//! Item history: archived versions, read-back, restore and tamper rejection.

use kestrel_core::model::{Category, Item};
use kestrel_core::session::{VaultError, VaultState};
use rusqlite::params;

const PW: &str = "correct horse battery staple";

fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kestrel.db");
    (dir, path)
}

/// Rename the live item three times, producing versions 1, 2 and 3.
fn seed_three_versions(state: &VaultState) -> (String, Vec<String>) {
    let first = state
        .save(Item::new(Category::Login, "First title".into()))
        .expect("first save");
    let mut second = first.clone();
    second.title = "Second title".into();
    state.save(second).expect("second save");
    let mut third = first.clone();
    third.title = "Third title".into();
    state.save(third).expect("third save");
    (
        first.id.clone(),
        vec![
            "First title".into(),
            "Second title".into(),
            "Third title".into(),
        ],
    )
}

#[test]
fn history_lists_old_titles_newest_first_and_reads_them_back() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(PW).unwrap();

    let (id, titles) = seed_three_versions(&state);
    let field_count = state.get(&id).unwrap().fields.len();

    let versions = state.history_list(&id).unwrap();
    assert_eq!(versions.len(), 2, "versions 1 and 2 are archived");
    assert_eq!(versions[0].version, 2);
    assert_eq!(versions[0].title, titles[1]);
    assert_eq!(versions[0].field_count, field_count);
    assert!(versions[0].archived_at > 0);
    assert_eq!(versions[1].version, 1);
    assert_eq!(versions[1].title, titles[0]);

    let old = state.history_get(&id, 1).unwrap();
    assert_eq!(old.title, titles[0]);
    assert_eq!(old.id, id);
}

#[test]
fn restore_saves_an_old_version_as_the_new_current_version() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(PW).unwrap();

    let (id, titles) = seed_three_versions(&state);

    let restored = state.history_restore(&id, 1).unwrap();
    assert_eq!(restored.title, titles[0]);
    assert_eq!(restored.id, id);
    assert_eq!(state.get(&id).unwrap().title, titles[0]);

    // The restore is a save: the superseded current version (3) is archived
    // and the restored content is stored as version 4.
    let versions = state.history_list(&id).unwrap();
    assert_eq!(versions.len(), 3);
    assert_eq!(versions[0].version, 3);
    assert_eq!(versions[0].title, titles[2]);
    assert_eq!(versions[1].version, 2);
    assert_eq!(versions[1].title, titles[1]);
    assert_eq!(versions[2].version, 1);
    assert_eq!(versions[2].title, titles[0]);

    // Version 4 is the live row, not an archived one.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let live_version: i64 = conn
        .query_row(
            "SELECT version FROM items WHERE item_uuid = ?1",
            params![id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(live_version, 4);
}

fn flip_archived_byte(path: &std::path::Path, item_id: &str, version: i64) {
    let conn = rusqlite::Connection::open(path).unwrap();
    let mut blob: Vec<u8> = conn
        .query_row(
            "SELECT data FROM item_versions WHERE item_uuid = ?1 AND version = ?2",
            params![item_id, version],
            |r| r.get(0),
        )
        .expect("archived row");
    let last = blob.len() - 1;
    blob[last] ^= 0xff;
    conn.execute(
        "UPDATE item_versions SET data = ?3 WHERE item_uuid = ?1 AND version = ?2",
        params![item_id, version, blob],
    )
    .expect("tamper write");
}

#[test]
fn tampered_archived_ciphertext_is_rejected() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(PW).unwrap();

    let (id, _) = seed_three_versions(&state);
    flip_archived_byte(&path, &id, 2);

    let err = state.history_get(&id, 2).unwrap_err();
    assert!(
        err.to_string().contains("crypto error"),
        "expected a crypto error, got: {err}"
    );
}

#[test]
fn unknown_item_has_no_history() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(PW).unwrap();

    assert!(matches!(
        state.history_list("does-not-exist"),
        Err(VaultError::NotFound)
    ));
    assert!(matches!(
        state.history_get("does-not-exist", 1),
        Err(VaultError::NotFound)
    ));
}

#[test]
fn known_item_without_versions_lists_empty() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(PW).unwrap();

    let item = state
        .save(Item::new(Category::Login, "Only version".into()))
        .unwrap();
    assert!(state.history_list(&item.id).unwrap().is_empty());
    assert!(matches!(
        state.history_get(&item.id, 1),
        Err(VaultError::NotFound)
    ));
}
