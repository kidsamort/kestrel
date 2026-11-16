//! Trash behaviour: soft delete, restore, permanent purge and empty trash.

use kestrel_core::model::{Category, Item};
use kestrel_core::session::{VaultError, VaultState};
use rusqlite::{params, Connection};

fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kestrel.db");
    (dir, path)
}

const PW: &str = "correct horse battery staple";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}

fn item(title: &str, category: Category) -> Item {
    Item::new(category, title.into())
}

fn vault_uuid(conn: &Connection, item_id: &str) -> String {
    conn.query_row(
        "SELECT vault_uuid FROM items WHERE item_uuid = ?1",
        params![item_id],
        |row| row.get(0),
    )
    .expect("item row carries its vault uuid")
}

fn count(conn: &Connection, sql: &str, item_id: &str) -> i64 {
    conn.query_row(sql, params![item_id], |row| row.get(0))
        .expect("count query")
}

#[test]
fn trash_hides_the_item_but_keeps_it_readable_and_restore_clears_the_marker() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(PW).unwrap();
    let saved = state.save(item("GitHub", Category::Login)).unwrap();

    state.trash_item(&saved.id).unwrap();

    // Gone from the normal list, still decryptable through `get`.
    assert!(state.list("", None, false).unwrap().is_empty());
    let still = state.get(&saved.id).unwrap();
    assert_eq!(still.title, "GitHub");
    assert_eq!(state.trash_count().unwrap(), 1);

    let trashed = state.trash_list().unwrap();
    assert_eq!(trashed.len(), 1);
    assert_eq!(trashed[0].id, saved.id);
    assert_eq!(trashed[0].title, "GitHub");
    let stamp = trashed[0].deleted_at.expect("deleted_at is stamped");
    assert!((now() - stamp).abs() <= 10, "stamp is current: {stamp}");

    // Idempotent: trashing again keeps the original deletion time.
    state.trash_item(&saved.id).unwrap();
    assert_eq!(state.trash_count().unwrap(), 1);
    assert_eq!(state.trash_list().unwrap()[0].deleted_at, Some(stamp));

    state.restore_item(&saved.id).unwrap();
    assert_eq!(state.list("", None, false).unwrap().len(), 1);
    assert_eq!(state.trash_count().unwrap(), 0);
    assert!(state.trash_list().unwrap().is_empty());

    let conn = Connection::open(&path).unwrap();
    let marker: Option<i64> = conn
        .query_row(
            "SELECT deleted_at FROM items WHERE item_uuid = ?1",
            params![saved.id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(marker.is_none(), "restore clears deleted_at in the row");

    // Restoring a live item is a harmless no-op.
    state.restore_item(&saved.id).unwrap();
    assert_eq!(state.list("", None, false).unwrap().len(), 1);
}

#[test]
fn purge_is_refused_for_live_items_and_removes_versions_and_attachments() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(PW).unwrap();

    let first = state.save(item("Mail", Category::Login)).unwrap();
    let mut edited = first.clone();
    edited.title = "Mail (work)".into();
    let saved = state.save(edited).unwrap();

    let conn = Connection::open(&path).unwrap();
    let vault = vault_uuid(&conn, &saved.id);
    conn.execute(
        "INSERT INTO attachments(vault_uuid, item_uuid, attachment_uuid, name, mime,
                                 size, digest, created_at, data)
         VALUES(?1, ?2, 'att-1', 'scan.pdf', 'application/pdf', 4, 'deadbeef', 0, ?3)",
        params![vault, saved.id, vec![0u8, 1, 2, 3]],
    )
    .unwrap();

    let versions_sql = "SELECT COUNT(*) FROM item_versions WHERE item_uuid = ?1";
    let attachments_sql = "SELECT COUNT(*) FROM attachments WHERE item_uuid = ?1";
    assert_eq!(count(&conn, versions_sql, &saved.id), 1);
    assert_eq!(count(&conn, attachments_sql, &saved.id), 1);

    match state.purge_item(&saved.id) {
        Err(VaultError::Invalid(message)) => {
            assert!(
                message.contains("restore or delete it from the vault first"),
                "{message}"
            )
        }
        other => panic!("live item must not purge: {other:?}"),
    }
    assert!(
        state.get(&saved.id).is_ok(),
        "refused purge changed nothing"
    );

    state.trash_item(&saved.id).unwrap();
    state.purge_item(&saved.id).unwrap();

    assert!(state.get(&saved.id).is_err(), "purged item is gone");
    assert!(state.trash_list().unwrap().is_empty());
    assert_eq!(state.trash_count().unwrap(), 0);
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM items WHERE item_uuid = ?1",
            &saved.id
        ),
        0
    );
    assert_eq!(count(&conn, versions_sql, &saved.id), 0);
    assert_eq!(count(&conn, attachments_sql, &saved.id), 0);

    assert!(matches!(
        state.purge_item("does-not-exist"),
        Err(VaultError::NotFound)
    ));
}

#[test]
fn empty_trash_returns_the_number_purged_and_leaves_live_items_alone() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(PW).unwrap();

    let live = state.save(item("Keep me", Category::SecureNote)).unwrap();
    let a = state.save(item("A", Category::Login)).unwrap();
    let b = state.save(item("B", Category::Login)).unwrap();
    // Give `a` an archived version and an attachment so empty_trash has more
    // than the item row to clean up.
    let mut a2 = a.clone();
    a2.title = "A (edited)".into();
    state.save(a2).unwrap();

    let conn = Connection::open(&path).unwrap();
    let vault = vault_uuid(&conn, &a.id);
    conn.execute(
        "INSERT INTO attachments(vault_uuid, item_uuid, attachment_uuid, name, mime,
                                 size, digest, created_at, data)
         VALUES(?1, ?2, 'att-empty', 'note.txt', 'text/plain', 3, 'cafe', 0, ?3)",
        params![vault, a.id, vec![9u8, 8, 7]],
    )
    .unwrap();
    assert!(
        count(
            &conn,
            "SELECT COUNT(*) FROM item_versions WHERE item_uuid = ?1",
            &a.id
        ) >= 1
    );

    state.trash_item(&a.id).unwrap();
    state.trash_item(&b.id).unwrap();
    assert_eq!(state.trash_count().unwrap(), 2);

    assert_eq!(state.empty_trash().unwrap(), 2);

    assert_eq!(state.trash_count().unwrap(), 0);
    assert!(state.trash_list().unwrap().is_empty());
    assert!(state.get(&a.id).is_err());
    assert!(state.get(&b.id).is_err());

    let listed = state.list("", None, false).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, live.id);
    assert!(state.get(&live.id).is_ok());

    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM items WHERE item_uuid = ?1",
            &a.id
        ),
        0
    );
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM item_versions WHERE item_uuid = ?1",
            &a.id
        ),
        0
    );
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM attachments WHERE item_uuid = ?1",
            &a.id
        ),
        0
    );

    // Empty trash on an already-empty trash is a no-op.
    assert_eq!(state.empty_trash().unwrap(), 0);
}
