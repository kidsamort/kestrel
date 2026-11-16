//! Store hardening: atomicity of rotation/save, vault-scoped identity, and the
//! AAD split between live items and archived versions.
//!
//! Every test drives the public API and inspects the database file directly
//! where the invariant is about on-disk shape (triggers, copied blobs, meta
//! flags), so a regression in the SQL is visible rather than swallowed.

use kestrel_core::crypto;
use kestrel_core::model::{Category, Item};
use kestrel_core::session::{VaultError, VaultState};
use kestrel_core::store::{Store, StoreError};
use rusqlite::{params, Connection};

const OLD: &str = "correct horse battery staple";
const NEW: &str = "another long passphrase for rotation";
const ITEM_KEY_PURPOSE: &[u8] = b"kestrel/v1/items";

fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kestrel.db");
    (dir, path)
}

fn meta_bytes(path: &std::path::Path, key: &str) -> Vec<u8> {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
            r.get(0)
        })
        .unwrap()
}

fn item_versions_rows(path: &std::path::Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM item_versions", [], |r| r.get(0))
        .unwrap()
}

/// A trigger that aborts every insert into `items` simulates a crash in the
/// middle of a write; SQLite rolls the surrounding transaction back exactly as
/// it would after a process death between two statements.
fn add_failing_items_trigger(path: &std::path::Path) {
    Connection::open(path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_items_insert BEFORE INSERT ON items
             BEGIN SELECT RAISE(ABORT, 'injected store failure'); END;",
        )
        .unwrap();
}

fn drop_failing_items_trigger(path: &std::path::Path) {
    Connection::open(path)
        .unwrap()
        .execute_batch("DROP TRIGGER IF EXISTS fail_items_insert;")
        .unwrap();
}

/* ------------------------------------------------------- rotation atomicity */

#[test]
fn failed_rotation_leaves_the_old_password_and_all_data_in_place() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(OLD).unwrap();

    let mut item = state.create_default("login").unwrap();
    item.title = "first".into();
    let item = state.save(item).unwrap();
    let mut second = item.clone();
    second.title = "second".into();
    state.save(second).unwrap();
    // A draft is not stored, so the first save is v1 and the second archives
    // it. The archived version must survive a rolled-back rotation unchanged.
    let history_before: Vec<i64> = state
        .history_list(&item.id)
        .unwrap()
        .iter()
        .map(|v| v.version)
        .collect();
    assert_eq!(history_before, vec![1]);

    add_failing_items_trigger(&path);
    let rotation = state.change_password(OLD, NEW);
    assert!(
        rotation.is_err(),
        "the injected failure must abort the rotation"
    );
    drop_failing_items_trigger(&path);

    state.lock().unwrap();
    // The old salt/verifier were rolled back with everything else.
    assert!(
        state.unlock(OLD).is_ok(),
        "a half-rotated database must still open with the old password"
    );
    assert_eq!(state.get(&item.id).unwrap().title, "second");
    assert_eq!(
        state
            .history_list(&item.id)
            .unwrap()
            .iter()
            .map(|v| v.version)
            .collect::<Vec<_>>(),
        history_before
    );

    state.lock().unwrap();
    assert!(
        state.unlock(NEW).is_err(),
        "the new password must not work after a rolled-back rotation"
    );
}

/* ----------------------------------------------------------- save atomicity */

#[test]
fn failed_save_does_not_archive_a_version_that_was_never_stored() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(OLD).unwrap();

    let mut item = state.create_default("login").unwrap();
    item.title = "kept".into();
    let item = state.save(item).unwrap();
    // The draft was never stored, so this save archived nothing; a second save
    // is what creates one archive row to protect.
    assert_eq!(item_versions_rows(&path), 0);
    let mut kept = item.clone();
    kept.title = "kept again".into();
    let item = state.save(kept).unwrap();
    assert_eq!(item_versions_rows(&path), 1);

    add_failing_items_trigger(&path);
    let mut update = item.clone();
    update.title = "lost".into();
    assert!(state.save(update).is_err());
    drop_failing_items_trigger(&path);

    assert_eq!(
        item_versions_rows(&path),
        1,
        "the archive insert must roll back with the failed item write"
    );
    assert_eq!(state.get(&item.id).unwrap().title, "kept again");
    assert_eq!(
        state
            .history_list(&item.id)
            .unwrap()
            .iter()
            .map(|v| v.version)
            .collect::<Vec<_>>(),
        vec![1]
    );
}

/* --------------------------------------------------- vault-scoped identities */

#[test]
fn deleting_an_item_in_one_vault_leaves_the_same_uuid_alone_elsewhere() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(OLD).unwrap();
    let personal = state.state().unwrap().vault_uuid;
    let work = state.create_vault("Work").unwrap();

    let mut shared = Item::new(Category::Login, "shared id".into());
    shared.id = "0d0e6f4a-1111-4222-8333-444455556666".into();

    let mut first = shared.clone();
    first.title = "personal v1".into();
    let first = state.save(first).unwrap();
    let mut first_update = first.clone();
    first_update.title = "personal v2".into();
    state.save(first_update).unwrap();

    state.switch_vault(&work.uuid).unwrap();
    let mut second = shared.clone();
    second.title = "work v1".into();
    let second = state.save(second).unwrap();
    let mut second_update = second.clone();
    second_update.title = "work v2".into();
    state.save(second_update).unwrap();

    // Delete only the personal copy.
    state.switch_vault(&personal).unwrap();
    state.delete(&shared.id).unwrap();
    assert!(state.get(&shared.id).is_err());
    assert!(
        state.history_list(&shared.id).is_err(),
        "history went with it"
    );

    // The work vault is untouched: live row and archived version remain.
    state.switch_vault(&work.uuid).unwrap();
    assert_eq!(state.get(&shared.id).unwrap().title, "work v2");
    let work_history: Vec<i64> = state
        .history_list(&shared.id)
        .unwrap()
        .iter()
        .map(|v| v.version)
        .collect();
    assert_eq!(work_history, vec![1]);

    let counts: Vec<(String, i64)> = {
        let conn = Connection::open(&path).unwrap();
        let mut stmt = conn
            .prepare("SELECT vault_uuid, COUNT(*) FROM item_versions GROUP BY vault_uuid")
            .unwrap();
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        rows.map(|r| r.unwrap()).collect()
    };
    assert_eq!(counts, vec![(work.uuid.clone(), 1)]);
}

/* ------------------------------------------------------------------ AAD split */

#[test]
fn archived_blob_cannot_be_replayed_into_the_live_items_table() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(OLD).unwrap();

    let mut item = state.create_default("login").unwrap();
    item.title = "v1".into();
    let item = state.save(item).unwrap();
    let mut second = item.clone();
    second.title = "v2".into();
    state.save(second).unwrap();

    let (version, blob): (i64, Vec<u8>) = {
        let conn = Connection::open(&path).unwrap();
        conn.query_row(
            "SELECT version, data FROM item_versions WHERE item_uuid = ?1 AND vault_uuid = ?2",
            params![item.id, state.state().unwrap().vault_uuid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    };

    // Replay the archived ciphertext at its own version number. A version-only
    // AAD would accept this; the history kind must reject it.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE items SET version = ?1, data = ?2 WHERE item_uuid = ?3",
            params![version, blob, item.id],
        )
        .unwrap();
    }

    match state.get(&item.id) {
        Err(VaultError::Store(StoreError::Crypto(_))) => {}
        other => panic!("replayed archive must fail authenticated decryption, got {other:?}"),
    }
}

#[test]
fn unlock_reseals_legacy_history_blobs_with_the_history_aad() {
    let (_dir, path) = scratch();
    let item_id;
    let archived_version;
    {
        let state = VaultState::open(path.clone()).unwrap();
        state.create(OLD).unwrap();
        let mut item = state.create_default("login").unwrap();
        item.title = "first".into();
        let item = state.save(item).unwrap();
        item_id = item.id.clone();
        let mut second = item.clone();
        second.title = "second".into();
        state.save(second.clone()).unwrap();
        let mut third = second;
        third.title = "third".into();
        state.save(third).unwrap();
        archived_version = state.history_list(&item_id).unwrap()[0].version;
    }

    // Rewrite the archived row the way the legacy build did: the live-item AAD,
    // then clear the marker so the next unlock performs the migration.
    {
        let salt = meta_bytes(&path, "kdf_salt");
        let master = crypto::derive_master_key(OLD, &salt).unwrap();
        let vault_uuid = String::from_utf8(meta_bytes(&path, "default_vault_uuid")).unwrap();
        let account_uuid = String::from_utf8(meta_bytes(&path, "account_uuid")).unwrap();
        let vault_key = master
            .derive(vault_uuid.as_bytes(), ITEM_KEY_PURPOSE)
            .unwrap();
        let conn = Connection::open(&path).unwrap();
        // Per-item keys arrived in schema v9: each item's blobs are sealed with
        // its own key, wrapped under the vault key. Read that key so the
        // rewrite below swaps the AAD, not the sealing key.
        let wrapped: Vec<u8> = conn
            .query_row(
                "SELECT wrapped FROM item_keys WHERE vault_uuid = ?1 AND item_uuid = ?2",
                params![vault_uuid, item_id],
                |r| r.get(0),
            )
            .unwrap();
        let item_key = crypto::SymKey::from_slice(
            &crypto::decrypt(
                &vault_key,
                &crypto::object_aad("item-key", &account_uuid, &vault_uuid, &item_id, 1),
                &wrapped,
            )
            .unwrap(),
        )
        .unwrap();
        let rows: Vec<(i64, Vec<u8>)> = {
            let mut stmt = conn
                .prepare("SELECT version, data FROM item_versions WHERE item_uuid = ?1 AND vault_uuid = ?2")
                .unwrap();
            let mapped = stmt
                .query_map(params![item_id, vault_uuid], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
                })
                .unwrap();
            mapped.map(|r| r.unwrap()).collect()
        };
        assert_eq!(rows.len(), 2, "two saves archive two versions");
        for (version, blob) in rows {
            let history_aad = crypto::object_aad(
                "item-history",
                &account_uuid,
                &vault_uuid,
                &item_id,
                version,
            );
            let plain = crypto::decrypt(&item_key, &history_aad, &blob).unwrap();
            let legacy_aad =
                crypto::object_aad("item", &account_uuid, &vault_uuid, &item_id, version);
            let legacy = crypto::encrypt(&item_key, &legacy_aad, &plain).unwrap();
            conn.execute(
                "UPDATE item_versions SET data = ?1
                 WHERE item_uuid = ?2 AND vault_uuid = ?3 AND version = ?4",
                params![legacy, item_id, vault_uuid, version],
            )
            .unwrap();
        }
        conn.execute("DELETE FROM meta WHERE key = 'enc_version'", [])
            .unwrap();
    }

    let state = VaultState::open(path.clone()).unwrap();
    state.unlock(OLD).unwrap();
    assert_eq!(
        state.history_get(&item_id, archived_version).unwrap().title,
        "second",
        "the newest archived version holds the title that was replaced"
    );
    assert_eq!(meta_bytes(&path, "enc_version"), b"2");
    drop(state);

    // A second pass must be a no-op rather than decrypting already-migrated
    // rows with the old AAD (which would fail).
    {
        let store = Store::open(&path).unwrap();
        let (master, meta) = store.unlock(OLD).unwrap();
        store.migrate_encrypted(&master, &meta).unwrap();
        store.migrate_encrypted(&master, &meta).unwrap();
    }
    let state = VaultState::open(path.clone()).unwrap();
    state.unlock(OLD).unwrap();
    assert_eq!(
        state.history_get(&item_id, archived_version).unwrap().title,
        "second",
        "the newest archived version holds the title that was replaced"
    );
}

/* ---------------------------------------------------------- schema upgrade */

#[test]
fn a_v2_database_is_upgraded_to_vault_scoped_identities() {
    let (_dir, path) = scratch();
    let item_id;
    {
        let state = VaultState::open(path.clone()).unwrap();
        state.create(OLD).unwrap();
        let item = state.save(state.create_default("login").unwrap()).unwrap();
        item_id = item.id.clone();
        let mut second = item.clone();
        second.title = "newer".into();
        state.save(second).unwrap();
    }

    // Rebuild the tables exactly as schema v2 had them: vault names unmarked,
    // item uuids unique across the whole database, attachments keyed by uuid
    // alone. Only the marker is left for `migrate` to find.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE vaults_v2 (
                account_uuid TEXT NOT NULL,
                vault_uuid   TEXT NOT NULL,
                data         BLOB NOT NULL,
                PRIMARY KEY (account_uuid, vault_uuid)
            );
            INSERT INTO vaults_v2(account_uuid, vault_uuid, data)
                SELECT account_uuid, vault_uuid, data FROM vaults;
            DROP TABLE vaults;
            ALTER TABLE vaults_v2 RENAME TO vaults;

            CREATE TABLE item_versions_v2 (
                vault_uuid  TEXT NOT NULL,
                item_uuid   TEXT NOT NULL,
                version     INTEGER NOT NULL,
                archived_at INTEGER NOT NULL,
                data        BLOB NOT NULL,
                PRIMARY KEY (item_uuid, version)
            );
            INSERT INTO item_versions_v2(vault_uuid, item_uuid, version, archived_at, data)
                SELECT vault_uuid, item_uuid, version, archived_at, data FROM item_versions;
            DROP TABLE item_versions;
            ALTER TABLE item_versions_v2 RENAME TO item_versions;

            CREATE TABLE attachments_v2 (
                vault_uuid      TEXT NOT NULL,
                item_uuid       TEXT NOT NULL,
                attachment_uuid TEXT PRIMARY KEY,
                name            TEXT NOT NULL,
                mime            TEXT NOT NULL,
                size            INTEGER NOT NULL,
                digest          TEXT NOT NULL,
                created_at      INTEGER NOT NULL,
                data            BLOB NOT NULL
            );
            INSERT INTO attachments_v2
                SELECT vault_uuid, item_uuid, attachment_uuid, name, mime, size, digest, created_at, data
                FROM attachments;
            DROP TABLE attachments;
            ALTER TABLE attachments_v2 RENAME TO attachments;

            UPDATE meta SET value = '2' WHERE key = 'schema_version';
            "#,
        )
        .unwrap();
    }

    let state = VaultState::open(path.clone()).unwrap();
    state.unlock(OLD).unwrap();
    assert_eq!(state.get(&item_id).unwrap().title, "newer");
    assert_eq!(state.history_list(&item_id).unwrap().len(), 1);

    let conn = Connection::open(&path).unwrap();
    // Existing v2 vault names were derived-key sealed, so they are marked 2.
    let marked: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM vaults WHERE key_version = 2",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(marked, 1);

    // The rebuilt version table now allows one uuid per vault, and rejects a
    // duplicate within the same vault.
    conn.execute(
        "INSERT INTO item_versions(vault_uuid, item_uuid, version, archived_at, data)
         VALUES('vault-b', ?1, 1, 0, x'00')",
        params![item_id],
    )
    .unwrap();
    assert!(conn
        .execute(
            "INSERT INTO item_versions(vault_uuid, item_uuid, version, archived_at, data)
             VALUES('vault-b', ?1, 1, 0, x'00')",
            params![item_id],
        )
        .is_err());
}

/* ------------------------------------------------------------------ counters */

#[test]
fn live_count_tracks_the_active_vault_and_ignores_the_trash() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(OLD).unwrap();
    let personal = state.state().unwrap().vault_uuid;

    let item = state.save(state.create_default("login").unwrap()).unwrap();
    assert_eq!(state.state().unwrap().item_count, 1);

    state.trash_item(&item.id).unwrap();
    assert_eq!(
        state.state().unwrap().item_count,
        0,
        "a trashed item must not be counted"
    );

    // A different vault with its own item changes neither the other vault's
    // counter nor its contents.
    let work = state.create_vault("Work").unwrap();
    state.switch_vault(&work.uuid).unwrap();
    state
        .save(state.create_default("login").unwrap())
        .expect("item saved in the second vault");
    assert_eq!(state.state().unwrap().item_count, 1);
    state.switch_vault(&personal).unwrap();
    assert_eq!(state.state().unwrap().item_count, 0);
    assert_eq!(state.trash_count().unwrap(), 1);
}
