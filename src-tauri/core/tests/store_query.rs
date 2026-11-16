//! Store query layer: paging, counters and the plaintext search projection.
//!
//! The projection is the security boundary of this slice, so the search tests
//! are adversarial: they put password-shaped values into every field shape that
//! could leak (sensitive flag, secret kind, TOTP secret) and assert that neither
//! the stored projection nor a query can reach them. The migration tests open a
//! hand-built pre-R5 database and reopen it twice, because "already migrated"
//! is the case that must stay a no-op.

use kestrel_core::model::{Category, Field, Item};
use kestrel_core::session::VaultState;
use kestrel_core::store::{search_text, Store, StoreError};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

const PW: &str = "correct horse battery staple";

fn scratch() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kestrel.db");
    (dir, path)
}

fn text_field(label: &str, kind: &str, value: &str, sensitive: bool) -> Field {
    Field {
        id: uuid::Uuid::new_v4().to_string(),
        label: label.to_string(),
        kind: kind.to_string(),
        value: value.to_string(),
        sensitive,
    }
}

fn column_names(path: &Path, table: &str) -> Vec<String> {
    let conn = Connection::open(path).unwrap();
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .unwrap();
    let names = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    names
}

/* ------------------------------------------------------------ paging */

#[test]
fn pages_are_windows_of_a_stable_order_and_report_the_full_total() {
    let (_dir, path) = scratch();
    let store = Store::open(&path).unwrap();
    let (master, meta) = store.initialise(PW).unwrap();

    for n in 1..=5 {
        let mut item = Item::new(Category::Login, format!("Site {n:02}"));
        for field in item.fields.iter_mut() {
            if field.kind == "username" {
                field.value = format!("user{n}");
            }
        }
        store.save_item(&master, &meta, item).unwrap();
    }

    let first = store
        .list_page(&master, &meta, "", None, false, 2, 0)
        .unwrap();
    assert_eq!(first.total, 5, "total counts every matching row");
    assert_eq!(first.items.len(), 2);
    assert_eq!(
        first
            .items
            .iter()
            .map(|i| i.title.as_str())
            .collect::<Vec<_>>(),
        ["Site 01", "Site 02"]
    );

    let second = store
        .list_page(&master, &meta, "", None, false, 2, 2)
        .unwrap();
    assert_eq!(second.total, 5);
    assert_eq!(
        second
            .items
            .iter()
            .map(|i| i.title.as_str())
            .collect::<Vec<_>>(),
        ["Site 03", "Site 04"]
    );

    let last = store
        .list_page(&master, &meta, "", None, false, 2, 4)
        .unwrap();
    assert_eq!(last.total, 5);
    assert_eq!(
        last.items
            .iter()
            .map(|i| i.title.as_str())
            .collect::<Vec<_>>(),
        ["Site 05"],
        "the final page is short, not padded"
    );

    let beyond = store
        .list_page(&master, &meta, "", None, false, 10, 10)
        .unwrap();
    assert!(beyond.items.is_empty());
    assert_eq!(beyond.total, 5, "an out-of-range offset still reports 5");

    let empty_page = store
        .list_page(&master, &meta, "", None, false, 0, 0)
        .unwrap();
    assert!(empty_page.items.is_empty());
    assert_eq!(empty_page.total, 5);

    // The unpaged API is the same query without bounds, in the same order.
    let all = store.list(&master, &meta, "").unwrap();
    assert_eq!(all.len(), 5);
    assert_eq!(all[0].title, "Site 01");
    assert_eq!(all[4].title, "Site 05");
}

#[test]
fn category_and_favourite_filters_scope_items_and_total() {
    let (_dir, path) = scratch();
    let store = Store::open(&path).unwrap();
    let (master, meta) = store.initialise(PW).unwrap();

    let mut favourite_login = Item::new(Category::Login, "Mail".into());
    favourite_login.favorite = true;
    let mut plain_login = Item::new(Category::Login, "Bank".into());
    plain_login.fields.push(text_field("username", "username", "bob", false));
    store.save_item(&master, &meta, favourite_login).unwrap();
    store.save_item(&master, &meta, plain_login).unwrap();
    store
        .save_item(&master, &meta, Item::new(Category::SecureNote, "Recipe".into()))
        .unwrap();

    let logins = store
        .list_page(&master, &meta, "", Some("login"), false, 10, 0)
        .unwrap();
    assert_eq!(logins.total, 2);
    assert_eq!(logins.items.len(), 2);

    let favourites = store
        .list_page(&master, &meta, "", None, true, 10, 0)
        .unwrap();
    assert_eq!(favourites.total, 1);
    assert_eq!(favourites.items[0].title, "Mail");

    let none = store
        .list_page(&master, &meta, "", Some("secureNote"), true, 10, 0)
        .unwrap();
    assert_eq!(none.total, 0);
    assert!(none.items.is_empty());
}

/* ------------------------------------------------------------ counts */

#[test]
fn counts_track_trash_and_restore_per_category() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(PW).unwrap();
    let login = state.save(state.create_default("login").unwrap()).unwrap();
    state
        .save(state.create_default("secureNote").unwrap())
        .unwrap();

    let mut starred = state.get(&login.id).unwrap();
    starred.favorite = true;
    state.save(starred).unwrap();

    let store = Store::open(&path).unwrap();
    let (master, meta) = store.unlock(PW).unwrap();

    let live = store.counts(&meta).unwrap();
    assert_eq!(live.total, 2);
    assert_eq!(live.favorites, 1);
    assert_eq!(live.trash, 0);
    assert_eq!(live.categories.get("login"), Some(&1));
    assert_eq!(live.categories.get("secureNote"), Some(&1));

    state.trash_item(&login.id).unwrap();
    let trashed = store.counts(&meta).unwrap();
    assert_eq!(trashed.total, 1, "trashed rows leave the live total");
    assert_eq!(trashed.favorites, 0, "the trashed row was the favourite");
    assert_eq!(trashed.trash, 1);
    assert_eq!(trashed.categories.get("login"), None);
    assert_eq!(trashed.categories.get("secureNote"), Some(&1));
    assert_eq!(
        store
            .list_page(&master, &meta, "", None, false, 10, 0)
            .unwrap()
            .total,
        1,
        "paging and counts agree on what is live"
    );

    state.restore_item(&login.id).unwrap();
    let restored = store.counts(&meta).unwrap();
    assert_eq!(restored.total, 2);
    assert_eq!(restored.favorites, 1);
    assert_eq!(restored.trash, 0);
    assert_eq!(restored.categories.get("login"), Some(&1));
}

/* ------------------------------------------------------------ search */

#[test]
fn search_finds_non_secret_fields_notes_tags_and_urls() {
    let (_dir, path) = scratch();
    let store = Store::open(&path).unwrap();
    let (master, meta) = store.initialise(PW).unwrap();

    let mut item = Item::new(Category::Login, "Acme Portal".into());
    for field in item.fields.iter_mut() {
        match field.kind.as_str() {
            "username" => field.value = "deploy-bot".into(),
            "url" => field.value = "https://acme.example/login".into(),
            _ => {}
        }
    }
    item.tags = vec!["production".into()];
    item.notes = "rotated quarterly".into();
    let saved = store.save_item(&master, &meta, item).unwrap();

    let cases = ["deploy-bot", "DEPLOY", "acme", "production", "quarterly", "acme.example"];
    for needle in cases {
        let page = store
            .list_page(&master, &meta, needle, None, false, 10, 0)
            .unwrap();
        assert_eq!(page.total, 1, "query {needle:?} must find the item");
        assert_eq!(page.items[0].id, saved.id);
    }

    let miss = store
        .list_page(&master, &meta, "not present", None, false, 10, 0)
        .unwrap();
    assert_eq!(miss.total, 0);

    // `LIKE` wildcards in the needle are literal text, not a match-everything.
    store
        .save_item(
            &master,
            &meta,
            Item::new(Category::SecureNote, "Progress 100%".into()),
        )
        .unwrap();
    let percent = store
        .list_page(&master, &meta, "100%", None, false, 10, 0)
        .unwrap();
    assert_eq!(percent.total, 1);
    assert_eq!(percent.items[0].title, "Progress 100%");
    let wildcard_only = store
        .list_page(&master, &meta, "%", None, false, 10, 0)
        .unwrap();
    assert_eq!(
        wildcard_only.total, 1,
        "a bare % must match the literal percent, not every row"
    );
}

#[test]
fn passwords_and_sensitive_fields_never_reach_the_search_index() {
    let (_dir, path) = scratch();
    let store = Store::open(&path).unwrap();
    let (master, meta) = store.initialise(PW).unwrap();

    let mut item = Item::new(Category::Login, "Bank".into());
    for field in item.fields.iter_mut() {
        match field.kind.as_str() {
            "username" => field.value = "clerk".into(),
            "password" => field.value = "swordfish-42".into(),
            _ => {}
        }
    }
    // A sensitive field whose flag is set, a password-kind field whose flag a
    // hand-edited import cleared, and a TOTP secret.
    item.fields
        .push(text_field("recovery answer", "text", "purple-otter", true));
    item.fields.push(Field {
        id: uuid::Uuid::new_v4().to_string(),
        label: "legacy password".to_string(),
        kind: "password".to_string(),
        value: "flag-dropped-secret".to_string(),
        sensitive: false,
    });
    item.totp_secret = Some("JBSWY3DPEHPK3PXP".to_string());
    let saved = store.save_item(&master, &meta, item.clone()).unwrap();

    let projection = search_text(&item);
    for secret in [
        "swordfish-42",
        "purple-otter",
        "flag-dropped-secret",
        "JBSWY3DP",
        "legacy password",
    ] {
        assert!(
            !projection.contains(secret),
            "the projection must not contain {secret:?}: {projection}"
        );
        let page = store
            .list_page(&master, &meta, secret, None, false, 10, 0)
            .unwrap();
        assert_eq!(page.total, 0, "query {secret:?} must not match");
        assert!(
            store.list(&master, &meta, secret).unwrap().is_empty(),
            "the unpaged API must not match {secret:?} either"
        );
    }
    assert!(projection.contains("clerk"), "non-secret values stay searchable");
    assert!(projection.contains("bank"), "the title stays searchable");

    // The positive control proves the item exists and is listed.
    let listed = store
        .list_page(&master, &meta, "clerk", None, false, 10, 0)
        .unwrap();
    assert_eq!(listed.total, 1);
    assert_eq!(listed.items[0].id, saved.id);
}

/* --------------------------------------------------------- migration */

#[test]
fn schema_upgrade_adds_the_projection_to_a_legacy_database_and_is_idempotent() {
    let (_dir, path) = scratch();

    // The pre-R5 shape: `items` has no projection columns and the marker
    // claims v3. Everything else is created by the base schema on open.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
            CREATE TABLE items (
                account_uuid     TEXT NOT NULL,
                vault_uuid       TEXT NOT NULL,
                item_uuid        TEXT NOT NULL,
                local_edit_count INTEGER NOT NULL DEFAULT 0,
                version          INTEGER NOT NULL,
                data             BLOB NOT NULL,
                PRIMARY KEY (vault_uuid, item_uuid)
            );
            INSERT INTO meta(key, value) VALUES('schema_version', '3');
            "#,
        )
        .unwrap();
    }

    // First open migrates; the second open must find nothing to do. Both are
    // `Store::open`, which runs the whole ladder every time.
    drop(Store::open(&path).unwrap());
    drop(Store::open(&path).unwrap());

    let columns = column_names(&path, "items");
    for added in ["search_text", "category", "favorite"] {
        assert_eq!(
            columns.iter().filter(|name| *name == added).count(),
            1,
            "{added} must exist exactly once, columns: {columns:?}"
        );
    }

    let conn = Connection::open(&path).unwrap();
    let version: String = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        version,
        kestrel_core::store::SCHEMA_VERSION.to_string(),
        "the marker is written once, at the current version"
    );
    let index: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'items_query'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(index, 1, "the query index exists after the upgrade");
}

#[test]
fn unlock_backfills_rows_written_before_the_projection() {
    let (_dir, path) = scratch();
    let store = Store::open(&path).unwrap();
    let (master, meta) = store.initialise(PW).unwrap();

    let mut item = Item::new(Category::SecureNote, "Wifi card".into());
    item.notes = "guest network password is on the fridge".into();
    item.tags = vec!["home".into()];
    item.favorite = true;
    let saved = store.save_item(&master, &meta, item).unwrap();
    drop(store);

    // Strip the projection the way a v3 database does: the blob stays, the
    // plaintext columns are absent.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE items SET search_text = NULL, category = NULL, favorite = 0",
            [],
        )
        .unwrap();
    }

    let store = Store::open(&path).unwrap();
    let (master, meta) = store.unlock(PW).unwrap();

    let page = store
        .list_page(&master, &meta, "guest network", None, false, 10, 0)
        .unwrap();
    assert_eq!(page.total, 1, "unlock indexed the legacy row");
    assert_eq!(page.items[0].id, saved.id);

    let counts = store.counts(&meta).unwrap();
    assert_eq!(counts.total, 1);
    assert_eq!(counts.favorites, 1, "the favourite flag was rebuilt too");
    assert_eq!(counts.categories.get("secureNote"), Some(&1));

    let conn = Connection::open(&path).unwrap();
    let unindexed: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM items WHERE search_text IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(unindexed, 0);
}

/* ------------------------------------------------------- single-row read */

#[test]
fn get_decrypts_only_the_requested_row() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).unwrap();
    state.create(PW).unwrap();

    let mut target = state.create_default("login").unwrap();
    target.title = "target".into();
    let target = state.save(target).unwrap();

    let mut binned = state.create_default("login").unwrap();
    binned.title = "binned".into();
    let binned = state.save(binned).unwrap();
    state.trash_item(&binned.id).unwrap();

    for index in 0..5 {
        let mut other = state.create_default("login").unwrap();
        other.title = format!("other {index}");
        state.save(other).unwrap();
    }

    // Every row except the two under test loses its ciphertext: a read that
    // decrypts the vault instead of one row cannot survive this, a row-scoped
    // read never looks at them.
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE items SET data = x'00' WHERE item_uuid NOT IN (?1, ?2)",
        params![target.id, binned.id],
    )
    .unwrap();
    drop(conn);

    let store = Store::open(&path).unwrap();
    let (master, meta) = store.unlock(PW).unwrap();

    let item = store
        .get(&master, &meta, &target.id)
        .expect("the requested row is intact");
    assert_eq!(item.title, "target");

    // The trash hides a row from the list, not from a direct read.
    let trashed = store
        .get(&master, &meta, &binned.id)
        .expect("a trashed row stays readable");
    assert_eq!(trashed.title, "binned");

    assert!(matches!(
        store.get(&master, &meta, "no-such-item"),
        Err(StoreError::NotFound)
    ));
}
