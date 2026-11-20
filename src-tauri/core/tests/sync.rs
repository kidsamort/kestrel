//! Schema v11, the store-side sync bookkeeping and the pure merge rule.
//!
//! Everything runs against a real SQLite file in a tempdir and real
//! XChaCha20-Poly1305 blobs — there is no mock store and no fake clock. The
//! tests pin the pieces the sync engine will depend on: the upgrade from v10,
//! dirty-row ordering, malformed-clock refusal, the four clock orderings, each
//! merge branch (including tombstones and removed fields) and the AAD binding
//! of a sealed body.

use kestrel_core::crypto::{self, CryptoError, SymKey};
use kestrel_core::model::{Category, Field, Item};
use kestrel_core::store::sync::SyncConflictRow;
use kestrel_core::store::{Store, StoreError, SCHEMA_VERSION};
use kestrel_core::sync::body::{open_body, seal_body, sync_aad};
use kestrel_core::sync::merge::{field_paths, merge_bodies, Merge, SyncBody};
use kestrel_core::sync::{bump, compare, merge_clocks, Clock, Ordering};
use rusqlite::{Connection, OptionalExtension};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const PASSWORD: &str = "correct horse battery staple";
const VAULT: &str = "vault-a";

fn scratch() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kestrel.db");
    (dir, path)
}

fn initialised(path: &Path) -> Store {
    let store = Store::open(path).expect("open store");
    store.initialise(PASSWORD).expect("initialise");
    store
}

fn schema_version(path: &Path) -> String {
    Connection::open(path)
        .expect("raw open")
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("schema_version")
}

fn table_exists(path: &Path, table: &str) -> bool {
    Connection::open(path)
        .expect("raw open")
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(()),
        )
        .optional()
        .expect("sqlite_master")
        .is_some()
}

fn clock(entries: &[(&str, u64)]) -> Clock {
    entries
        .iter()
        .map(|(device, counter)| (device.to_string(), *counter))
        .collect()
}

fn base_item() -> Item {
    Item {
        id: "item-1".to_string(),
        title: "base".to_string(),
        category: Category::Login,
        fields: Vec::new(),
        notes: String::new(),
        urls: Vec::new(),
        tags: Vec::new(),
        favorite: false,
        totp_secret: None,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
    }
}

fn field(id: &str, value: &str) -> Field {
    Field {
        id: id.to_string(),
        label: id.to_string(),
        kind: "text".to_string(),
        value: value.to_string(),
        sensitive: false,
    }
}

fn sync_body(item: Item, deleted: bool, clocks: &[(&str, Clock)]) -> SyncBody {
    SyncBody {
        item,
        deleted,
        clocks: clocks
            .iter()
            .map(|(path, clock)| (path.to_string(), clock.clone()))
            .collect::<BTreeMap<_, _>>(),
    }
}

/* ---------------------------------------------------------------- schema ---- */

#[test]
fn a_v10_database_gains_the_sync_tables() {
    let (_dir, path) = scratch();
    {
        let store = initialised(&path);
        assert!(store.is_initialised().unwrap());
    }

    // Rewind to the v10 shape with raw SQL: the three sync tables did not
    // exist, and the version marker says 10.
    {
        let conn = Connection::open(&path).expect("raw open");
        conn.execute_batch(
            "DROP TABLE sync_items;
             DROP TABLE sync_conflicts;
             DROP TABLE sync_meta;
             UPDATE meta SET value = '10' WHERE key = 'schema_version';",
        )
        .expect("rewind to v10");
    }
    assert_eq!(schema_version(&path), "10");
    for table in ["sync_items", "sync_conflicts", "sync_meta"] {
        assert!(!table_exists(&path, table), "{table} should be gone");
    }

    let store = Store::open(&path).expect("v10 vault upgrades");
    assert_eq!(schema_version(&path), SCHEMA_VERSION.to_string());
    for table in ["sync_items", "sync_conflicts", "sync_meta"] {
        assert!(table_exists(&path, table), "{table} should exist");
    }
    assert!(store.is_initialised().unwrap(), "the vault itself survived");

    // The new metadata table round-trips a value and survives a reopen.
    assert_eq!(store.sync_meta_get("cursor").unwrap(), None);
    store.sync_meta_set("cursor", "42").unwrap();
    assert_eq!(
        store.sync_meta_get("cursor").unwrap().as_deref(),
        Some("42")
    );
    assert!(store.sync_state(VAULT, "item-1").unwrap().is_none());
    drop(store);

    let store = Store::open(&path).expect("second open is a no-op");
    assert_eq!(schema_version(&path), SCHEMA_VERSION.to_string());
    assert_eq!(
        store.sync_meta_get("cursor").unwrap().as_deref(),
        Some("42")
    );
}

/* ------------------------------------------------------------ item state ---- */

#[test]
fn dirty_rows_are_ordered_limited_and_marked_clean() {
    let (_dir, path) = scratch();
    let store = initialised(&path);
    let first = clock(&[("device-a", 1)]);

    store.sync_upsert(VAULT, "item-b", &first, true).unwrap();
    store.sync_upsert(VAULT, "item-a", &first, true).unwrap();
    store.sync_upsert(VAULT, "item-c", &first, false).unwrap();
    store.sync_upsert(VAULT, "item-d", &first, true).unwrap();

    let dirty = store.sync_dirty(VAULT, 10).unwrap();
    let ids: Vec<&str> = dirty.iter().map(|state| state.item_id.as_str()).collect();
    assert_eq!(ids, vec!["item-a", "item-b", "item-d"]);
    assert!(dirty.iter().all(|state| state.dirty));
    assert_eq!(dirty[0].clock, first);
    assert_eq!(dirty[0].body, None, "no push has been acknowledged yet");

    let limited = store.sync_dirty(VAULT, 2).unwrap();
    let ids: Vec<&str> = limited.iter().map(|state| state.item_id.as_str()).collect();
    assert_eq!(ids, vec!["item-a", "item-b"]);

    // A later write of the same item replaces the clock but keeps the row.
    let mut second = first.clone();
    bump(&mut second, "device-a");
    store.sync_upsert(VAULT, "item-a", &second, true).unwrap();
    assert_eq!(store.sync_dirty(VAULT, 10).unwrap().len(), 3);
    assert_eq!(
        store.sync_state(VAULT, "item-a").unwrap().unwrap().clock,
        second
    );

    // Marking clean clears the flag and keeps the settled clock.
    store.sync_mark_clean(VAULT, "item-a", &second).unwrap();
    let state = store.sync_state(VAULT, "item-a").unwrap().expect("row");
    assert!(!state.dirty);
    assert_eq!(state.clock, second);

    let pending = store.sync_dirty(VAULT, 10).unwrap();
    let remaining: Vec<&str> = pending
        .iter()
        .map(|state| state.item_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(remaining, vec!["item-b", "item-d"]);

    // An upsert after a clean write queues the item again.
    let mut third = second.clone();
    bump(&mut third, "device-a");
    store.sync_upsert(VAULT, "item-a", &third, true).unwrap();
    let state = store.sync_state(VAULT, "item-a").unwrap().expect("row");
    assert!(state.dirty);

    assert!(store.sync_state(VAULT, "absent").unwrap().is_none());
    assert!(matches!(
        store.sync_mark_clean(VAULT, "absent", &third),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn refused_and_malformed_clocks_are_errors() {
    let (_dir, path) = scratch();
    let store = initialised(&path);

    assert!(matches!(
        store.sync_upsert(VAULT, "item-1", &Clock::new(), true),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.sync_upsert(VAULT, "item-1", &clock(&[("device-a", 0)]), true),
        Err(StoreError::Invalid(_))
    ));
    assert!(store.sync_state(VAULT, "item-1").unwrap().is_none());

    let good = clock(&[("device-a", 1)]);
    store.sync_upsert(VAULT, "item-1", &good, true).unwrap();
    {
        let conn = Connection::open(store.path()).expect("raw open");
        conn.execute(
            "UPDATE sync_items SET clock = '{\"device-a\": \"one\"}' WHERE item_id = 'item-1'",
            [],
        )
        .expect("corrupt clock");
    }
    assert!(matches!(
        store.sync_state(VAULT, "item-1"),
        Err(StoreError::Json(_))
    ));
    assert!(matches!(
        store.sync_dirty(VAULT, 10),
        Err(StoreError::Json(_))
    ));

    // The conflict table decodes its clocks the same way.
    let row = SyncConflictRow {
        item_id: "item-2".to_string(),
        local_clock: good.clone(),
        remote_clock: good,
        local_body: vec![1, 2, 3],
        remote_body: vec![4, 5, 6],
        created_at: 5,
    };
    store.sync_conflict_put(VAULT, &row).unwrap();
    {
        let conn = Connection::open(store.path()).expect("raw open");
        conn.execute(
            "UPDATE sync_conflicts SET remote_clock = 'not json' WHERE item_id = 'item-2'",
            [],
        )
        .expect("corrupt clock");
    }
    assert!(matches!(
        store.sync_conflicts(VAULT),
        Err(StoreError::Json(_))
    ));
}

/* ----------------------------------------------------------------- clocks ---- */

#[test]
fn compare_orders_clocks_without_timestamps() {
    assert_eq!(
        compare(&clock(&[("a", 1), ("b", 2)]), &clock(&[("b", 2), ("a", 1)])),
        Ordering::Equal
    );
    assert_eq!(
        compare(&clock(&[("a", 2), ("b", 1)]), &clock(&[("a", 1), ("b", 1)])),
        Ordering::Dominates
    );
    assert_eq!(
        compare(&clock(&[("a", 1), ("b", 1)]), &clock(&[("a", 2), ("b", 1)])),
        Ordering::Dominated
    );
    assert_eq!(
        compare(&clock(&[("a", 2), ("b", 1)]), &clock(&[("a", 1), ("b", 2)])),
        Ordering::Concurrent
    );

    // A missing device key is counter zero.
    assert_eq!(
        compare(&clock(&[("a", 1)]), &Clock::new()),
        Ordering::Dominates
    );
    assert_eq!(
        compare(&Clock::new(), &clock(&[("a", 1)])),
        Ordering::Dominated
    );
    assert_eq!(compare(&clock(&[("a", 0)]), &Clock::new()), Ordering::Equal);

    // A key present on one side only is still an ordering, not a conflict.
    assert_eq!(
        compare(&clock(&[("a", 1), ("b", 1)]), &clock(&[("a", 1)])),
        Ordering::Dominates
    );
    assert_eq!(
        compare(&clock(&[("a", 1)]), &clock(&[("a", 1), ("b", 1)])),
        Ordering::Dominated
    );

    assert_eq!(
        merge_clocks(&clock(&[("a", 1), ("b", 2)]), &clock(&[("b", 3), ("c", 0)])),
        clock(&[("a", 1), ("b", 3)])
    );
    let mut bumped = Clock::new();
    bump(&mut bumped, "dev");
    assert_eq!(bumped, clock(&[("dev", 1)]));
    bump(&mut bumped, "dev");
    assert_eq!(bumped, clock(&[("dev", 2)]));
}

/* ------------------------------------------------------------------ merge ---- */

#[test]
fn field_paths_name_every_syncable_value() {
    let mut item = base_item();
    item.fields = vec![field("f1", "a"), field("f2", "b")];
    let expected: BTreeSet<String> = [
        "title",
        "category",
        "notes",
        "urls",
        "tags",
        "favorite",
        "totp_secret",
        "fields.f1",
        "fields.f2",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(field_paths(&item), expected);
}

#[test]
fn a_dominating_item_clock_decides_without_looking_at_fields() {
    let local = sync_body(base_item(), false, &[]);
    let mut remote_item = base_item();
    remote_item.title = "remote".to_string();
    let remote = sync_body(remote_item, false, &[]);

    assert_eq!(
        merge_bodies(
            &local,
            &clock(&[("a", 2)]),
            &remote,
            &clock(&[("a", 1)]),
            "c"
        ),
        Merge::Local
    );
    assert_eq!(
        merge_bodies(
            &local,
            &clock(&[("a", 1)]),
            &remote,
            &clock(&[("a", 2)]),
            "c"
        ),
        Merge::Remote
    );
    // Identical clocks mean identical state: nothing to do.
    assert_eq!(
        merge_bodies(
            &local,
            &clock(&[("a", 1)]),
            &remote,
            &clock(&[("a", 1)]),
            "c"
        ),
        Merge::Local
    );
}

#[test]
fn concurrent_disjoint_changes_merge_without_conflicts() {
    let mut local_item = base_item();
    local_item.title = "mine".to_string();
    let mut remote_item = base_item();
    remote_item.notes = "theirs".to_string();

    let local = sync_body(
        local_item,
        false,
        &[("title", clock(&[("a", 2), ("b", 1)]))],
    );
    let remote = sync_body(
        remote_item,
        false,
        &[("notes", clock(&[("a", 1), ("b", 2)]))],
    );
    let local_clock = clock(&[("a", 2), ("b", 1)]);
    let remote_clock = clock(&[("a", 1), ("b", 2)]);

    match merge_bodies(&local, &local_clock, &remote, &remote_clock, "c") {
        Merge::Merged {
            body,
            clock: merged_clock,
            conflicts,
        } => {
            assert!(conflicts.is_empty(), "{conflicts:?}");
            assert_eq!(body.item.title, "mine");
            assert_eq!(body.item.notes, "theirs");
            assert!(!body.deleted);
            assert_eq!(merged_clock, clock(&[("a", 2), ("b", 2), ("c", 1)]));
            assert_eq!(compare(&merged_clock, &local_clock), Ordering::Dominates);
            assert_eq!(compare(&merged_clock, &remote_clock), Ordering::Dominates);
            // The unchanged local value keeps its clock; the adopted remote
            // value is bumped for the merging device.
            assert_eq!(
                body.clocks.get("title"),
                Some(&clock(&[("a", 2), ("b", 1)]))
            );
            assert_eq!(
                body.clocks.get("notes"),
                Some(&clock(&[("a", 1), ("b", 2), ("c", 1)]))
            );
        }
        other => panic!("expected a merged body, got {other:?}"),
    }
}

#[test]
fn the_same_field_changed_on_both_sides_is_a_conflict() {
    let mut local_item = base_item();
    local_item.title = "mine".to_string();
    let mut remote_item = base_item();
    remote_item.title = "theirs".to_string();

    let local = sync_body(
        local_item,
        false,
        &[("title", clock(&[("a", 2), ("b", 1)]))],
    );
    let remote = sync_body(
        remote_item,
        false,
        &[("title", clock(&[("a", 1), ("b", 2)]))],
    );

    match merge_bodies(
        &local,
        &clock(&[("a", 2), ("b", 1)]),
        &remote,
        &clock(&[("a", 1), ("b", 2)]),
        "c",
    ) {
        Merge::Merged {
            body, conflicts, ..
        } => {
            assert_eq!(conflicts, vec!["title".to_string()]);
            assert_eq!(body.item.title, "mine", "the local value is kept");
            assert_eq!(
                body.clocks.get("title"),
                Some(&clock(&[("a", 2), ("b", 2)])),
                "an unresolved conflict is not bumped past the remote side"
            );
        }
        other => panic!("expected a merged body, got {other:?}"),
    }
}

#[test]
fn a_field_removed_on_one_side_does_not_resurrect() {
    let removed = "fields.f1";
    // Local removed the field; its clock is newer than the remote copy.
    let mut local_item = base_item();
    local_item.fields = Vec::new();
    let mut remote_item = base_item();
    remote_item.fields = vec![field("f1", "old")];

    let local = sync_body(
        local_item.clone(),
        false,
        &[(removed, clock(&[("a", 2), ("b", 1)]))],
    );
    let remote = sync_body(
        remote_item.clone(),
        false,
        &[(removed, clock(&[("a", 1), ("b", 1)]))],
    );
    match merge_bodies(
        &local,
        &clock(&[("a", 2), ("b", 1)]),
        &remote,
        &clock(&[("a", 1), ("b", 2)]),
        "c",
    ) {
        Merge::Merged {
            body, conflicts, ..
        } => {
            assert!(conflicts.is_empty());
            assert!(body.item.fields.is_empty(), "the removal stands");
            assert_eq!(
                body.clocks.get(removed),
                Some(&clock(&[("a", 2), ("b", 1)]))
            );
        }
        other => panic!("expected a merged body, got {other:?}"),
    }

    // The remote side removed it with the newer clock: the field disappears
    // locally too, and the removal clock is bumped for this device.
    let local = sync_body(
        remote_item,
        false,
        &[(removed, clock(&[("a", 1), ("b", 1)]))],
    );
    let remote = sync_body(
        local_item,
        false,
        &[(removed, clock(&[("a", 1), ("b", 2)]))],
    );
    match merge_bodies(
        &local,
        &clock(&[("a", 2), ("b", 1)]),
        &remote,
        &clock(&[("a", 1), ("b", 2)]),
        "c",
    ) {
        Merge::Merged {
            body, conflicts, ..
        } => {
            assert!(conflicts.is_empty());
            assert!(body.item.fields.is_empty(), "the remote removal stands");
            assert_eq!(
                body.clocks.get(removed),
                Some(&clock(&[("a", 1), ("b", 2), ("c", 1)]))
            );
        }
        other => panic!("expected a merged body, got {other:?}"),
    }
}

#[test]
fn a_tombstone_concurrent_with_an_edit_is_a_conflict() {
    let removed = "deleted";
    let mut remote_item = base_item();
    remote_item.notes = "remote edit".to_string();

    // Local deleted the item; remote edited a field. The item clocks are
    // concurrent, so the tombstone must not silently win.
    let local = sync_body(
        base_item(),
        true,
        &[(removed, clock(&[("a", 2), ("b", 1)]))],
    );
    let remote = sync_body(
        remote_item.clone(),
        false,
        &[("notes", clock(&[("a", 1), ("b", 2)]))],
    );
    match merge_bodies(
        &local,
        &clock(&[("a", 2), ("b", 1)]),
        &remote,
        &clock(&[("a", 1), ("b", 2)]),
        "c",
    ) {
        Merge::Merged {
            body,
            clock: merged_clock,
            conflicts,
        } => {
            assert_eq!(conflicts, vec!["deleted".to_string()]);
            assert!(body.deleted, "the local tombstone is kept for review");
            assert_eq!(body.item.notes, "remote edit");
            assert_eq!(
                compare(&merged_clock, &clock(&[("a", 2), ("b", 1)])),
                Ordering::Dominates
            );
            assert_eq!(
                compare(&merged_clock, &clock(&[("a", 1), ("b", 2)])),
                Ordering::Dominates
            );
            assert_eq!(merged_clock.get("c"), Some(&1));
        }
        other => panic!("expected a merged body, got {other:?}"),
    }

    // The mirror case: the remote tombstone's own clock dominates, but the item
    // clocks are concurrent, so the local live item is kept and the conflict is
    // surfaced instead of losing the password.
    let local = sync_body(
        base_item(),
        false,
        &[("title", clock(&[("a", 2), ("b", 1)]))],
    );
    let remote = sync_body(
        base_item(),
        true,
        &[(removed, clock(&[("a", 1), ("b", 2)]))],
    );
    match merge_bodies(
        &local,
        &clock(&[("a", 2), ("b", 1)]),
        &remote,
        &clock(&[("a", 1), ("b", 2)]),
        "c",
    ) {
        Merge::Merged {
            body, conflicts, ..
        } => {
            assert_eq!(conflicts, vec!["deleted".to_string()]);
            assert!(!body.deleted, "a concurrent delete never wins silently");
        }
        other => panic!("expected a merged body, got {other:?}"),
    }
}

/* ------------------------------------------------------------- sealed body ---- */

#[test]
fn sealed_bodies_are_bound_to_their_item_and_account() {
    let key = SymKey::from_slice(&[7u8; crypto::KEY_LEN]).expect("key");
    let body = sync_body(
        base_item(),
        false,
        &[("title", clock(&[("a", 2), ("b", 1)]))],
    );

    let at = clock(&[("a", 3)]);
    let blob = seal_body(&key, "account-1", "item-1", &at, &body).expect("seal");
    assert_eq!(
        open_body(&key, "account-1", "item-1", &at, &blob).expect("open"),
        body
    );

    // The AAD binds the item id, the account id and the clock.
    assert!(matches!(
        open_body(&key, "account-1", "item-2", &at, &blob),
        Err(CryptoError::Decrypt)
    ));
    assert!(matches!(
        open_body(&key, "account-2", "item-1", &at, &blob),
        Err(CryptoError::Decrypt)
    ));
    // The clock is authenticated, so a hostile service cannot replay an old
    // body under a clock that dominates the local one.
    let later = clock(&[("a", 9)]);
    assert!(matches!(
        open_body(&key, "account-1", "item-1", &later, &blob),
        Err(CryptoError::Decrypt)
    ));

    // A body whose item.id disagrees with the argument is refused on seal...
    let mut mismatched = body.clone();
    mismatched.item.id = "item-9".to_string();
    assert!(matches!(
        seal_body(&key, "account-1", "item-1", &at, &mismatched),
        Err(CryptoError::Malformed)
    ));

    // ...and on open, even when the ciphertext itself is valid for the AAD.
    let plain = serde_json::to_vec(&mismatched).expect("json");
    let crafted =
        crypto::encrypt(&key, &sync_aad("account-1", "item-1", &at), &plain).expect("seal");
    assert!(matches!(
        open_body(&key, "account-1", "item-1", &at, &crafted),
        Err(CryptoError::Malformed)
    ));

    // A tampered blob is rejected by the AEAD, not parsed.
    let mut tampered = blob.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(matches!(
        open_body(&key, "account-1", "item-1", &at, &tampered),
        Err(CryptoError::Decrypt)
    ));
}

/* --------------------------------------------------------------- conflicts ---- */

#[test]
fn conflicts_replace_per_item_and_reset_wipes_everything() {
    let (_dir, path) = scratch();
    let store = initialised(&path);
    let local_clock = clock(&[("a", 1)]);
    let remote_clock = clock(&[("b", 2)]);

    let first = SyncConflictRow {
        item_id: "item-1".to_string(),
        local_clock: local_clock.clone(),
        remote_clock: remote_clock.clone(),
        local_body: vec![1, 2, 3],
        remote_body: vec![4, 5, 6],
        created_at: 100,
    };
    store.sync_conflict_put(VAULT, &first).unwrap();

    let mut replacement = first.clone();
    replacement.remote_body = vec![9, 9];
    replacement.created_at = 101;
    store.sync_conflict_put(VAULT, &replacement).unwrap();
    assert_eq!(
        store.sync_conflicts(VAULT).unwrap(),
        vec![replacement.clone()]
    );

    let second = SyncConflictRow {
        item_id: "item-0".to_string(),
        local_clock: local_clock.clone(),
        remote_clock,
        local_body: vec![7],
        remote_body: vec![8],
        created_at: 102,
    };
    store.sync_conflict_put(VAULT, &second).unwrap();
    assert_eq!(
        store.sync_conflicts(VAULT).unwrap(),
        vec![second.clone(), replacement.clone()],
        "conflicts are ordered by item id"
    );

    store.sync_conflict_clear(VAULT, "item-0").unwrap();
    assert_eq!(store.sync_conflicts(VAULT).unwrap(), vec![replacement]);

    // Reset clears clocks, conflicts and metadata together.
    store
        .sync_upsert(VAULT, "item-1", &local_clock, true)
        .unwrap();
    store.sync_meta_set("cursor", "5").unwrap();
    store.sync_reset().unwrap();
    assert!(store.sync_conflicts(VAULT).unwrap().is_empty());
    assert!(store.sync_state(VAULT, "item-1").unwrap().is_none());
    assert_eq!(store.sync_meta_get("cursor").unwrap(), None);
}

/// The two ways the engine could silently move nothing or the wrong thing:
/// items saved before this device had an identity, and a second vault in the
/// same file.
#[test]
fn backfill_queues_old_items_and_a_second_vault_stays_separate() {
    let (_dir, path) = scratch();
    let store = Store::open(&path).expect("open store");
    let (master, meta) = store.initialise(PASSWORD).expect("initialise");
    // No device row yet: a save must not invent a clock it cannot attribute.
    let item = base_item();
    store.save_item(&master, &meta, item.clone()).expect("save");
    assert!(
        store
            .sync_state(&meta.vault_uuid, &item.id)
            .unwrap()
            .is_none(),
        "a vault without an account records nothing"
    );

    // The first identity is what lets a backfill attribute the write.
    let identity = store.device_identity(&master).expect("device identity");
    let seeded = store
        .sync_backfill(&meta.vault_uuid, &identity.device_id)
        .expect("backfill");
    assert_eq!(seeded, 1);
    let state = store
        .sync_state(&meta.vault_uuid, &item.id)
        .unwrap()
        .expect("row");
    assert!(
        state.dirty,
        "the first sync must upload what the vault holds"
    );
    assert_eq!(state.clock.get(&identity.device_id), Some(&1));

    // Idempotent: a second run cannot re-queue an item the server already has.
    assert_eq!(
        store
            .sync_backfill(&meta.vault_uuid, &identity.device_id)
            .expect("second backfill"),
        0
    );

    // Another vault in the same file has its own rows and its own dirty set.
    let other = store
        .create_vault(&master, &meta, "Second")
        .expect("second vault");
    assert!(
        store.sync_dirty(&other.uuid, 10).unwrap().is_empty(),
        "vault B must not inherit vault A's pending items"
    );
    assert_eq!(store.sync_dirty(&meta.vault_uuid, 10).unwrap().len(), 1);
    assert_eq!(store.vault_count().unwrap(), 2);
}

/// Forgetting a server must keep what each item knows. Deleting the clocks made
/// the next run re-seed every item at `{device: 1}`, and a server clock of
/// `{device: 3}` then dominated a locally edited item and overwrote it.
#[test]
fn forgetting_a_server_keeps_the_item_clocks_and_drops_the_metadata() {
    let (_dir, path) = scratch();
    let store = Store::open(&path).expect("open store");
    let (master, _meta) = store.initialise(PASSWORD).expect("initialise");
    let identity = store.device_identity(&master).expect("identity");
    let mut clock = clock(&[(&identity.device_id, 7)]);
    store.sync_upsert(VAULT, "item-1", &clock, false).unwrap();
    store
        .sync_set_body(VAULT, "item-1", b"sealed", &clock)
        .unwrap();
    store.sync_meta_set("cursor", "42").unwrap();
    store
        .sync_conflict_put(
            VAULT,
            &SyncConflictRow {
                item_id: "item-1".to_string(),
                local_clock: clock.clone(),
                remote_clock: clock.clone(),
                local_body: vec![1],
                remote_body: vec![2],
                created_at: 1,
            },
        )
        .unwrap();

    store.sync_forget_server().expect("forget");

    assert_eq!(
        store.sync_meta_get("cursor").unwrap(),
        None,
        "the cursor belongs to the server"
    );
    assert!(
        store.sync_conflicts(VAULT).unwrap().is_empty(),
        "conflicts belong to the server"
    );
    let state = store
        .sync_state(VAULT, "item-1")
        .unwrap()
        .expect("the item clock survives: it protects the content");
    assert_eq!(state.clock, clock);
    assert_eq!(state.body.as_deref(), Some(&b"sealed"[..]));

    // And a re-seed cannot overwrite that clock with `{device: 1}`.
    let before = clock.clone();
    bump(&mut clock, &identity.device_id);
    store
        .sync_backfill(VAULT, &identity.device_id)
        .expect("backfill");
    assert_eq!(
        store.sync_state(VAULT, "item-1").unwrap().unwrap().clock,
        before,
        "backfill leaves an existing row alone"
    );
}

/// Pointing at another server queues everything: the new service has never seen
/// this vault, and the old one's acknowledged bodies mean nothing to it.
#[test]
fn requeueing_for_a_new_server_drops_baselines_and_queues_every_item() {
    let (_dir, path) = scratch();
    let store = Store::open(&path).expect("open store");
    let (master, _meta) = store.initialise(PASSWORD).expect("initialise");
    let identity = store.device_identity(&master).expect("identity");
    let clock = clock(&[(&identity.device_id, 2)]);
    for id in ["item-a", "item-b"] {
        store.sync_upsert(VAULT, id, &clock, false).unwrap();
        store.sync_set_body(VAULT, id, b"sealed", &clock).unwrap();
    }
    assert_eq!(
        store.sync_counts(VAULT).unwrap().0,
        0,
        "nothing pending yet"
    );

    assert_eq!(store.sync_requeue_all().expect("requeue"), 2);

    let (dirty, _) = store.sync_counts(VAULT).unwrap();
    assert_eq!(dirty, 2, "a new server must receive every item");
    let state = store.sync_state(VAULT, "item-a").unwrap().unwrap();
    assert_eq!(state.body, None, "the old server's baseline is meaningless");
    assert_eq!(state.body_clock, None);
    assert_eq!(
        state.clock, clock,
        "the clock is kept: it still protects the item"
    );
}
