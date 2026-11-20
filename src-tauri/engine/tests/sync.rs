//! End-to-end tests: two real vault files, the real service on an ephemeral
//! port, and the real TLS-less loopback client.
//!
//! Nothing about the server, the store, the merge or the seal is mocked. Each
//! test boots `kestrel-sync` in a thread with its own SQLite file and blob
//! directory, creates an account through [`SyncClient`] on device A, enrols
//! device B through the same endpoint flow the app uses, and then drives
//! [`sync_once`] on both sides.
//!
//! The tests own the local-write seam the app owns in production: after
//! `save_item` or `set_trashed`, the test records the write with a bumped
//! version vector and the dirty flag, which is exactly what makes the engine
//! push it. No test reaches into SQL or fakes a clock.

use std::net::SocketAddr;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use kestrel_core::crypto::SymKey;
use kestrel_core::model::{Category, Item};
use kestrel_core::store::{Store, StoreError, VaultMeta};
use kestrel_core::sync::{bump, Clock};
use kestrel_engine::{
    conflict_views, resolve_conflict, sync_once, ConflictView, EngineError, ResolveChoice,
    SyncContext, SyncReport,
};
use kestrel_net::{ClientConfig, SyncClient};
use kestrel_sync::{Config as ServerConfig, Server};
use tempfile::TempDir;

const PASSWORD: &str = "correct horse battery staple";

/* --------------------------------------------------------------- helpers ---- */

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after the epoch")
        .as_secs() as i64
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn hex_decode(text: &str) -> Vec<u8> {
    fn digit(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            other => panic!("{other:?} is not hex"),
        }
    }
    let bytes = text.as_bytes();
    assert!(bytes.len().is_multiple_of(2), "odd hex length: {text:?}");
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| (digit(pair[0]) << 4) | digit(pair[1]))
        .collect()
}

/// Standard base64, the encoding the enrolment endpoint uses for `sealed`.
/// The net crate encodes it; the test has to decode it back to feed the core's
/// hex-shaped claim input, and this crate does not depend on `base64` itself.
fn base64_decode(text: &str) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for byte in text.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        let value = TABLE
            .iter()
            .position(|candidate| *candidate == byte)
            .unwrap_or_else(|| panic!("{byte:?} is not base64")) as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    out
}

fn agreement_bytes(hex: &str) -> [u8; 32] {
    let bytes = hex_decode(hex);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn field_value(item: &Item, label: &str) -> String {
    item.fields
        .iter()
        .find(|field| field.label == label)
        .unwrap_or_else(|| panic!("item has no field labelled {label:?}"))
        .value
        .clone()
}

fn set_field(item: &mut Item, label: &str, value: &str) {
    let field = item
        .fields
        .iter_mut()
        .find(|field| field.label == label)
        .unwrap_or_else(|| panic!("item has no field labelled {label:?}"));
    field.value = value.to_string();
}

/* ---------------------------------------------------------------- server ---- */

/// The real service, in-process on an ephemeral port. Shaped exactly like the
/// net crate's test harness: a tokio runtime in a thread, a oneshot to stop it,
/// a tempdir for the database and blobs.
struct TestServer {
    addr: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    _dir: TempDir,
}

impl TestServer {
    fn start() -> TestServer {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = ServerConfig {
            addr: "127.0.0.1:0".parse().expect("valid address"),
            db_path: dir.path().join("server.db"),
            blob_dir: dir.path().join("blobs"),
            ..ServerConfig::default()
        };

        let (addr_tx, addr_rx) = mpsc::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("tokio runtime");
            runtime.block_on(async move {
                let server = Server::bind(config)
                    .await
                    .expect("the store opens and the socket binds");
                addr_tx.send(server.local_addr()).expect("address reported");
                server
                    .run(async move {
                        let _ = stop_rx.await;
                    })
                    .await
                    .expect("the server runs until asked to stop");
            });
        });

        let addr = addr_rx.recv().expect("the server started");
        TestServer {
            addr,
            stop: Some(stop_tx),
            thread: Some(thread),
            _dir: dir,
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        // `dir` is dropped after this impl runs; it removes the database and
        // blobs once the server thread has stopped using them.
    }
}

/* ---------------------------------------------------------------- device ---- */

/// One vault file wired to the service: everything a caller needs to build a
/// [`SyncContext`], plus the local-write helpers the app would own.
struct Device {
    store: Store,
    master: SymKey,
    meta: VaultMeta,
    account_key: SymKey,
    account_id: String,
    device_id: String,
    client: SyncClient,
    _dir: TempDir,
}

impl Device {
    fn context(&self) -> SyncContext<'_> {
        SyncContext {
            store: &self.store,
            master: &self.master,
            meta: &self.meta,
            account_id: &self.account_id,
            account_key: &self.account_key,
            device_id: &self.device_id,
            client: &self.client,
        }
    }

    fn sync(&self) -> SyncReport {
        sync_once(&self.context()).expect("sync_once")
    }

    fn views(&self) -> Vec<ConflictView> {
        conflict_views(&self.context()).expect("conflict_views")
    }

    fn resolve(&self, item_id: &str, choice: ResolveChoice) {
        resolve_conflict(&self.context(), item_id, choice).expect("resolve_conflict");
    }

    /// Create an item and record the local write the way the app does.
    fn create(&self, item: Item) -> Item {
        let saved = self
            .store
            .save_item(&self.master, &self.meta, item)
            .expect("save_item");
        let mut clock = Clock::new();
        clock.insert(self.device_id.clone(), 1);
        self.store
            .sync_upsert(&self.meta.vault_uuid, &saved.id, &clock, true)
            .expect("sync_upsert");
        saved
    }

    /// Save a changed item and bump this device's counter.
    fn edit(&self, item: Item) -> Item {
        let saved = self
            .store
            .save_item(&self.master, &self.meta, item)
            .expect("save_item");
        self.touch(&saved.id);
        saved
    }

    fn trash(&self, item_id: &str) {
        self.store
            .set_trashed(&self.meta, item_id, true)
            .expect("trash");
        self.touch(item_id);
    }

    fn touch(&self, item_id: &str) {
        let mut clock = self
            .store
            .sync_state(&self.meta.vault_uuid, item_id)
            .expect("sync_state")
            .map(|state| state.clock)
            .unwrap_or_default();
        bump(&mut clock, &self.device_id);
        self.store
            .sync_upsert(&self.meta.vault_uuid, item_id, &clock, true)
            .expect("sync_upsert");
    }

    fn get(&self, item_id: &str) -> Item {
        self.store
            .get(&self.master, &self.meta, item_id)
            .expect("get")
    }

    fn is_trashed(&self, item_id: &str) -> bool {
        self.store
            .is_trashed(&self.meta, item_id)
            .expect("is_trashed")
    }
}

fn open_vault() -> (TempDir, Store, SymKey, VaultMeta) {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = Store::open(dir.path().join("vault.db")).expect("open store");
    let (master, meta) = store.initialise(PASSWORD).expect("initialise");
    (dir, store, master, meta)
}

/// Create device A's vault and account through the real endpoint, then enrol
/// device B through offer → claim → ack, exactly as the app does.
fn pair(base_url: &str) -> (Device, Device) {
    // --- device A creates the account ---------------------------------------
    let (dir_a, store_a, master_a, meta_a) = open_vault();
    let created = store_a.account_create(&master_a).expect("account_create");
    let identity_a = store_a.device_identity(&master_a).expect("identity a");
    let keys_a = store_a.device_secret_keys(&master_a).expect("keys a");
    let account_id = created.account_id.clone();

    let client_a = SyncClient::new(ClientConfig {
        base_url: base_url.to_string(),
        account_id: account_id.clone(),
        device_id: identity_a.device_id.clone(),
        signing_key: *keys_a.signing_secret(),
        allow_insecure: false,
    })
    .expect("client a");
    let registered = client_a
        .create_account(agreement_bytes(&identity_a.agreement_pub), "Device A")
        .expect("register device A");
    assert_eq!(registered.account_id, account_id);

    // --- device B has its own keypair before it has an account --------------
    let (dir_b, store_b, master_b, meta_b) = open_vault();
    let identity_b = store_b.device_identity(&master_b).expect("identity b");
    let keys_b = store_b.device_secret_keys(&master_b).expect("keys b");

    let code = store_a.account_enrol_code();
    let sealed = store_a
        .account_seal_for_device(&master_a, &code.code, &identity_b.agreement_pub)
        .expect("seal the account key for B");
    client_a
        .enroll_offer(
            &identity_b.device_id,
            &code.code,
            &hex_decode(&sealed.sealed),
            unix_now() + 600,
        )
        .expect("offer");

    let client_b = SyncClient::new(ClientConfig {
        base_url: base_url.to_string(),
        account_id: account_id.clone(),
        device_id: identity_b.device_id.clone(),
        signing_key: *keys_b.signing_secret(),
        allow_insecure: false,
    })
    .expect("client b");
    let claim = client_b
        .enroll_claim(
            &code.code,
            agreement_bytes(&identity_b.agreement_pub),
            "Device B",
        )
        .expect("claim");
    assert_eq!(claim.account_id, account_id);
    let claimed = store_b
        .account_enroll_claim(
            &master_b,
            &code.code,
            &hex_encode(&base64_decode(&claim.sealed)),
            &sealed.sender_agreement_pub,
        )
        .expect("store the claimed account");
    assert_eq!(claimed.account_id, account_id);
    client_a
        .enroll_ack(&identity_b.device_id)
        .expect("acknowledge B");

    let account_key_a = store_a.account_key(&master_a).expect("account key a");
    let account_key_b = store_b.account_key(&master_b).expect("account key b");

    let a = Device {
        store: store_a,
        master: master_a,
        meta: meta_a,
        account_key: account_key_a,
        account_id: account_id.clone(),
        device_id: identity_a.device_id,
        client: client_a,
        _dir: dir_a,
    };
    let b = Device {
        store: store_b,
        master: master_b,
        meta: meta_b,
        account_key: account_key_b,
        account_id,
        device_id: identity_b.device_id,
        client: client_b,
        _dir: dir_b,
    };
    (a, b)
}

fn login(title: &str) -> Item {
    Item::new(Category::Login, title.to_string())
}

/* ----------------------------------------------------------------- tests ---- */

#[test]
fn a_created_item_reaches_the_second_device() {
    let server = TestServer::start();
    let (a, b) = pair(&server.base_url());

    let item = a.create(login("Mail"));
    let report_a = a.sync();
    assert_eq!(report_a.pushed, 1);
    assert_eq!(report_a.pulled, 0);

    let report_b = b.sync();
    assert_eq!(report_b.pulled, 1);
    assert_eq!(report_b.pushed, 0);

    let on_b = b.get(&item.id);
    assert_eq!(on_b.title, "Mail");
    assert_eq!(on_b.category, Category::Login);
    assert_eq!(on_b.fields.len(), item.fields.len());
    for (left, right) in on_b.fields.iter().zip(&item.fields) {
        assert_eq!(left.id, right.id);
        assert_eq!(left.label, right.label);
        assert_eq!(left.kind, right.kind);
        assert_eq!(left.value, right.value);
        assert_eq!(left.sensitive, right.sensitive);
    }
}

#[test]
fn disjoint_edits_merge_field_by_field_without_a_conflict() {
    let server = TestServer::start();
    let (a, b) = pair(&server.base_url());
    let item = a.create(login("Shared login"));
    a.sync();
    b.sync();

    // B edits the title; A edits the password of the same item.
    let mut b_item = b.get(&item.id);
    b_item.title = "Shared by B".to_string();
    b.edit(b_item);
    let mut a_item = a.get(&item.id);
    set_field(&mut a_item, "password", "secret-from-a");
    a.edit(a_item);

    a.sync(); // A's field is accepted
    b.sync(); // B pulls it, merges around its title, pushes the merge
    a.sync(); // A adopts the merge

    assert!(a.views().is_empty(), "a disjoint change is not a conflict");
    assert!(b.views().is_empty(), "a disjoint change is not a conflict");

    for device in [&a, &b] {
        let final_item = device.get(&item.id);
        assert_eq!(final_item.title, "Shared by B");
        assert_eq!(field_value(&final_item, "password"), "secret-from-a");
    }
}

#[test]
fn the_same_field_changed_on_both_sides_surfaces_a_conflict_and_converges() {
    let server = TestServer::start();
    let (a, b) = pair(&server.base_url());
    let item = a.create(login("Contested"));
    a.sync();
    b.sync();

    // Both sides change the same field before either syncs.
    let mut a_item = a.get(&item.id);
    a_item.title = "A version".to_string();
    a.edit(a_item);
    let mut b_item = b.get(&item.id);
    b_item.title = "B version".to_string();
    b.edit(b_item);

    a.sync(); // A's write lands
    b.sync(); // B pulls it concurrently, then its own push is rejected

    let views = b.views();
    assert_eq!(
        views.len(),
        1,
        "the side whose push lost holds the conflict"
    );
    let view = &views[0];
    assert_eq!(view.item_id, item.id);
    assert_eq!(view.title, "B version");
    assert_eq!(view.remote_device, a.device_id);
    let title = view
        .fields
        .iter()
        .find(|field| field.path == "title")
        .expect("the title is named");
    assert_eq!(title.local, "B version");
    assert_eq!(title.remote, "A version");
    assert!(!title.sensitive);
    assert_eq!(
        b.get(&item.id).title,
        "B version",
        "nothing changed silently"
    );
    assert_eq!(
        a.get(&item.id).title,
        "A version",
        "nothing changed silently"
    );
    assert!(
        a.views().is_empty(),
        "the side the server accepted has nothing to resolve"
    );

    // B keeps its value and pushes a clock that dominates both.
    b.resolve(&item.id, ResolveChoice::Mine);
    b.sync();
    assert!(b.views().is_empty());

    // A now writes again before pulling the settlement, so A also conflicts.
    let mut a_item = a.get(&item.id);
    a_item.title = "A again".to_string();
    a.edit(a_item);
    a.sync();

    let views = a.views();
    assert_eq!(views.len(), 1);
    let title = views[0]
        .fields
        .iter()
        .find(|field| field.path == "title")
        .expect("the title is named");
    assert_eq!(title.local, "A again");
    assert_eq!(title.remote, "B version");
    assert_eq!(views[0].remote_device, b.device_id);

    // A takes theirs, both sync again and both hold the same value.
    a.resolve(&item.id, ResolveChoice::Theirs);
    a.sync();
    b.sync();

    assert_eq!(a.get(&item.id).title, "B version");
    assert_eq!(b.get(&item.id).title, "B version");
    assert!(a.views().is_empty());
    assert!(b.views().is_empty());
}

#[test]
fn a_delete_concurrent_with_an_edit_is_a_conflict_not_a_silent_delete() {
    let server = TestServer::start();
    let (a, b) = pair(&server.base_url());
    let item = a.create(login("Delete me"));
    a.sync();
    b.sync();

    a.trash(&item.id);
    let mut b_item = b.get(&item.id);
    b_item.notes = "still needed".to_string();
    b.edit(b_item);

    a.sync(); // the tombstone lands
    b.sync(); // B pulls it concurrently and its live push is rejected

    assert!(a.is_trashed(&item.id));
    assert!(!b.is_trashed(&item.id), "the edit did not delete the item");
    assert_eq!(b.get(&item.id).notes, "still needed");

    let views = b.views();
    assert_eq!(views.len(), 1);
    let deleted = views[0]
        .fields
        .iter()
        .find(|field| field.path == "deleted")
        .expect("the tombstone is the conflicting path");
    assert_eq!(deleted.label, "Deleted");
    assert_eq!(deleted.local, "live");
    assert_eq!(deleted.remote, "deleted");

    // Keeping the local (live) item restores it on the other device too.
    b.resolve(&item.id, ResolveChoice::Mine);
    b.sync();
    a.sync();

    assert!(!a.is_trashed(&item.id));
    assert_eq!(a.get(&item.id).notes, "still needed");
    assert!(a.views().is_empty());
    assert!(b.views().is_empty());
}

#[test]
fn a_second_sync_with_no_changes_pulls_and_pushes_nothing() {
    let server = TestServer::start();
    let (a, b) = pair(&server.base_url());
    a.create(login("Steady"));
    a.sync();
    b.sync();

    let again_a = a.sync();
    assert_eq!(again_a.pulled, 0);
    assert_eq!(again_a.pushed, 0);
    let again_b = b.sync();
    assert_eq!(again_b.pulled, 0);
    assert_eq!(again_b.pushed, 0);
}

#[test]
fn an_unseen_tombstone_records_the_clock_without_creating_a_row() {
    let server = TestServer::start();
    let (a, b) = pair(&server.base_url());

    // A can publish a tombstone for an item it never had: the id is opaque and
    // the service creates the row from the operation.
    let tombstone_id = "never-seen-item";
    let mut clock = Clock::new();
    clock.insert(a.device_id.clone(), 9);
    a.store
        .sync_upsert(&a.meta.vault_uuid, tombstone_id, &clock, true)
        .expect("queue the tombstone");
    let report = a.sync();
    assert_eq!(report.pushed, 1);

    b.sync();

    assert!(
        matches!(
            b.store.get(&b.master, &b.meta, tombstone_id),
            Err(StoreError::NotFound)
        ),
        "a tombstone must not create an item"
    );
    assert!(matches!(
        b.store.is_trashed(&b.meta, tombstone_id),
        Err(StoreError::NotFound)
    ));
    let state = b
        .store
        .sync_state(&b.meta.vault_uuid, tombstone_id)
        .expect("sync_state")
        .expect("the clock is recorded");
    assert_eq!(state.clock, clock);
    assert!(!state.dirty);
    assert_eq!(state.body, None, "a tombstone carries no body");
}

#[test]
fn keeping_both_sides_saves_the_remote_item_under_a_new_id() {
    let server = TestServer::start();
    let (a, b) = pair(&server.base_url());
    let item = a.create(login("Keep both"));
    a.sync();
    b.sync();

    let mut a_item = a.get(&item.id);
    a_item.title = "A version".to_string();
    a.edit(a_item);
    let mut b_item = b.get(&item.id);
    b_item.title = "B version".to_string();
    b.edit(b_item);

    a.sync();
    b.sync();
    assert_eq!(b.views().len(), 1);

    assert!(matches!(
        resolve_conflict(&b.context(), "no-such-conflict", ResolveChoice::Mine),
        Err(EngineError::NoConflict(_))
    ));

    b.resolve(&item.id, ResolveChoice::Both);
    b.sync();
    a.sync();

    assert_eq!(b.get(&item.id).title, "B version");
    assert_eq!(a.get(&item.id).title, "B version");

    let copy = b
        .store
        .load_all(&b.master, &b.meta)
        .expect("load_all")
        .into_iter()
        .find(|candidate| candidate.title == "A version (conflict copy)")
        .expect("the remote value was kept under a new id");
    assert_ne!(copy.id, item.id);
    assert!(
        a.store.get(&a.master, &a.meta, &copy.id).is_ok(),
        "the copy is pushed like any other item and reaches A"
    );
    assert!(a.views().is_empty());
    assert!(b.views().is_empty());
}

#[test]
fn an_unparsable_cursor_is_refused_instead_of_restarting_from_zero() {
    let server = TestServer::start();
    let (a, _b) = pair(&server.base_url());
    a.store
        .sync_meta_set("cursor", "not-a-cursor")
        .expect("write a bad cursor");

    let error = sync_once(&a.context()).expect_err("a bad cursor is refused");
    assert!(matches!(error, EngineError::Cursor(_)));

    // The failure is recorded for the status line and the bad value is kept:
    // silently rewriting it to zero is exactly what must not happen.
    assert_eq!(
        a.store.sync_meta_get("state").expect("state").as_deref(),
        Some("error")
    );
    assert!(a.store.sync_meta_get("error").expect("error").is_some());
    assert_eq!(
        a.store.sync_meta_get("cursor").expect("cursor").as_deref(),
        Some("not-a-cursor")
    );
}

/// A push whose response was lost is the one retry that looks like a conflict:
/// the client re-seals the same content, so the ciphertext differs while the
/// clock does not. The server refuses to pick a winner; the engine has to
/// recognise its own earlier write and settle it, or the row stays dirty
/// forever and every later run reports the same conflict.
#[test]
fn a_lost_push_response_settles_instead_of_conflicting_forever() {
    let server = TestServer::start();
    let (a, b) = pair(&server.base_url());
    let item = a.create(login("Retried"));
    a.sync();
    b.sync();
    assert_eq!(b.get(&item.id).title, "Retried");

    // Simulate the lost acknowledgement: the item is on the server under this
    // clock, but this device believes it still has to push it.
    let state = a
        .store
        .sync_state(&a.meta.vault_uuid, &item.id)
        .expect("sync_state")
        .expect("row");
    a.store
        .sync_upsert(&a.meta.vault_uuid, &item.id, &state.clock, true)
        .expect("re-queue");

    let report = a.sync();
    assert_eq!(report.conflicts, 0, "our own write is not a conflict");
    assert!(
        a.views().is_empty(),
        "no conflict row may be stored for a retry"
    );
    let after = a
        .store
        .sync_state(&a.meta.vault_uuid, &item.id)
        .expect("sync_state")
        .expect("row");
    assert!(!after.dirty, "the retry must settle the row");

    // And the other device still sees exactly one item with the same content.
    b.sync();
    let b_item = b.get(&item.id);
    assert_eq!(b_item.title, "Retried");
}
