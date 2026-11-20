//! Windows Hello enrolment, status and unlock.
//!
//! The real mechanism raises a Windows Hello prompt inside `NCryptFinalizeKey`
//! and `NCryptDecrypt`, which no test can answer. Everything above the
//! [`Protector`] trait — the storage row, the mechanism it records, the session
//! it builds and every failure path — is exercised here with an in-memory
//! protector. That protector lives only in this test binary: the library has no
//! mock, no fallback and no test-only branch that ships.

use kestrel_core::crypto::SymKey;
use kestrel_core::hello::{HelloError, Mechanism, Protector};
use kestrel_core::model::{Category, Item};
use kestrel_core::session::{VaultError, VaultState};
use kestrel_core::store::SCHEMA_VERSION;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

const PW: &str = "correct horse battery staple";

fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kestrel.db");
    (dir, path)
}

/* ------------------------------------------------ test-only protector ---- */

#[derive(Clone, Copy, PartialEq)]
enum Behaviour {
    Working,
    /// Platform has no usable Hello (no TPM, provider missing).
    Unavailable,
    /// The user declines the prompt.
    Cancelled,
    /// Wrapping succeeds but the key that comes back is a different one.
    SubstituteKey,
}

#[derive(Clone)]
struct MemoryProtector {
    inner: Arc<Mutex<MemoryState>>,
}

struct MemoryState {
    keys: HashMap<String, [u8; 32]>,
    behaviour: Behaviour,
}

impl MemoryProtector {
    fn new(behaviour: Behaviour) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemoryState {
                keys: HashMap::new(),
                behaviour,
            })),
        }
    }

    fn working() -> Self {
        Self::new(Behaviour::Working)
    }

    fn behaviour(&self) -> Behaviour {
        self.inner.lock().unwrap().behaviour
    }

    fn key_count(&self) -> usize {
        self.inner.lock().unwrap().keys.len()
    }

    fn boxed(&self) -> Box<dyn Protector> {
        Box::new(self.clone())
    }
}

/// Test-only wrapper: prepend a marker and reverse the bytes, so a test can
/// tell "stored wrapped blob" from "master key in the clear". This is not a
/// cipher and is never compiled into the shipped library.
fn wrap(secret: &[u8]) -> Vec<u8> {
    let mut out = b"kestrel-test-wrap".to_vec();
    out.extend(secret.iter().rev());
    out
}

fn unwrap(blob: &[u8]) -> Option<Vec<u8>> {
    let body = blob.strip_prefix(b"kestrel-test-wrap".as_slice())?;
    Some(body.iter().rev().copied().collect())
}

impl Protector for MemoryProtector {
    fn probe(&self) -> Result<Mechanism, HelloError> {
        match self.behaviour() {
            Behaviour::Unavailable => Err(HelloError::Unavailable(
                "no TPM on this machine".to_string(),
            )),
            _ => Ok(Mechanism::TpmKey),
        }
    }

    fn protect(&self, name: &str, secret: &[u8]) -> Result<Vec<u8>, HelloError> {
        match self.behaviour() {
            Behaviour::Unavailable => return Err(HelloError::Unavailable("no TPM".into())),
            Behaviour::Cancelled => return Err(HelloError::Cancelled),
            _ => {}
        }
        assert_eq!(secret.len(), 32, "the wrapped secret is the master key");
        let mut inner = self.inner.lock().unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(secret);
        inner.keys.insert(name.to_string(), key);
        Ok(wrap(secret))
    }

    fn unprotect(&self, name: &str, blob: &[u8]) -> Result<SymKey, HelloError> {
        // A different key comes back with the same gesture: the wrapping
        // succeeds, the material is wrong.
        if self.behaviour() == Behaviour::SubstituteKey {
            return SymKey::from_slice(&[0xAB; 32]).map_err(|_| HelloError::WrongKey);
        }
        let plain = {
            let inner = self.inner.lock().unwrap();
            match inner.keys.get(name) {
                Some(key) => key.to_vec(),
                None => return Err(HelloError::MissingKey),
            }
        };
        match unwrap(blob) {
            Some(opened) if opened == plain => {
                SymKey::from_slice(&opened).map_err(|_| HelloError::WrongKey)
            }
            _ => Err(HelloError::Platform(
                "wrapped blob does not match the stored key".to_string(),
            )),
        }
    }

    fn forget(&self, name: &str) -> Result<(), HelloError> {
        match self.inner.lock().unwrap().keys.remove(name) {
            Some(_) => Ok(()),
            None => Err(HelloError::MissingKey),
        }
    }

    fn has_key(&self, name: &str) -> bool {
        self.inner.lock().unwrap().keys.contains_key(name)
    }
}

/* ------------------------------------------------------------- helpers ---- */

fn unlocked(protector: &MemoryProtector, path: &Path) -> VaultState {
    let state = VaultState::open_with_protector(path.to_path_buf(), protector.boxed())
        .expect("vault opens");
    state.create(PW).expect("vault created");
    state
}

fn hello_row(path: &Path) -> Option<(String, Vec<u8>, i64)> {
    let conn = rusqlite::Connection::open(path).expect("db opens");
    conn.query_row(
        "SELECT mechanism, wrapped, created_at FROM hello",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .ok()
}

fn schema_version(path: &Path) -> String {
    let conn = rusqlite::Connection::open(path).expect("db opens");
    conn.query_row(
        "SELECT value FROM meta WHERE key = 'schema_version'",
        [],
        |row| row.get(0),
    )
    .expect("schema version present")
}

fn table_exists(path: &Path, table: &str) -> bool {
    let conn = rusqlite::Connection::open(path).expect("db opens");
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |_| Ok(()),
    )
    .is_ok()
}

/// Remove the protector's key without touching the row: what a TPM clear, or
/// another tool deleting the key, looks like from the core's point of view.
fn drop_key(protector: &MemoryProtector, vault_uuid: &str) {
    let name = format!("kestrel-hello-v1-{vault_uuid}");
    let removed = protector.inner.lock().unwrap().keys.remove(&name);
    assert!(removed.is_some(), "the key was there to remove");
}

/* --------------------------------------------------------------- tests ---- */

#[test]
fn enroll_status_unlock_roundtrip() {
    let (_dir, path) = scratch();
    let protector = MemoryProtector::working();
    let state = unlocked(&protector, &path);

    let saved = state
        .save(Item::new(Category::Login, "Mail".to_string()))
        .expect("item saved");

    let before = state.hello_status().expect("status");
    assert!(before.available, "the protector reports itself usable");
    assert!(!before.enrolled, "nothing is enrolled yet");
    assert_eq!(before.mechanism, "");
    assert_eq!(before.created_at, None);

    let enrolled = state.hello_enroll().expect("enrolment");
    assert!(enrolled.enrolled);
    assert!(enrolled.available);
    assert_eq!(enrolled.mechanism, "tpm-key");
    assert!(enrolled.label.contains("Windows Hello"));
    assert!(enrolled.created_at.unwrap_or(0) > 0);

    // The row holds the mechanism and a wrapped blob — never the key itself.
    let (mechanism, wrapped, created_at) = hello_row(&path).expect("row written");
    assert_eq!(mechanism, "tpm-key");
    assert!(Mechanism::from_id(&mechanism).is_some());
    assert!(created_at > 0);
    assert!(
        wrapped.starts_with(b"kestrel-test-wrap"),
        "the blob is the protector's output"
    );
    assert_eq!(wrapped.len(), b"kestrel-test-wrap".len() + 32);

    // Lock, then open again with the gesture instead of the password.
    state.lock().expect("locked");
    let locked_status = state.hello_status().expect("status while locked");
    assert!(locked_status.enrolled, "status works while locked");

    let after = state.hello_unlock().expect("hello unlock");
    assert!(!after.locked);
    assert_eq!(after.vault_uuid, default_vault_uuid(&path));
    assert_eq!(after.item_count, 1);
    let items = state.list("", None, false).expect("items listed");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, saved.id);

    // The password still opens the same vault: Hello is additive.
    state.lock().unwrap();
    let by_password = state.unlock(PW).expect("password unlock");
    assert!(!by_password.locked);
}

fn default_vault_uuid(path: &Path) -> String {
    let conn = rusqlite::Connection::open(path).expect("db opens");
    conn.query_row(
        "SELECT value FROM meta WHERE key = 'default_vault_uuid'",
        [],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    .expect("default vault uuid")
}

#[test]
fn disable_removes_row_and_key() {
    let (_dir, path) = scratch();
    let protector = MemoryProtector::working();
    let state = unlocked(&protector, &path);
    state.hello_enroll().expect("enrolment");
    assert_eq!(protector.key_count(), 1);

    let disabled = state.hello_disable().expect("disable");
    assert!(!disabled.enrolled);
    assert!(disabled.available, "the machine can still enrol again");
    assert_eq!(disabled.mechanism, "");
    assert_eq!(protector.key_count(), 0, "the wrapping key is gone");
    assert!(hello_row(&path).is_none(), "the row is gone");

    state.lock().unwrap();
    match state.hello_unlock() {
        Err(VaultError::Hello(HelloError::NotEnrolled)) => {}
        other => panic!(
            "expected NotEnrolled, got {other:?}",
            other = other.map(|s| s.locked)
        ),
    }
    assert!(state.state().unwrap().locked, "still locked");
}

#[test]
fn re_enrolment_replaces_the_previous_wrapping() {
    let (_dir, path) = scratch();
    let protector = MemoryProtector::working();
    let state = unlocked(&protector, &path);
    state.hello_enroll().expect("first enrolment");
    let first = hello_row(&path).unwrap().1;
    state.hello_enroll().expect("second enrolment");
    let second = hello_row(&path).unwrap().1;
    assert_eq!(
        protector.key_count(),
        1,
        "one key per vault, not one per enrolment"
    );
    assert_eq!(state.hello_status().unwrap().enrolled, true);
    // Same master key, so the blob is the same; the point is that a second
    // enrolment succeeds instead of failing on an existing CNG key name.
    assert_eq!(first, second);
}

#[test]
fn a_substituted_key_is_rejected_before_it_becomes_a_session() {
    let (_dir, path) = scratch();
    let protector = MemoryProtector::working();
    let state = unlocked(&protector, &path);
    state.hello_enroll().expect("enrolment");
    state.lock().unwrap();

    // Same vault file and the same enrolment row, but a protector that hands
    // back different key material for the right gesture.
    drop(state);
    assert!(
        hello_row(&path).is_some(),
        "the enrolment survives the lock"
    );
    let impostor = MemoryProtector::new(Behaviour::SubstituteKey);
    let state = VaultState::open_with_protector(path.clone(), impostor.boxed()).unwrap();
    let error = state
        .hello_unlock()
        .expect_err("wrong key must not open the vault");
    match error {
        VaultError::Hello(HelloError::WrongKey) => {}
        other => panic!("expected WrongKey, got {other}"),
    }
    assert!(state.state().unwrap().locked, "no session was installed");
}

#[test]
fn cancelled_prompt_leaves_the_vault_locked_and_unchanged() {
    let (_dir, path) = scratch();
    let cancelling = MemoryProtector::new(Behaviour::Cancelled);
    let state = unlocked(&cancelling, &path);
    let error = state.hello_enroll().expect_err("cancelled enrolment fails");
    match error {
        VaultError::Hello(HelloError::Cancelled) => {}
        other => panic!("expected Cancelled, got {other}"),
    }
    assert!(!state.hello_status().unwrap().enrolled);
    assert!(hello_row(&path).is_none());
}

#[test]
fn unavailable_platform_is_reported_as_such() {
    let (_dir, path) = scratch();
    let unavailable = MemoryProtector::new(Behaviour::Unavailable);
    let state = unlocked(&unavailable, &path);

    let status = state.hello_status().expect("status is still readable");
    assert!(!status.available);
    assert!(!status.enrolled);
    let detail = status.detail.expect("the reason is surfaced");
    assert!(detail.contains("not available"), "detail: {detail}");

    let error = state.hello_enroll().expect_err("cannot enrol");
    assert!(matches!(
        error,
        VaultError::Hello(HelloError::Unavailable(_))
    ));
    assert!(hello_row(&path).is_none());
}

#[test]
fn enrolment_requires_an_unlocked_session() {
    let (_dir, path) = scratch();
    let protector = MemoryProtector::working();
    let state = unlocked(&protector, &path);
    state.lock().unwrap();
    let error = state.hello_enroll().expect_err("locked vault cannot enrol");
    assert!(matches!(error, VaultError::Locked), "got {error}");
}

#[test]
fn an_unknown_mechanism_is_reported_not_guessed() {
    let (_dir, path) = scratch();
    let protector = MemoryProtector::working();
    let state = unlocked(&protector, &path);
    let uuid = state.state().unwrap().vault_uuid;
    // A row from a newer build, with its key still present: the mechanism is
    // what this build cannot use, not the enrolment itself.
    protector
        .inner
        .lock()
        .unwrap()
        .keys
        .insert(format!("kestrel-hello-v1-{uuid}"), [0x11; 32]);
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO hello(vault_uuid, mechanism, wrapped, created_at)
             VALUES(?1, 'future-mechanism', X'00', 1)",
            [&uuid],
        )
        .unwrap();
    }
    let status = state.hello_status().unwrap();
    assert!(status.enrolled);
    assert!(!status.available, "the UI must not offer it");
    assert!(status.detail.unwrap().contains("unknown mechanism"));
    assert!(Mechanism::from_id("future-mechanism").is_none());

    state.lock().unwrap();
    match state.hello_unlock() {
        Err(VaultError::Hello(HelloError::UnknownMechanism(text))) => {
            assert_eq!(text, "future-mechanism")
        }
        other => panic!(
            "expected UnknownMechanism, got {other:?}",
            other = other.map(|s| s.locked)
        ),
    }
}

#[test]
fn a_password_change_drops_the_wrapped_key() {
    let (_dir, path) = scratch();
    let protector = MemoryProtector::working();
    let state = unlocked(&protector, &path);
    state.hello_enroll().expect("enrolment");

    // Re-keying changes the master key, so the wrapped copy is stale by
    // definition. Offering it would produce an unlock that fails the verifier.
    let next = state
        .change_password(PW, "a different long password")
        .expect("rotation");
    assert!(!next.locked);
    let status = state.hello_status().unwrap();
    assert!(!status.enrolled, "a stale enrolment must not survive");
    assert_eq!(protector.key_count(), 0, "the wrapping key is removed");

    state.lock().unwrap();
    match state.hello_unlock() {
        Err(VaultError::Hello(HelloError::NotEnrolled)) => {}
        other => panic!(
            "expected NotEnrolled, got {other:?}",
            other = other.map(|s| s.locked)
        ),
    }

    // The new password is the way in, and Hello can be enabled again.
    state
        .unlock("a different long password")
        .expect("new password");
    assert!(state.hello_enroll().expect("re-enrolment").enrolled);
}

#[test]
fn schema_v4_database_upgrades_and_keeps_its_items() {
    let (_dir, path) = scratch();
    let protector = MemoryProtector::working();
    let id = {
        let state = unlocked(&protector, &path);
        state
            .save(Item::new(Category::Password, "Router".to_string()))
            .expect("item saved")
            .id
    };
    // Rewind the file to the v4 shape: no `hello` table, version 4. This is a
    // real database on disk, not a freshly created one.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "DROP TABLE hello;
             UPDATE meta SET value = '4' WHERE key = 'schema_version';",
        )
        .unwrap();
    }
    assert!(!table_exists(&path, "hello"));
    assert_eq!(schema_version(&path), "4");

    // First open after the upgrade: table created, version bumped, data intact.
    let state = VaultState::open_with_protector(path.clone(), protector.boxed()).unwrap();
    assert_eq!(schema_version(&path), SCHEMA_VERSION.to_string());
    assert!(table_exists(&path, "hello"));
    let reopened = state.unlock(PW).expect("v4 password still opens the vault");
    assert_eq!(reopened.item_count, 1);
    assert_eq!(state.get(&id).unwrap().title, "Router");

    // The upgrade introduced no enrolment of its own.
    let status = state.hello_status().unwrap();
    assert!(!status.enrolled);
    assert!(status.available);

    // A second open is a no-op: same version, same item, enrolment preserved.
    let enrolled = state.hello_enroll().expect("enrol after upgrade");
    assert!(enrolled.enrolled);
    drop(state);
    let state = VaultState::open_with_protector(path.clone(), protector.boxed()).unwrap();
    assert_eq!(schema_version(&path), SCHEMA_VERSION.to_string());
    let status = state.hello_status().unwrap();
    assert!(status.enrolled, "the upgrade must not drop an enrolment");
    assert_eq!(state.unlock(PW).unwrap().item_count, 1);
}

#[test]
fn enrolling_from_a_switched_vault_lands_on_the_default_vault() {
    let (_dir, path) = scratch();
    let protector = MemoryProtector::working();
    let state = unlocked(&protector, &path);

    let second = state.create_vault("Work").expect("second vault");
    state.switch_vault(&second.uuid).expect("switched");
    assert_eq!(state.state().unwrap().vault_uuid, second.uuid);

    // The row belongs to the vault the Gate unlocks, not to the switched one.
    let status = state.hello_enroll().expect("enrolled");
    assert!(status.enrolled);

    let rows: Vec<String> = {
        let conn = rusqlite::Connection::open(&path).expect("db opens");
        let mut stmt = conn.prepare("SELECT vault_uuid FROM hello").unwrap();
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        rows
    };
    assert_eq!(rows.len(), 1, "exactly one enrolment row");
    assert_ne!(rows[0], second.uuid, "not the vault that was active");
    assert!(state.hello_status().unwrap().enrolled);

    state.lock().unwrap();
    let unlocked_state = state.hello_unlock().expect("unlocks the default vault");
    assert!(!unlocked_state.locked);
    assert_ne!(unlocked_state.vault_uuid, second.uuid);
}

#[test]
fn a_password_change_clears_every_enrolment() {
    let (_dir, path) = scratch();
    let protector = MemoryProtector::working();
    let state = unlocked(&protector, &path);
    let second = state.create_vault("Work").expect("second vault");

    // Enrol the default vault, then leave the switched vault active so the
    // rotation happens while another vault is selected.
    state.hello_enroll().expect("enrolled");
    assert_eq!(protector.key_count(), 1);

    state.switch_vault(&second.uuid).expect("switched");
    state
        .change_password(PW, "another long passphrase")
        .expect("rotated");

    assert!(
        !state.hello_status().unwrap().enrolled,
        "a re-key invalidates the enrolment of every vault"
    );
    assert_eq!(protector.key_count(), 0, "the wrapping key is forgotten");
    assert_eq!(hello_row(&path), None, "no row survives the rotation");
}

#[test]
fn a_row_without_its_key_is_not_an_enrolment() {
    let (_dir, path) = scratch();
    let protector = MemoryProtector::working();
    let state = unlocked(&protector, &path);
    state.hello_enroll().expect("enrolled");

    let uuid = state.state().unwrap().vault_uuid;
    drop_key(&protector, &uuid);

    let status = state.hello_status().expect("status");
    assert!(!status.enrolled, "a row without its key cannot unlock");
    assert_eq!(status.mechanism, "");
    assert!(
        status.detail.is_some(),
        "the user is told why the enrolment vanished"
    );

    // Enabling again repairs both halves.
    let repaired = state.hello_enroll().expect("re-enrolled");
    assert!(repaired.enrolled);
    state.lock().unwrap();
    assert!(!state.hello_unlock().expect("unlocks").locked);
}
