//! The sync account, the Secret Key, enrolment envelopes and per-item keys.
//!
//! These tests drive the parts that decide whether a second device can receive
//! the account key and whether a vault written by an older build stays readable:
//! account creation and the one-shot Secret Key, the X25519/AEAD envelope, the
//! checksum gate, and the lazy per-item-key migration with its bytes-on-disk
//! proof.

use kestrel_core::crypto::{self, SymKey};
use kestrel_core::model::{Category, Item};
use kestrel_core::session::VaultState;
use kestrel_core::store::{
    agreement_public, agreement_secret, open_sealed_account, seal_account_key, Store, VaultMeta,
};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "a different long passphrase";

fn scratch() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kestrel.db");
    (dir, path)
}

/// A store initialised with a password, plus the keys an older build would have
/// used: the master key and the vault identity.
fn initialised(path: &Path) -> (Store, SymKey, VaultMeta) {
    let store = Store::open(path).expect("open store");
    let (master, meta) = store.initialise(PASSWORD).expect("initialise");
    (store, master, meta)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex"))
        .collect()
}

fn item_counts(path: &Path) -> (i64, i64) {
    let conn = Connection::open(path).expect("second connection");
    let keys: i64 = conn
        .query_row("SELECT COUNT(*) FROM item_keys", [], |row| row.get(0))
        .expect("item_keys count");
    let items: i64 = conn
        .query_row("SELECT COUNT(*) FROM items", [], |row| row.get(0))
        .expect("items count");
    (items, keys)
}

fn item_blob(path: &Path, id: &str) -> Vec<u8> {
    Connection::open(path)
        .expect("second connection")
        .query_row(
            "SELECT data FROM items WHERE item_uuid = ?1",
            params![id],
            |row| row.get(0),
        )
        .expect("item blob")
}

/// Write an item the way a build before schema v9 did: sealed directly with the
/// vault item key, no `item_keys` row. This is the population the backfill must
/// migrate without losing anything.
fn insert_legacy_item(path: &Path, master: &SymKey, meta: &VaultMeta, id: &str, title: &str) {
    let mut item = Item::new(Category::Login, title.to_string());
    item.id = id.to_string();
    let plain = serde_json::to_vec(&item).expect("serialize item");
    let legacy = master
        .derive(meta.vault_uuid.as_bytes(), b"kestrel/v1/items")
        .expect("legacy item key");
    let aad = crypto::object_aad("item", &meta.account_uuid, &meta.vault_uuid, id, 1);
    let blob = crypto::encrypt(&legacy, &aad, &plain).expect("seal legacy item");
    Connection::open(path)
        .expect("second connection")
        .execute(
            "INSERT INTO items(account_uuid, vault_uuid, item_uuid, local_edit_count, version, data)
             VALUES(?1, ?2, ?3, 1, 1, ?4)",
            params![meta.account_uuid, meta.vault_uuid, id, blob],
        )
        .expect("insert legacy item");
}

#[test]
fn account_create_seals_both_keys_and_returns_the_secret_once() {
    let (_dir, path) = scratch();
    let (store, master, _meta) = initialised(&path);

    let created = store.account_create(&master).expect("create account");
    assert_eq!(created.account_id.len(), 32, "16 random bytes as hex");
    assert!(
        created
            .account_id
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()),
        "the account id is lower-case hex: {}",
        created.account_id
    );
    assert_eq!(
        created.secret_key.split('-').count(),
        14,
        "13 groups of four plus the checksum character"
    );
    assert_eq!(created.secret_key.split('-').last().map(str::len), Some(1));

    // The row stores ciphertext, never either value in the clear.
    let conn = Connection::open(&path).expect("second connection");
    let (wrapped, secret, id): (Vec<u8>, Vec<u8>, String) = conn
        .query_row(
            "SELECT account_key_wrapped, secret_key, account_id FROM account",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("account row");
    assert_eq!(id, created.account_id);
    assert_eq!(
        wrapped.len(),
        crypto::NONCE_LEN + crypto::KEY_LEN + 16,
        "nonce, 32-byte account key and tag"
    );
    assert_eq!(
        secret.len(),
        crypto::NONCE_LEN + crypto::KEY_LEN + 16,
        "nonce, 32-byte Secret Key and tag"
    );
    assert!(
        !wrapped.is_empty() && wrapped != vec![0u8; wrapped.len()],
        "a sealed key is never a blank row"
    );

    // A second creation is refused: the Secret Key was handed over once.
    assert!(
        store.account_create(&master).is_err(),
        "a vault file has exactly one account"
    );

    // The stored Secret Key still derives the stored account key, and a wrong
    // master key opens neither row.
    let check = store.account_secret_key(&master).expect("check secret");
    assert!(check.present && check.verified);
    assert_eq!(check.created_at, Some(created.created_at));
    let wrong = SymKey::from_slice(&[0u8; 32]).expect("32 bytes");
    assert!(
        store.account_secret_key(&wrong).is_err(),
        "the rows are sealed under the master key"
    );

    let status = store.account_status().expect("status");
    assert!(status.exists && status.secret_key_set);
    assert_eq!(
        status.account_id.as_deref(),
        Some(created.account_id.as_str())
    );
    assert_eq!(
        status.device_count, 1,
        "creating the account also creates device 1's keypair"
    );
}

#[test]
fn enrolment_round_trips_between_two_device_keypairs() {
    let receiver_secret = agreement_secret();
    let receiver_public = agreement_public(&receiver_secret);
    let other_secret = agreement_secret();

    // Any 32-byte code is a valid one; the account module mints this shape.
    let (_dir, path) = scratch();
    let (store, master, _meta) = initialised(&path);
    let created = store.account_create(&master).expect("create account");
    let code = store.account_enrol_code().code.clone();

    let account_key = SymKey::from_slice(&[0x42u8; 32]).expect("32 bytes");
    let sender_secret = agreement_secret();
    let envelope = seal_account_key(
        &sender_secret,
        &receiver_public,
        &code,
        &created.account_id,
        &account_key,
    )
    .expect("seal the account key");

    let opened = open_sealed_account(&receiver_secret, &code, &envelope).expect("open envelope");
    assert_eq!(
        opened.account_id(),
        created.account_id,
        "the account id travels inside the seal"
    );
    // Equality is proved by use: the recovered key decrypts what the original
    // sealed, which no different key could do.
    let probe = crypto::encrypt(opened.account_key(), b"probe", b"payload").expect("seal probe");
    assert_eq!(
        crypto::decrypt(&account_key, b"probe", &probe).expect("decrypt probe"),
        b"payload"
    );

    // The wrong code fails on the AEAD tag, not on a length check.
    let wrong_code = store.account_enrol_code().code.clone();
    assert!(
        open_sealed_account(&receiver_secret, &wrong_code, &envelope).is_err(),
        "the code is part of the key derivation"
    );

    // Another device cannot open an envelope addressed to this one.
    assert!(
        open_sealed_account(&other_secret, &code, &envelope).is_err(),
        "the receiver secret is part of the shared secret"
    );

    // One flipped byte is enough.
    for index in [0usize, envelope.len() / 2, envelope.len() - 1] {
        let mut tampered = envelope.clone();
        tampered[index] ^= 0x01;
        assert!(
            open_sealed_account(&receiver_secret, &code, &tampered).is_err(),
            "a tampered envelope at byte {index} must not open"
        );
    }

    // A checksum typo is refused before any curve work, and says so.
    let mut chars: Vec<char> = code.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    let broken: String = chars.into_iter().collect();
    let error = open_sealed_account(&receiver_secret, &broken, &envelope)
        .err()
        .expect("a changed checksum must fail");
    assert!(
        error.to_string().contains("checksum"),
        "the checksum, not the cipher, rejects the typo: {error}"
    );
    let store_error = store
        .account_seal_for_device(&master, &broken, &to_hex(&receiver_public))
        .err()
        .expect("sealing refuses a typo too");
    assert!(store_error.to_string().contains("checksum"));
}

#[test]
fn the_store_seals_this_accounts_key_to_a_device() {
    let (_dir, path) = scratch();
    let (store, master, _meta) = initialised(&path);
    store.account_create(&master).expect("create account");
    let code = store.account_enrol_code().code.clone();

    let first_secret = agreement_secret();
    let second_secret = agreement_secret();
    let first = store
        .account_seal_for_device(&master, &code, &to_hex(&agreement_public(&first_secret)))
        .expect("seal to the first device");
    let second = store
        .account_seal_for_device(&master, &code, &to_hex(&agreement_public(&second_secret)))
        .expect("seal to the second device");

    let first_key =
        open_sealed_account(&first_secret, &code, &unhex(&first.sealed)).expect("open first");
    let second_key =
        open_sealed_account(&second_secret, &code, &unhex(&second.sealed)).expect("open second");
    // Two envelopes, two sender ephemerals, one account key: what the first
    // recovers decrypts what the second recovers.
    let probe =
        crypto::encrypt(first_key.account_key(), b"account", b"same key").expect("seal probe");
    assert_eq!(
        crypto::decrypt(second_key.account_key(), b"account", &probe).expect("decrypt probe"),
        b"same key"
    );
    assert_ne!(
        first.sender_agreement_pub, second.sender_agreement_pub,
        "each envelope carries its own sender agreement key"
    );

    // Public keys are hex, never a private half.
    assert_eq!(first.sender_agreement_pub.len(), 64);
    assert_eq!(
        unhex(&first.sealed).len(),
        32 + crypto::NONCE_LEN + 64 + 16,
        "account id and account key are both inside the seal"
    );

    // A malformed agreement key is refused, not silently truncated.
    for bad in ["", "00", &"zz".repeat(32)] {
        assert!(
            store.account_seal_for_device(&master, &code, bad).is_err(),
            "rejected malformed device key {bad:?}"
        );
    }

    let devices = store.account_devices().expect("devices");
    assert_eq!(devices.len(), 1, "only this device is mirrored so far");
    let identity = store.device_identity(&master).expect("identity");
    assert_eq!(devices[0].device_id, identity.device_id);
    assert_eq!(devices[0].signing_pub, identity.signing_pub);
    assert_eq!(devices[0].agreement_pub, identity.agreement_pub);
    assert_eq!(devices[0].name, identity.device_name);
}

#[test]
fn revoking_a_mirrored_device_keeps_the_row_and_refuses_self() {
    let (_dir, path) = scratch();
    let (store, master, _meta) = initialised(&path);
    store.account_create(&master).expect("create account");
    let local = store.device_identity(&master).expect("identity");

    // The local device is the one that signs every request; it can neither
    // revoke nor forget itself.
    assert!(store.mark_device_revoked(&local.device_id).is_err());
    assert!(store.forget_device(&local.device_id).is_err());

    // A mirror row the sync service reported: public halves only, no sealed
    // private key, which is exactly what a remote device row looks like.
    let remote = "1a2b3c4d5e6f708192a3b4c5d6e7f809";
    {
        let conn = Connection::open(&path).expect("raw open");
        conn.execute(
            "INSERT INTO devices
                 (device_id, signing_pub, agreement_pub, name, created_at, last_seen)
             VALUES(?1, ?2, ?3, ?4, ?5, ?5)",
            params![remote, vec![1_u8; 32], vec![2_u8; 32], "old laptop", 1_i64],
        )
        .expect("insert remote device");
    }

    let before = store.account_devices().expect("devices");
    let row = before
        .iter()
        .find(|device| device.device_id == remote)
        .expect("the remote device is mirrored");
    assert_eq!(row.revoked_at, None);

    let revoked_at = store.mark_device_revoked(remote).expect("revoke");
    assert!(revoked_at > 0);
    // The row is kept: that is what lets Settings name the device after the
    // revocation, and what makes the audit trail exist at all.
    let after = store.account_devices().expect("devices after revoke");
    let row = after
        .iter()
        .find(|device| device.device_id == remote)
        .expect("the revoked row is still there");
    assert_eq!(row.revoked_at, Some(revoked_at));
    // A retry is idempotent and does not move the timestamp.
    assert_eq!(
        store.mark_device_revoked(remote).expect("second revoke"),
        revoked_at
    );

    // The no-server path removes the row instead; it is not a revocation and
    // the local device is still refused.
    store.forget_device(remote).expect("forget the mirror row");
    assert!(store
        .account_devices()
        .expect("devices after forget")
        .iter()
        .all(|device| device.device_id != remote));
    assert!(
        store.forget_device(remote).is_err(),
        "nothing left to forget"
    );
    assert!(store.mark_device_revoked(remote).is_err(), "row is gone");
}

#[test]
fn item_keys_are_created_lazily_and_old_items_are_resealed() {
    let (_dir, path) = scratch();
    let (store, master, meta) = initialised(&path);
    insert_legacy_item(&path, &master, &meta, "legacy-item", "before per-item keys");

    // Before the backfill the row has no key of its own and still opens: the
    // legacy vault key is the documented fallback.
    assert_eq!(
        store
            .get(&master, &meta, "legacy-item")
            .expect("read legacy")
            .title,
        "before per-item keys"
    );
    assert_eq!(item_counts(&path), (1, 0), "no item key yet");
    let before = item_blob(&path, "legacy-item");

    let migrated = store.backfill_item_keys(&master, &meta).expect("backfill");
    assert_eq!(migrated, 1, "one item was given a key");
    assert_eq!(item_counts(&path), (1, 1), "one wrapped item key");

    // The bytes on disk changed: the row really was re-sealed under the new
    // key, not merely left readable through the fallback.
    let after = item_blob(&path, "legacy-item");
    assert_ne!(before, after, "the item blob was re-sealed");
    assert_eq!(
        store
            .get(&master, &meta, "legacy-item")
            .expect("read migrated")
            .title,
        "before per-item keys"
    );

    // A save now keeps using the item's own key.
    let mut item = store.get(&master, &meta, "legacy-item").expect("read");
    item.title = "edited after migration".into();
    store.save_item(&master, &meta, item).expect("save");
    assert_eq!(
        item_counts(&path),
        (1, 1),
        "the key is reused, not duplicated"
    );
    assert_eq!(
        store
            .get(&master, &meta, "legacy-item")
            .expect("read")
            .title,
        "edited after migration"
    );

    // Idempotent and resumable: a second run finds nothing to do and rewrites
    // nothing.
    let settled = item_blob(&path, "legacy-item");
    assert_eq!(
        store
            .backfill_item_keys(&master, &meta)
            .expect("backfill again"),
        0
    );
    assert_eq!(item_blob(&path, "legacy-item"), settled);

    // A brand-new item gets a key at save time, with no backfill involved.
    let mut fresh = Item::new(Category::Login, "new item".into());
    fresh.id = "brand-new-item".into();
    store
        .save_item(&master, &meta, fresh)
        .expect("save new item");
    assert_eq!(
        item_counts(&path),
        (2, 2),
        "new items are keyed immediately"
    );
}

#[test]
fn unlock_backfills_item_keys_and_the_account_survives_lock() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).expect("open state");
    state.create(PASSWORD).expect("create vault");
    let created = state.account_create().expect("create account");
    let account_id = created.account_id.clone();

    state.lock().expect("lock");
    assert!(state.account_status().expect("locked status").exists);

    // Insert the old-shape item while the vault is locked, the same way an
    // older build would have written it.
    let (salt, account_uuid, vault_uuid) = {
        let conn = Connection::open(&path).expect("second connection");
        let read = |key: &str| -> String {
            conn.query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .expect("meta")
        };
        let salt: Vec<u8> = conn
            .query_row("SELECT value FROM meta WHERE key = 'kdf_salt'", [], |row| {
                row.get(0)
            })
            .expect("salt");
        (salt, read("account_uuid"), read("default_vault_uuid"))
    };
    let master = crypto::derive_master_key(PASSWORD, &salt).expect("master key");
    let meta = VaultMeta {
        account_uuid,
        vault_uuid,
        salt,
        verifier: Vec::new(),
    };
    {
        let conn = Connection::open(&path).expect("second connection");
        let mut item = Item::new(Category::Login, "written while locked".into());
        item.id = "locked-legacy-item".into();
        let plain = serde_json::to_vec(&item).expect("serialize");
        let legacy = master
            .derive(meta.vault_uuid.as_bytes(), b"kestrel/v1/items")
            .expect("legacy key");
        let aad = crypto::object_aad("item", &meta.account_uuid, &meta.vault_uuid, &item.id, 1);
        let blob = crypto::encrypt(&legacy, &aad, &plain).expect("seal");
        conn.execute(
            "INSERT INTO items(account_uuid, vault_uuid, item_uuid, local_edit_count, version, data)
             VALUES(?1, ?2, ?3, 1, 1, ?4)",
            params![meta.account_uuid, meta.vault_uuid, item.id, blob],
        )
        .expect("insert legacy item");
    }
    assert_eq!(item_counts(&path), (1, 0));

    state.unlock(PASSWORD).expect("unlock");
    assert!(
        state.get("locked-legacy-item").is_ok(),
        "the unlock-time backfill migrated the row"
    );
    assert_eq!(item_counts(&path), (1, 1));

    // The account row survived the lock, with the same id and an intact Secret
    // Key.
    let status = state.account_status().expect("status");
    assert_eq!(status.account_id.as_deref(), Some(account_id.as_str()));
    let check = state.account_secret_key().expect("secret check");
    assert!(check.present && check.verified);

    state.lock().expect("lock again");
    state.unlock(PASSWORD).expect("unlock again");
    assert_eq!(
        state
            .account_status()
            .expect("status")
            .account_id
            .as_deref(),
        Some(account_id.as_str())
    );
}

#[test]
fn account_and_item_keys_survive_a_master_password_change() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path.clone()).expect("open state");
    state.create(PASSWORD).expect("create vault");
    let created = state.account_create().expect("create account");
    let account_id = created.account_id.clone();
    let identity = state.device_identity().expect("device keys");

    let mut item = state.create_default("login").expect("draft");
    item.title = "rekeyed item".into();
    let item = state.save(item).expect("save");
    assert_eq!(item_counts(&path), (1, 1));

    state
        .change_password(PASSWORD, NEW_PASSWORD)
        .expect("rotate the master password");

    // The account id is the same, and both sealed rows were re-sealed under the
    // new master key instead of being left behind.
    let status = state.account_status().expect("status");
    assert_eq!(status.account_id.as_deref(), Some(account_id.as_str()));
    let check = state.account_secret_key().expect("secret check");
    assert!(check.present && check.verified);
    assert_eq!(item_counts(&path), (1, 1), "one item, one item key");
    assert_eq!(
        state.get(&item.id).expect("read after rotation").title,
        "rekeyed item"
    );

    // The old password no longer opens anything.
    state.lock().expect("lock");
    assert!(state.unlock(PASSWORD).is_err());
    state.unlock(NEW_PASSWORD).expect("new password unlocks");
    assert!(state.account_secret_key().expect("secret check").verified);
    // The device keypair was re-sealed with the account rows: it still opens,
    // and it is still the same keypair the sync service was told about.
    assert_eq!(state.device_identity().expect("device keys"), identity);
    assert_eq!(
        state
            .device_secret_keys()
            .expect("device secrets open under the new master key")
            .device_id(),
        identity.device_id
    );
}

/// The whole receive path, with the keypairs this crate generates: the sender
/// seals to the public half the joining device would show on its card, and that
/// device's stored private half opens it.
#[test]
fn generated_device_keypairs_move_the_account_key_end_to_end() {
    let (_sender_dir, sender_path) = scratch();
    let (sender, sender_master, _meta) = initialised(&sender_path);
    let created = sender
        .account_create(&sender_master)
        .expect("create account");
    let code = sender.account_enrol_code().code.clone();

    let (_receiver_dir, receiver_path) = scratch();
    let (receiver, receiver_master, _meta) = initialised(&receiver_path);
    let identity = receiver
        .device_identity(&receiver_master)
        .expect("receiver keypair");
    let keys = receiver
        .device_secret_keys(&receiver_master)
        .expect("receiver private halves");
    assert_eq!(keys.device_id(), identity.device_id);
    assert_eq!(
        to_hex(&agreement_public(keys.agreement_secret())),
        identity.agreement_pub,
        "the shown agreement key is the public half of the stored secret"
    );

    // The sender's device keypair is independent of the ephemeral sender
    // agreement key inside the envelope; only the receiver's agreement key
    // decides who can open the blob.
    let sealed = sender
        .account_seal_for_device(&sender_master, &code, &identity.agreement_pub)
        .expect("seal to the receiver's card key");
    let opened = open_sealed_account(keys.agreement_secret(), &code, &unhex(&sealed.sealed))
        .expect("the receiver opens its own envelope");
    assert_eq!(opened.account_id(), created.account_id);
    let probe = crypto::encrypt(opened.account_key(), b"probe", b"payload").expect("seal probe");
    assert_eq!(
        crypto::decrypt(opened.account_key(), b"probe", &probe).expect("decrypt probe"),
        b"payload"
    );

    // The low-level public API takes the two generated keypairs just as well.
    let direct = seal_account_key(
        keys.agreement_secret(),
        &agreement_public(keys.agreement_secret()),
        &code,
        &created.account_id,
        opened.account_key(),
    )
    .expect("seal to self with a generated keypair");
    assert_eq!(
        open_sealed_account(keys.agreement_secret(), &code, &direct)
            .expect("open self-sealed")
            .account_id(),
        created.account_id
    );
}

/// A successful claim writes the account row and this device's row, and both
/// survive a lock/unlock cycle: the account key is sealed under the master key,
/// not held in memory.
#[test]
fn claim_writes_both_rows_and_a_lock_keeps_them() {
    let (_sender_dir, sender_path) = scratch();
    let sender = VaultState::open(sender_path).expect("sender state");
    sender.create(PASSWORD).expect("create sender vault");
    let created = sender.account_create().expect("create account");
    let code = sender.account_enrol_code().expect("code").code.clone();

    let (_receiver_dir, receiver_path) = scratch();
    let receiver = VaultState::open(receiver_path).expect("receiver state");
    receiver.create(PASSWORD).expect("create receiver vault");
    let identity = receiver.device_identity().expect("receiver keypair");
    let sealed = sender
        .account_seal_for_device(&code, &identity.agreement_pub)
        .expect("seal to the receiver");

    let claimed = receiver
        .account_enroll_claim(&code, &sealed.sealed, &sealed.sender_agreement_pub)
        .expect("claim the account");
    assert_eq!(claimed.account_id, created.account_id);

    let status = receiver.account_status().expect("status");
    assert!(status.exists);
    assert_eq!(
        status.account_id.as_deref(),
        Some(created.account_id.as_str()),
        "the account id came out of the sealed blob"
    );
    assert!(
        !status.secret_key_set,
        "a joined device holds the account key, not the printed Secret Key"
    );
    assert_eq!(status.device_count, 1, "this device's own row");

    let devices = receiver.account_devices().expect("devices");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, identity.device_id);
    assert_eq!(devices[0].signing_pub, identity.signing_pub);
    assert_eq!(devices[0].agreement_pub, identity.agreement_pub);

    // The Secret Key check reports absence instead of failing.
    let check = receiver.account_secret_key().expect("secret check");
    assert!(!check.present && !check.verified);
    assert_eq!(check.created_at, Some(status.created_at.expect("created")));

    receiver.lock().expect("lock");
    receiver.unlock(PASSWORD).expect("unlock");

    let after = receiver.account_status().expect("status after unlock");
    assert_eq!(
        after.account_id.as_deref(),
        Some(created.account_id.as_str())
    );
    assert_eq!(after.device_count, 1);
    let devices = receiver.account_devices().expect("devices after unlock");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, identity.device_id);
    assert_eq!(
        receiver
            .device_secret_keys()
            .expect("the sealed keypair still opens after a lock")
            .device_id(),
        identity.device_id
    );
}

/// Every untrusted input collapses into one message: a wrong code, a tampered
/// blob and a sender key that is not the one inside the blob. The successful
/// claim afterwards proves the refusals came from the inputs, not from a broken
/// setup.
#[test]
fn claim_refuses_a_wrong_code_tampered_blob_and_wrong_sender_identically() {
    let (_sender_dir, sender_path) = scratch();
    let sender = VaultState::open(sender_path).expect("sender state");
    sender.create(PASSWORD).expect("create sender vault");
    sender.account_create().expect("create account");
    let code = sender.account_enrol_code().expect("code").code.clone();

    let (_receiver_dir, receiver_path) = scratch();
    let receiver = VaultState::open(receiver_path).expect("receiver state");
    receiver.create(PASSWORD).expect("create receiver vault");
    let identity = receiver.device_identity().expect("receiver keypair");
    let sealed = sender
        .account_seal_for_device(&code, &identity.agreement_pub)
        .expect("seal to the receiver");

    let mut envelope = unhex(&sealed.sealed);
    let middle = envelope.len() / 2;
    envelope[middle] ^= 0x01;

    let wrong_code = sender
        .account_enrol_code()
        .expect("another code")
        .code
        .clone();
    let wrong_sender = to_hex(&agreement_public(&agreement_secret()));

    let code_error = receiver
        .account_enroll_claim(&wrong_code, &sealed.sealed, &sealed.sender_agreement_pub)
        .expect_err("a wrong code must not claim")
        .to_string();
    let blob_error = receiver
        .account_enroll_claim(&code, &to_hex(&envelope), &sealed.sender_agreement_pub)
        .expect_err("a tampered blob must not claim")
        .to_string();
    let sender_error = receiver
        .account_enroll_claim(&code, &sealed.sealed, &wrong_sender)
        .expect_err("a sender key that is not in the blob must not claim")
        .to_string();

    assert_eq!(
        code_error, blob_error,
        "the code and the blob look the same"
    );
    assert_eq!(code_error, sender_error, "the sender key looks the same");
    assert!(
        code_error.contains("does not open an account"),
        "one honest sentence, no oracle: {code_error}"
    );

    // The untouched values still work, so the setup was valid all along.
    receiver
        .account_enroll_claim(&code, &sealed.sealed, &sealed.sender_agreement_pub)
        .expect("the valid triple claims");
    assert_eq!(receiver.account_status().expect("status").device_count, 1);
}

/// The keys the card would draw are the keys the claim records, and the stored
/// private halves really are the pairs of those public halves.
#[test]
fn the_joining_device_card_shows_the_keys_the_claim_records() {
    let (_dir, path) = scratch();
    let (store, master, _meta) = initialised(&path);
    let identity = store.device_identity(&master).expect("card keys");
    let again = store.device_identity(&master).expect("card keys again");
    assert_eq!(
        again, identity,
        "the keypair is generated once, not per view"
    );
    assert_eq!(identity.device_id.len(), 32);
    assert_eq!(identity.signing_pub.len(), 64);
    assert_eq!(identity.agreement_pub.len(), 64);

    let keys = store.device_secret_keys(&master).expect("private halves");
    assert_eq!(keys.device_id(), identity.device_id);
    assert_eq!(
        to_hex(&agreement_public(keys.agreement_secret())),
        identity.agreement_pub
    );
    let signing = ed25519_dalek::SigningKey::from_bytes(keys.signing_secret());
    assert_eq!(
        to_hex(signing.verifying_key().as_bytes()),
        identity.signing_pub,
        "the shown signing key is the public half of the sealed seed"
    );

    // Nothing private is in the row's public columns: the sealed halves are
    // ciphertext, and the public columns are the public halves.
    let conn = Connection::open(&path).expect("second connection");
    let (signing_pub, agreement_pub, sealed_signing, sealed_agreement): (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = conn
        .query_row(
            "SELECT signing_pub, agreement_pub, signing_key_wrapped, agreement_key_wrapped
             FROM devices WHERE device_id = ?1",
            params![identity.device_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("device row");
    assert_eq!(to_hex(&signing_pub), identity.signing_pub);
    assert_eq!(to_hex(&agreement_pub), identity.agreement_pub);
    assert_eq!(sealed_signing.len(), crypto::NONCE_LEN + 32 + 16);
    assert_eq!(sealed_agreement.len(), crypto::NONCE_LEN + 32 + 16);
    assert!(
        !sealed_signing
            .windows(32)
            .any(|window| window == &keys.signing_secret()[..]),
        "the signing seed is never stored in the clear"
    );
}

/// The v10 step is the only patch behaviour with no fixture behind it: every
/// other migration test starts from a database that already has the current
/// shape. This one rewinds a real vault to v9 — no wrapped device-key columns,
/// `account.secret_key` still `NOT NULL` — and proves the upgrade re-adds them
/// without losing the account row.
#[test]
fn a_v9_database_gains_the_device_key_columns_and_a_nullable_secret_key() {
    let (_dir, path) = scratch();
    let account_id = {
        let state = VaultState::open(path.clone()).expect("open");
        state.create(PASSWORD).expect("create");
        let created = state.account_create().expect("account");
        state.lock().expect("lock");
        // `AccountCreated` zeroizes on drop, so the id is cloned out.
        created.account_id.clone()
    };

    // Rewind to the v9 shape with raw SQL: drop the two wrapped columns and
    // rebuild `account` with the v9 `NOT NULL` secret_key.
    {
        let conn = rusqlite::Connection::open(&path).expect("raw open");
        conn.execute_batch(
            "ALTER TABLE devices DROP COLUMN signing_key_wrapped;
             ALTER TABLE devices DROP COLUMN agreement_key_wrapped;
             CREATE TABLE account_v9 (
                 account_id         TEXT PRIMARY KEY,
                 account_key_wrapped BLOB NOT NULL,
                 secret_key         BLOB NOT NULL,
                 created_at         INTEGER NOT NULL
             );
             INSERT INTO account_v9 SELECT account_id, account_key_wrapped, secret_key, created_at FROM account;
             DROP TABLE account;
             ALTER TABLE account_v9 RENAME TO account;
             UPDATE meta SET value = '9' WHERE key = 'schema_version';",
        )
        .expect("rewind to v9");
    }

    let state = VaultState::open(path.clone()).expect("v9 vault upgrades");
    let conn = rusqlite::Connection::open(&path).expect("raw open");
    let columns = |table: &str| -> Vec<String> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .expect("pragma");
        stmt.query_map([], |row| row.get::<_, String>(1))
            .expect("rows")
            .map(|name| name.expect("name"))
            .collect()
    };
    let device_columns = columns("devices");
    assert!(device_columns
        .iter()
        .any(|name| name == "signing_key_wrapped"));
    assert!(device_columns
        .iter()
        .any(|name| name == "agreement_key_wrapped"));
    let secret_notnull: i64 = conn
        .query_row(
            "SELECT \"notnull\" FROM pragma_table_info('account') WHERE name = 'secret_key'",
            [],
            |row| row.get(0),
        )
        .expect("secret_key column");
    assert_eq!(secret_notnull, 0, "v10 makes the Secret Key optional");
    drop(conn);

    // The account itself survived the upgrade and still opens.
    state.unlock(PASSWORD).expect("unlock");
    let status = state.account_status().expect("status");
    assert!(status.exists);
    assert_eq!(status.account_id.as_deref(), Some(account_id.as_str()));
    assert!(status.secret_key_set, "the v9 row had a Secret Key");
}
