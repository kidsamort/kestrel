//! Passkey storage across a password rotation.
//!
//! The seal is bound to the item key, which is derived from the master key. A
//! rotation that did not re-seal passkey payloads would leave every credential
//! permanently unreadable — and worse, the old ciphertext would survive a
//! rewrite of the items table. This test pins both directions: the old master
//! can no longer open a credential, and the new one can.

use kestrel_core::model::{Category, Item, PasskeyRow};
use kestrel_core::store::Store;

const OLD: &str = "old master password 123";
const NEW: &str = "new master password 456";

#[test]
fn password_change_reseals_passkeys_and_retires_the_old_key() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = Store::open(dir.path().join("kestrel.db")).expect("store");
    let (old_master, meta) = store.initialise(OLD).expect("initialise");

    let item = store
        .save_item(
            &old_master,
            &meta,
            Item::new(Category::Login, "Example".into()),
        )
        .expect("save item");
    let row = PasskeyRow {
        credential_id: vec![0xab; 32],
        item_uuid: item.id.clone(),
        rp_id: "example.com".into(),
        created_at: item.created_at,
        last_used_at: None,
    };
    let secret = [0x5au8; 32];
    store
        .passkey_insert(&old_master, &meta, &row, &secret, 3)
        .expect("insert passkey");

    let (new_master, new_meta) = store
        .change_password(&old_master, &meta, NEW)
        .expect("rotate");

    // The old password no longer derives the key that opens the vault.
    assert!(store.unlock(OLD).is_err(), "old password must fail");
    let (_unlocked, unlocked_meta) = store.unlock(NEW).expect("new password unlocks");
    assert_eq!(unlocked_meta.account_uuid, meta.account_uuid);

    // The old master key must not open the re-sealed credential.
    assert!(
        store
            .passkey_open(&old_master, &meta, &row.credential_id, "example.com")
            .is_err(),
        "old master must not authenticate the rotated seal"
    );

    // The new key opens it, with the private scalar and counter intact.
    let opened = store
        .passkey_open(&new_master, &new_meta, &row.credential_id, "example.com")
        .expect("open after rotation")
        .expect("credential still exists");
    assert_eq!(opened.private_key, secret);
    assert_eq!(opened.sign_count, 3);
    let rendered = format!("{opened:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(
        !rendered.contains("90, 90"),
        "Debug must not print the private scalar"
    );

    // And it is still attached to the same item.
    let listed = store.passkeys_for_item(&new_meta, &item.id).expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].credential_id, row.credential_id);
}
