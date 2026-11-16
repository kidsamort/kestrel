//! Attachment behaviour: sealed at rest, bound to their owning item, and gone
//! without a trace once removed.

use kestrel_core::model::{Category, Item};
use kestrel_core::session::{VaultError, VaultState};

fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kestrel.db");
    (dir, path)
}

const PW: &str = "correct horse battery staple";

fn login(state: &VaultState, title: &str) -> Item {
    state
        .save(Item::new(Category::Login, title.to_string()))
        .expect("item saved")
}

#[test]
fn roundtrip_keeps_metadata_and_bytes() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(PW).unwrap();
    let item = login(&state, "Passport scan");

    assert!(state.attachment_list(&item.id).unwrap().is_empty());

    let bytes = vec![0x00u8, 0x7f, 0xff];
    let added = state
        .attachment_add(
            &item.id,
            "scan.bin",
            "application/octet-stream",
            bytes.clone(),
        )
        .unwrap();
    assert_eq!(added.name, "scan.bin");
    assert_eq!(added.mime, "application/octet-stream");
    assert_eq!(added.size, 3);
    assert!(added.created_at > 0);
    assert_eq!(added.digest.len(), 16, "digest prefix is 16 hex chars");
    assert!(
        added
            .digest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "digest must be lowercase hex: {}",
        added.digest
    );

    let listed = state.attachment_list(&item.id).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, added.id);
    assert_eq!(listed[0].size, 3);
    assert_eq!(listed[0].digest, added.digest);

    assert_eq!(state.attachment_read(&item.id, &added.id).unwrap(), bytes);

    // Identical content hashes identically; different content does not.
    let other = login(&state, "Other");
    let same = state
        .attachment_add(
            &other.id,
            "copy.bin",
            "application/octet-stream",
            bytes.clone(),
        )
        .unwrap();
    assert_eq!(same.digest, added.digest);
    let different = state
        .attachment_add(&other.id, "other.bin", "application/octet-stream", vec![9])
        .unwrap();
    assert_ne!(different.digest, added.digest);
}

#[test]
fn stored_blob_is_ciphertext_not_the_uploaded_bytes() {
    let (_dir, path) = scratch();
    {
        let state = VaultState::open(path.clone()).unwrap();
        state.create(PW).unwrap();
        let item = login(&state, "Sealed");
        let bytes = b"ATTACHMENT-CANARY-42".to_vec();
        let added = state
            .attachment_add(&item.id, "canary.txt", "text/plain", bytes)
            .unwrap();

        let conn = rusqlite::Connection::open(&path).unwrap();
        let blob: Vec<u8> = conn
            .query_row(
                "SELECT data FROM attachments WHERE attachment_uuid = ?1",
                rusqlite::params![added.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(blob, b"ATTACHMENT-CANARY-42", "row must not hold plaintext");
        assert!(
            blob.len() > b"ATTACHMENT-CANARY-42".len(),
            "nonce + tag must make the row longer than the payload"
        );
        assert!(
            !blob
                .windows(b"ATTACHMENT-CANARY-42".len())
                .any(|window| window == b"ATTACHMENT-CANARY-42"),
            "plaintext leaked into the blob"
        );
    }

    // The blob still decrypts after a restart.
    let state = VaultState::open(path).unwrap();
    state.unlock(PW).unwrap();
    let item = state.list("", None, false).unwrap().remove(0);
    let listed = state.attachment_list(&item.id).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        state.attachment_read(&item.id, &listed[0].id).unwrap(),
        b"ATTACHMENT-CANARY-42".to_vec()
    );
}

#[test]
fn oversized_and_empty_uploads_are_rejected() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(PW).unwrap();
    let item = login(&state, "Limits");

    let too_big = vec![0u8; 26 * 1024 * 1024];
    let err = state
        .attachment_add(&item.id, "huge.bin", "application/octet-stream", too_big)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("attachment exceeds the 25 MiB limit"),
        "{err}"
    );
    assert!(state.attachment_list(&item.id).unwrap().is_empty());

    let err = state
        .attachment_add(
            &item.id,
            "empty.bin",
            "application/octet-stream",
            Vec::new(),
        )
        .unwrap_err();
    assert!(err.to_string().contains("empty"), "{err}");

    let err = state
        .attachment_add(&item.id, "   ", "text/plain", vec![1])
        .unwrap_err();
    assert!(err.to_string().contains("name"), "{err}");
}

#[test]
fn remove_empties_the_list_and_a_second_remove_is_not_found() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(PW).unwrap();
    let item = login(&state, "Transient");
    let added = state
        .attachment_add(&item.id, "note.txt", "text/plain", b"hello".to_vec())
        .unwrap();

    state.attachment_remove(&item.id, &added.id).unwrap();
    assert!(state.attachment_list(&item.id).unwrap().is_empty());
    assert!(matches!(
        state.attachment_read(&item.id, &added.id).unwrap_err(),
        VaultError::NotFound
    ));
    assert!(matches!(
        state.attachment_remove(&item.id, &added.id).unwrap_err(),
        VaultError::NotFound
    ));
}

#[test]
fn an_attachment_belongs_to_exactly_one_item() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(PW).unwrap();
    let owner = login(&state, "Owner");
    let stranger = login(&state, "Stranger");
    let added = state
        .attachment_add(
            &owner.id,
            "secret.pdf",
            "application/pdf",
            b"%PDF-1.7".to_vec(),
        )
        .unwrap();

    // The stranger's id never resolves, even with the right attachment id.
    assert!(matches!(
        state.attachment_read(&stranger.id, &added.id).unwrap_err(),
        VaultError::NotFound
    ));
    assert!(matches!(
        state
            .attachment_remove(&stranger.id, &added.id)
            .unwrap_err(),
        VaultError::NotFound
    ));
    assert!(matches!(
        state
            .attachment_save_as(&stranger.id, &added.id)
            .unwrap_err(),
        VaultError::NotFound
    ));

    // The owner still sees and can read its file, and the stranger sees none.
    assert_eq!(state.attachment_list(&owner.id).unwrap().len(), 1);
    assert!(state.attachment_list(&stranger.id).unwrap().is_empty());
    assert_eq!(
        state.attachment_read(&owner.id, &added.id).unwrap(),
        b"%PDF-1.7".to_vec()
    );
}

#[test]
fn adding_to_an_unknown_item_is_refused() {
    let (_dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(PW).unwrap();
    let err = state
        .attachment_add("not-an-item", "orphan.txt", "text/plain", b"x".to_vec())
        .unwrap_err();
    assert!(matches!(err, VaultError::NotFound));
}

#[test]
fn locked_vault_refuses_attachment_access() {
    let (_dir, path) = scratch();
    {
        let state = VaultState::open(path.clone()).unwrap();
        state.create(PW).unwrap();
        let item = login(&state, "Locked");
        state
            .attachment_add(&item.id, "a.txt", "text/plain", b"x".to_vec())
            .unwrap();
    }
    let state = VaultState::open(path).unwrap();
    assert!(matches!(
        state.attachment_list("anything").unwrap_err(),
        VaultError::Locked
    ));
}
