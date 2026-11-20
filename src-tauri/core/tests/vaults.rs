//! Multiple vaults: separate keys, one password, no leakage between scopes.

use kestrel_core::session::VaultState;

const PW: &str = "correct horse battery staple";
const NEW_PW: &str = "another long passphrase for rotation";

fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kestrel.db");
    (dir, path)
}

fn open(path: std::path::PathBuf) -> VaultState {
    let state = VaultState::open(path).unwrap();
    if state.state().unwrap().initialized {
        state.unlock(PW).unwrap();
    } else {
        state.create(PW).unwrap();
    }
    state
}

#[test]
fn a_new_vault_is_a_separate_scope() {
    let (_dir, path) = scratch();
    let state = open(path);

    let personal = state.state().unwrap();
    assert_eq!(personal.vault_name, "Personal");
    assert_eq!(personal.vault_count, 1);

    let mut item = state.create_default("login").unwrap();
    item.title = "Personal login".into();
    let personal_item = state.save(item).unwrap();

    let work = state.create_vault("Work").unwrap();
    assert_eq!(work.name, "Work");
    assert_eq!(work.item_count, 0);

    let switched = state.switch_vault(&work.uuid).unwrap();
    assert_eq!(switched.vault_uuid, work.uuid);
    assert_eq!(switched.vault_name, "Work");
    assert_eq!(switched.vault_count, 2);

    // The other vault's rows are invisible, and not just filtered out of a list.
    assert!(state.list("", None, false).unwrap().is_empty());
    assert!(state.get(&personal_item.id).is_err());
    assert!(state.history_list(&personal_item.id).is_err());

    let mut second = state.create_default("login").unwrap();
    second.title = "Work login".into();
    let work_item = state.save(second).unwrap();
    assert_eq!(state.list("", None, false).unwrap().len(), 1);

    state.switch_vault(&personal.vault_uuid).unwrap();
    let listed = state.list("", None, false).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, personal_item.id);
    assert_eq!(
        state.get(&personal_item.id).unwrap().title,
        "Personal login"
    );
    assert!(state.get(&work_item.id).is_err());
}

#[test]
fn switching_to_an_unknown_vault_is_refused() {
    let (_dir, path) = scratch();
    let state = open(path);
    let before = state.state().unwrap();
    assert!(state.switch_vault("not-a-vault").is_err());
    assert_eq!(state.state().unwrap().vault_uuid, before.vault_uuid);
}

#[test]
fn vaults_can_be_renamed_and_counts_follow_the_scope() {
    let (_dir, path) = scratch();
    let state = open(path);
    let work = state.create_vault("Work").unwrap();
    state.switch_vault(&work.uuid).unwrap();
    // Drafts are not stored, so each one is saved to become an item.
    state.save(state.create_default("login").unwrap()).unwrap();
    state.save(state.create_default("login").unwrap()).unwrap();

    state.rename_vault(&work.uuid, "  Consulting  ").unwrap();
    let listed = state.vaults().unwrap();
    let renamed = listed.iter().find(|v| v.uuid == work.uuid).unwrap();
    assert_eq!(renamed.name, "Consulting");
    assert_eq!(renamed.item_count, 2);
    assert_eq!(state.state().unwrap().vault_name, "Consulting");

    // Names are validated rather than silently trimmed to nothing.
    assert!(state.rename_vault(&work.uuid, "   ").is_err());
}

#[test]
fn rotation_re_encrypts_every_vault() {
    let (_dir, path) = scratch();
    let state = open(path);
    let personal = state.state().unwrap();
    let mut a = state.create_default("login").unwrap();
    a.title = "alpha".into();
    let a = state.save(a).unwrap();

    let work = state.create_vault("Work").unwrap();
    state.switch_vault(&work.uuid).unwrap();
    let mut b = state.create_default("login").unwrap();
    b.title = "beta".into();
    let b = state.save(b).unwrap();

    state.change_password(PW, NEW_PW).unwrap();

    // Still readable in the active vault…
    assert_eq!(state.get(&b.id).unwrap().title, "beta");
    // …and in the vault that was not active during the rotation.
    state.switch_vault(&personal.vault_uuid).unwrap();
    assert_eq!(state.get(&a.id).unwrap().title, "alpha");
    let names: Vec<String> = state
        .vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(names, vec!["Personal", "Work"]);
}

/// Vaults written before per-vault keys encrypted the name with the master key
/// itself. Reading one must migrate it in place instead of failing to unlock.
#[test]
fn a_legacy_vault_name_is_migrated_on_read() {
    use kestrel_core::crypto;

    let (_dir, path) = scratch();
    {
        let state = open(path.clone());
        state.create_vault("Legacy").unwrap();
    }

    // Rewrite both vault rows the way the first build did: master key, same AAD.
    let salt: Vec<u8> = {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.query_row("SELECT value FROM meta WHERE key = 'kdf_salt'", [], |r| {
            r.get(0)
        })
        .unwrap()
    };
    let master = crypto::derive_master_key(PW, &salt).unwrap();
    let account: String = {
        let conn = rusqlite::Connection::open(&path).unwrap();
        String::from_utf8(
            conn.query_row(
                "SELECT value FROM meta WHERE key = 'account_uuid'",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let conn = rusqlite::Connection::open(&path).unwrap();
    let rows: Vec<(String, Vec<u8>)> = {
        let mut stmt = conn.prepare("SELECT vault_uuid, data FROM vaults").unwrap();
        let mapped = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .unwrap();
        mapped.map(|r| r.unwrap()).collect()
    };
    for (uuid, blob) in rows {
        let aad = crypto::object_aad("vault", &account, &uuid, &uuid, 1);
        let derived = master.derive(uuid.as_bytes(), b"kestrel/v1/vault").unwrap();
        let plain = crypto::decrypt(&derived, &aad, &blob).unwrap();
        let legacy = crypto::encrypt(&master, &aad, &plain).unwrap();
        conn.execute(
            "UPDATE vaults SET data = ?1, key_version = 1 WHERE vault_uuid = ?2",
            rusqlite::params![legacy, uuid],
        )
        .unwrap();
    }
    drop(conn);

    let state = VaultState::open(path.clone()).unwrap();
    state.unlock(PW).unwrap();
    let names: Vec<String> = state
        .vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(names, vec!["Personal", "Legacy"]);

    // The read migrated the row: it now decrypts with the derived key, is
    // marked v2, and no longer opens with the master key at all.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let (uuid, blob, key_version): (String, Vec<u8>, i64) = conn
        .query_row(
            "SELECT vault_uuid, data, key_version FROM vaults WHERE vault_uuid <> (SELECT value FROM meta WHERE key = 'default_vault_uuid')",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        key_version, 2,
        "a migrated name row is marked as derived-key sealed"
    );
    let aad = crypto::object_aad("vault", &account, &uuid, &uuid, 1);
    let derived = master.derive(uuid.as_bytes(), b"kestrel/v1/vault").unwrap();
    assert!(crypto::decrypt(&derived, &aad, &blob).is_ok());
    assert!(
        crypto::decrypt(&master, &aad, &blob).is_err(),
        "after migration the master key must not open the name row"
    );
}

#[test]
fn rotation_survives_a_reopen() {
    let (_dir, path) = scratch();
    let personal;
    let work_item;
    {
        let state = open(path.clone());
        personal = state.state().unwrap();
        let mut a = state.create_default("login").unwrap();
        a.title = "alpha".into();
        state.save(a).unwrap();
        let work = state.create_vault("Work").unwrap();
        state.switch_vault(&work.uuid).unwrap();
        let mut b = state.create_default("login").unwrap();
        b.title = "beta".into();
        work_item = state.save(b).unwrap();
        state.change_password(PW, NEW_PW).unwrap();
    }

    // The new password opens both vaults from disk.
    let state = VaultState::open(path).unwrap();
    state.unlock(NEW_PW).unwrap();
    state.switch_vault(&personal.vault_uuid).unwrap();
    assert_eq!(state.list("", None, false).unwrap().len(), 1);
    state
        .switch_vault(&state.vaults().unwrap()[1].uuid)
        .unwrap();
    assert_eq!(state.get(&work_item.id).unwrap().title, "beta");
}
