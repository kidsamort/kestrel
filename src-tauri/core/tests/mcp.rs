//! Field grants and the read audit, through the core's public API.
//!
//! These are the invariants the settings card, the MCP server and the CLI
//! token path all depend on: a grant is an exact (principal, item, field)
//! triple, a read returns the value only when a live grant allows it, every
//! granted read is recorded before it is answered, and nothing about a refusal
//! is recorded. A deadline in the past is not a grant, and a one-shot grant is
//! spent by the read it authorizes.

use kestrel_core::model::{Category, Item};
use kestrel_core::session::VaultState;
use kestrel_core::VaultError;
use std::time::{SystemTime, UNIX_EPOCH};

const PASSWORD: &str = "correct horse battery staple";

fn scratch(tag: &str) -> (VaultState, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let state = VaultState::open(dir.path().join(format!("{tag}.db"))).expect("vault opens");
    state.create(PASSWORD).expect("vault created");
    (state, dir)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// A login whose password field holds `secret`. Returns the saved item and the
/// password/username field ids. The username is a real value too, so a grant
/// that names the wrong field can be told apart from an empty answer.
fn login(state: &VaultState, secret: &str) -> (Item, String, String) {
    login_named(state, "Deploy target", secret)
}

fn login_named(state: &VaultState, title: &str, secret: &str) -> (Item, String, String) {
    let mut item = Item::new(Category::Login, title.to_string());
    let mut password = String::new();
    let mut username = String::new();
    for field in &mut item.fields {
        match field.kind.as_str() {
            "password" => {
                field.value = secret.to_string();
                password = field.id.clone();
            }
            "username" => {
                field.value = "deploy-user".to_string();
                username = field.id.clone();
            }
            _ => {}
        }
    }
    let item = state.save(item).expect("item saved");
    (item, password, username)
}

#[test]
fn a_granted_read_returns_the_value_and_is_audited() {
    let (state, _dir) = scratch("mcp-reveal");
    let secret = "mcp-value-1";
    let (item, password, _username) = login(&state, secret);

    state
        .mcp_set_grants("editor", &[(item.id.clone(), password.clone())])
        .expect("grants recorded");
    let grants = state.mcp_grants().expect("grants");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].client, "editor");
    assert_eq!(grants[0].item_id, item.id);
    assert_eq!(grants[0].field, password);
    assert!(grants[0].created_at > 0);

    assert_eq!(
        state
            .mcp_reveal("editor", &item.id, &password)
            .expect("granted read"),
        secret
    );
    let audit = state.mcp_audit(10).expect("audit");
    assert_eq!(audit.len(), 1, "exactly the one read: {audit:?}");
    assert_eq!(audit[0].client, "editor");
    assert_eq!(audit[0].item_id, item.id);
    assert_eq!(audit[0].field, password);
    assert!(audit[0].at > 0);
}

#[test]
fn a_field_outside_the_allowlist_is_refused_and_not_recorded() {
    let (state, _dir) = scratch("mcp-refuse");
    let (item, password, username) = login(&state, "mcp-value-2");
    state
        .mcp_set_grants("editor", &[(item.id.clone(), password.clone())])
        .expect("grants recorded");

    // Wrong field, wrong client, wrong item: three different ways to be wrong
    // with a real item in hand.
    assert!(matches!(
        state.mcp_reveal("editor", &item.id, &username),
        Err(VaultError::NotGranted)
    ));
    assert!(matches!(
        state.mcp_reveal("assistant", &item.id, &password),
        Err(VaultError::NotGranted)
    ));
    assert!(matches!(
        state.mcp_reveal("editor", "no-such-item", &password),
        Err(VaultError::NotGranted)
    ));
    assert!(
        state.mcp_audit(10).expect("audit").is_empty(),
        "a refused read must not be recorded"
    );
}

#[test]
fn re_pairing_replaces_the_allowlist_and_clearing_ends_access() {
    let (state, _dir) = scratch("mcp-replace");
    let (item, password, username) = login(&state, "mcp-value-3");
    state
        .mcp_set_grants(
            "editor",
            &[(item.id.clone(), password.clone()), (item.id.clone(), username.clone())],
        )
        .expect("first allowlist");
    assert_eq!(state.mcp_grants().expect("grants").len(), 2);

    state
        .mcp_set_grants("editor", &[(item.id.clone(), username.clone())])
        .expect("second allowlist");
    assert!(matches!(
        state.mcp_reveal("editor", &item.id, &password),
        Err(VaultError::NotGranted)
    ));
    assert_eq!(
        state
            .mcp_reveal("editor", &item.id, &username)
            .expect("still granted"),
        "deploy-user"
    );

    assert_eq!(state.mcp_clear_grants("editor").expect("cleared"), 1);
    assert!(state.mcp_grants().expect("grants").is_empty());
    assert!(matches!(
        state.mcp_reveal("editor", &item.id, &username),
        Err(VaultError::NotGranted)
    ));
}

#[test]
fn a_grant_must_name_a_real_item_and_field() {
    let (state, _dir) = scratch("mcp-validate");
    let (item, password, _username) = login(&state, "mcp-value-4");

    assert!(matches!(
        state.mcp_set_grants("editor", &[(item.id.clone(), "no-such-field".into())]),
        Err(VaultError::FieldNotFound)
    ));
    assert!(
        state.mcp_set_grants("editor", &[("no-such-item".into(), password)]).is_err(),
        "a missing item cannot be granted"
    );
    assert!(state.mcp_grants().expect("grants").is_empty());
    // An unknown principal kind would be a row no read path consults.
    assert!(matches!(
        state.set_grants("robot", "editor", &[], None, false),
        Err(VaultError::Invalid(_))
    ));
}

#[test]
fn a_locked_vault_refuses_a_reveal_even_with_a_grant() {
    let (state, _dir) = scratch("mcp-locked");
    let (item, password, _username) = login(&state, "mcp-value-5");
    state
        .mcp_set_grants("editor", &[(item.id.clone(), password.clone())])
        .expect("grants recorded");
    state.lock().expect("lock");

    assert!(matches!(
        state.mcp_reveal("editor", &item.id, &password),
        Err(VaultError::Locked)
    ));
    assert!(state.mcp_audit(10).is_err(), "a locked vault has no session");
}

/* ------------------------------------------------------------ lifetime rules */

#[test]
fn a_deadline_in_the_past_is_not_a_grant() {
    let (state, _dir) = scratch("expired");
    let (item, password, _username) = login(&state, "expired-value");
    let past = now() - 60;

    state
        .set_grants(
            "mcp",
            "editor",
            &[(item.id.clone(), password.clone())],
            Some(past),
            false,
        )
        .expect("expired grant stored");
    assert!(matches!(
        state.mcp_reveal("editor", &item.id, &password),
        Err(VaultError::NotGranted)
    ));
    assert!(state.mcp_audit(10).expect("audit").is_empty());

    state
        .set_grants(
            "cli",
            "terminal",
            &[(item.id.clone(), password.clone())],
            Some(past),
            false,
        )
        .expect("expired cli grant stored");
    assert!(matches!(
        state.cli_resolve("terminal", &[(item.id.clone(), password.clone())]),
        Err(VaultError::NotGranted)
    ));
    assert!(
        state.cli_items("terminal").expect("cli items").is_empty(),
        "an expired grant does not even reveal the item's title"
    );

    // The same rows with a future deadline do authorize.
    let future = now() + 3600;
    state
        .set_grants(
            "cli",
            "terminal",
            &[(item.id.clone(), password.clone())],
            Some(future),
            false,
        )
        .expect("live cli grant");
    assert_eq!(
        state
            .cli_resolve("terminal", &[(item.id.clone(), password.clone())])
            .expect("live read"),
        vec!["expired-value".to_string()]
    );
}

#[test]
fn a_one_shot_grant_is_spent_by_the_first_successful_read() {
    let (state, _dir) = scratch("one-shot");
    let (item, password, username) = login(&state, "once-value");

    state
        .set_grants(
            "mcp",
            "editor",
            &[(item.id.clone(), password.clone())],
            None,
            true,
        )
        .expect("one-shot grant");
    assert_eq!(
        state
            .mcp_reveal("editor", &item.id, &password)
            .expect("first read"),
        "once-value"
    );
    assert!(
        matches!(
            state.mcp_reveal("editor", &item.id, &password),
            Err(VaultError::NotGranted)
        ),
        "the second read has no grant left"
    );
    assert!(
        state.grants_for("mcp", "editor").expect("grants").is_empty(),
        "the spent row is gone"
    );
    assert_eq!(
        state.mcp_audit(10).expect("audit").len(),
        1,
        "one successful read, one row"
    );

    // A refused read does not spend the grant: the wrong field is attempted
    // first, then the granted one still works.
    state
        .set_grants(
            "cli",
            "terminal",
            &[(item.id.clone(), password.clone())],
            None,
            true,
        )
        .expect("one-shot cli grant");
    assert!(matches!(
        state.cli_resolve("terminal", &[(item.id.clone(), username)]),
        Err(VaultError::NotGranted)
    ));
    assert_eq!(
        state
            .cli_resolve("terminal", &[(item.id.clone(), password)])
            .expect("still unspent"),
        vec!["once-value".to_string()]
    );
    assert!(state
        .grants_for("cli", "terminal")
        .expect("grants")
        .is_empty());
}

/* ----------------------------------------------------------------- cli path */

#[test]
fn a_cli_token_reads_only_its_granted_fields_and_the_read_is_audited() {
    let (state, _dir) = scratch("cli-grant");
    let (item, password, username) = login(&state, "cli-secret");

    state
        .set_grants(
            "cli",
            "terminal",
            &[(item.id.clone(), password.clone())],
            None,
            false,
        )
        .expect("cli grant");

    assert_eq!(
        state
            .cli_resolve("terminal", &[(item.id.clone(), password.clone())])
            .expect("granted read"),
        vec!["cli-secret".to_string()]
    );
    assert!(
        matches!(
            state.cli_resolve("terminal", &[(item.id.clone(), username.clone())]),
            Err(VaultError::NotGranted)
        ),
        "the second field was never granted"
    );
    // Same principal id under another kind is a different principal.
    assert!(matches!(
        state.cli_resolve("editor", &[(item.id.clone(), password.clone())]),
        Err(VaultError::NotGranted)
    ));

    let audit = state.audit_for_item(&item.id).expect("item audit");
    assert_eq!(audit.len(), 1, "one successful CLI read: {audit:?}");
    assert_eq!(audit[0].client, "cli:terminal");
    assert_eq!(audit[0].field, password);
}

#[test]
fn list_shows_only_items_that_carry_a_grant() {
    let (state, _dir) = scratch("cli-list");
    let (granted, password, _username) = login_named(&state, "Granted login", "cli-list-1");
    let (hidden, _hidden_password, _hidden_username) =
        login_named(&state, "Hidden login", "cli-list-2");

    state
        .set_grants(
            "cli",
            "terminal",
            &[(granted.id.clone(), password.clone())],
            None,
            false,
        )
        .expect("cli grant");

    let listed = state.cli_items("terminal").expect("cli items");
    assert_eq!(listed.len(), 1, "only the granted item: {listed:?}");
    assert_eq!(listed[0].id, granted.id);
    assert_eq!(listed[0].title, "Granted login");
    assert!(
        listed.iter().all(|summary| summary.id != hidden.id),
        "an ungranted title must not be listable"
    );

    // A token with no grants lists nothing; the legacy unrestricted token
    // never calls this method (the SDK layer keeps that path on list_quiet).
    assert!(state.cli_items("nobody").expect("no grants").is_empty());

    state
        .mcp_clear_grants("terminal")
        .expect("only MCP rows are cleared");
    assert_eq!(
        state.cli_items("terminal").expect("still granted").len(),
        1,
        "clearing the MCP path must not touch the CLI principal"
    );
}

/* ---------------------------------------------------------- per-item editor */

#[test]
fn item_grants_replace_the_whole_item_and_the_audit_is_readable_per_item() {
    let (state, _dir) = scratch("item-grants");
    let (item, password, username) = login(&state, "item-value");
    state
        .mcp_set_grants("editor", &[(item.id.clone(), password.clone())])
        .expect("mcp grant");

    state
        .set_item_grants(
            &item.id,
            &[("cli".into(), "terminal".into(), username.clone())],
        )
        .expect("editor save");
    let rows = state.grants_for_item(&item.id).expect("item grants");
    assert_eq!(rows.len(), 1, "the MCP row was replaced: {rows:?}");
    assert_eq!(rows[0].principal_kind, "cli");
    assert_eq!(rows[0].principal_id, "terminal");
    assert_eq!(rows[0].field, username);
    assert_eq!(rows[0].expires_at, None);
    assert!(!rows[0].one_shot);
    assert!(
        state.grants_for("mcp", "editor").expect("mcp").is_empty(),
        "the item editor owns every principal's rows for that item"
    );

    // A read through the saved grant is audited and visible on the item.
    state
        .cli_resolve("terminal", &[(item.id.clone(), username.clone())])
        .expect("granted read");
    let audit = state.audit_for_item(&item.id).expect("audit");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].client, "cli:terminal");
    assert_eq!(audit[0].field, username);

    // An empty list removes access rather than keeping hidden rows.
    state
        .set_item_grants(&item.id, &[])
        .expect("item access cleared");
    assert!(state.grants_for_item(&item.id).unwrap().is_empty());
    assert!(matches!(
        state.cli_resolve("terminal", &[(item.id.clone(), username)]),
        Err(VaultError::NotGranted)
    ));
}

/* ----------------------------------------------------------------- schema */

/// An old database migrated from `mcp_grants` must keep every row, and a second
/// open of the same file must be a no-op — the SSH agent opens the vault path
/// on every request, so a migration that only works once would break it.
#[test]
fn old_mcp_grants_are_migrated_and_a_reopen_keeps_them() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("legacy.db");
    {
        let conn = rusqlite::Connection::open(&path).expect("raw db opens");
        conn.execute_batch(
            r#"
            CREATE TABLE mcp_grants (
                client      TEXT NOT NULL,
                item_uuid   TEXT NOT NULL,
                field       TEXT NOT NULL,
                created_at  INTEGER NOT NULL,
                PRIMARY KEY (client, item_uuid, field)
            );
            CREATE TABLE mcp_audit (
                id         INTEGER PRIMARY KEY,
                client     TEXT NOT NULL,
                item_uuid  TEXT NOT NULL,
                field      TEXT NOT NULL,
                at         INTEGER NOT NULL
            );
            INSERT INTO mcp_grants(client, item_uuid, field, created_at)
                VALUES('editor', 'item-legacy', 'field-legacy', 1234);
            INSERT INTO mcp_audit(client, item_uuid, field, at)
                VALUES('editor', 'item-legacy', 'field-legacy', 1235);
            "#,
        )
        .expect("old schema written");
    }

    let state = VaultState::open(path.clone()).expect("old database migrates");
    state.create(PASSWORD).expect("vault created");

    let grants = state.mcp_grants().expect("migrated grants");
    assert_eq!(grants.len(), 1, "the old row survived: {grants:?}");
    assert_eq!(grants[0].client, "editor");
    assert_eq!(grants[0].item_id, "item-legacy");
    assert_eq!(grants[0].field, "field-legacy");
    assert_eq!(grants[0].created_at, 1234, "created_at is preserved");
    let audit = state.audit_for_item("item-legacy").expect("audit");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].client, "editor");

    // The new shape is the only grant table left, and the old one is gone.
    let conn = rusqlite::Connection::open(&path).expect("raw db reopens");
    let old: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'mcp_grants'",
            [],
            |row| row.get(0),
        )
        .expect("sqlite_master query");
    assert_eq!(old, 0, "the v6 table is dropped after the copy");
    let kind: String = conn
        .query_row(
            "SELECT principal_kind FROM grants WHERE principal_id = 'editor'",
            [],
            |row| row.get(0),
        )
        .expect("new row exists");
    assert_eq!(kind, "mcp", "existing rows migrate as MCP principals");
}

#[test]
fn a_second_open_of_the_same_vault_is_a_no_op_and_keeps_grants() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("reopen.db");
    let state = VaultState::open(path.clone()).expect("first open");
    state.create(PASSWORD).expect("vault created");
    let (item, password, _username) = login(&state, "reopen-value");
    state
        .set_grants(
            "cli",
            "terminal",
            &[(item.id.clone(), password.clone())],
            None,
            true,
        )
        .expect("grant stored");
    state
        .cli_resolve("terminal", &[(item.id.clone(), password.clone())])
        .expect("one-shot read");

    // The first connection stays open, exactly like the SSH agent's per-request
    // `Store::open` alongside the app's session. The migration ladder must be
    // safe to run against a database that already has the v12 shape.
    let second = VaultState::open(path.clone()).expect("second open of the same file");
    second.unlock(PASSWORD).expect("unlock");

    assert_eq!(
        second.audit_for_item(&item.id).expect("audit intact").len(),
        1,
        "the audit row written before the second open is still there"
    );
    assert!(
        second.grants_for("cli", "terminal").expect("grants").is_empty(),
        "the spent one-shot row was not resurrected"
    );
    assert!(matches!(
        second.cli_resolve("terminal", &[(item.id.clone(), password.clone())]),
        Err(VaultError::NotGranted)
    ));
}
