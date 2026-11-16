//! Schema creation and in-place upgrades.
//!
//! A fresh database gets every table at the current shape; an existing one is
//! walked forward one version at a time. Each step checks the on-disk shape
//! before touching it, so running the whole chain on an up-to-date database is
//! a series of cheap comparisons.

use super::{Store, StoreError, SCHEMA_VERSION};
use rusqlite::{params, OptionalExtension, Transaction};

/// Tables and indexes every database has through v4. Tables added by a later
/// version live in their own step below, so the ladder shows when each arrived.
const BASE_SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS accounts (
        account_uuid TEXT PRIMARY KEY,
        data         BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS vaults (
        account_uuid TEXT NOT NULL,
        vault_uuid   TEXT NOT NULL,
        data         BLOB NOT NULL,
        key_version  INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (account_uuid, vault_uuid)
    );
    CREATE TABLE IF NOT EXISTS items (
        account_uuid     TEXT NOT NULL,
        vault_uuid       TEXT NOT NULL,
        item_uuid        TEXT NOT NULL,
        local_edit_count INTEGER NOT NULL DEFAULT 0,
        version          INTEGER NOT NULL,
        data             BLOB NOT NULL,
        category         TEXT,
        favorite         INTEGER NOT NULL DEFAULT 0,
        search_text      TEXT,
        PRIMARY KEY (vault_uuid, item_uuid)
    );
    CREATE INDEX IF NOT EXISTS items_vault ON items(vault_uuid);
    CREATE INDEX IF NOT EXISTS items_version ON items(vault_uuid, version);
    CREATE TABLE IF NOT EXISTS item_versions (
        vault_uuid  TEXT NOT NULL,
        item_uuid   TEXT NOT NULL,
        version     INTEGER NOT NULL,
        archived_at INTEGER NOT NULL,
        data        BLOB NOT NULL,
        PRIMARY KEY (vault_uuid, item_uuid, version)
    );
    CREATE INDEX IF NOT EXISTS item_versions_item
        ON item_versions(vault_uuid, item_uuid, version DESC);
    CREATE TABLE IF NOT EXISTS attachments (
        vault_uuid      TEXT NOT NULL,
        item_uuid       TEXT NOT NULL,
        attachment_uuid TEXT NOT NULL,
        name            TEXT NOT NULL,
        mime            TEXT NOT NULL,
        size            INTEGER NOT NULL,
        digest          TEXT NOT NULL,
        created_at      INTEGER NOT NULL,
        data            BLOB NOT NULL,
        PRIMARY KEY (vault_uuid, attachment_uuid)
    );
    CREATE INDEX IF NOT EXISTS attachments_item ON attachments(vault_uuid, item_uuid);
"#;

/// The Windows Hello enrolment row (schema v5): one per vault, holding the
/// mechanism that wrapped the key material and the wrapped blob itself. The
/// wrapped blob is ciphertext from a user-gesture-bound key, never the key.
const HELLO_SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS hello (
        vault_uuid TEXT PRIMARY KEY,
        mechanism  TEXT NOT NULL,
        wrapped    BLOB NOT NULL,
        created_at INTEGER NOT NULL
    );
"#;

/// The printable recovery kit (schema v8): one row per vault holding the master
/// key sealed under a key derived from the printed code. The code itself is
/// never stored, so the row alone opens nothing; replacing the row is what
/// makes a used code stop working.
const RECOVERY_SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS recovery (
        vault_uuid TEXT PRIMARY KEY,
        wrapped    BLOB NOT NULL,
        created_at INTEGER NOT NULL
    );
"#;

/// Sync account state (schema v9): the local half of the account identity.
///
/// `account` holds one row per vault file. Both blobs are ciphertext: the
/// account key and the Secret Key are sealed under the master key, so a stolen
/// database reveals neither. The printed Secret Key is the only other copy, and
/// it exists on paper only.
///
/// `devices` is a local mirror of the account's devices: public keys and
/// display metadata, plus — in the row that is *this* device — the two private
/// halves sealed under the master key. A row without sealed halves is another
/// device of the account, which this file can name but not sign for. `item_keys`
/// holds one random 32-byte key per item, sealed under the vault item key; the
/// item body, its archived versions, its attachments and its passkey blobs are
/// sealed with that key instead. The key is scoped by `vault_uuid` because the
/// same item uuid may legitimately exist in two vaults (the store keeps
/// identities vault-scoped), and swapping one vault's key for another's would
/// make that item unreadable.
const ACCOUNT_SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS account (
        account_id          TEXT PRIMARY KEY,
        account_key_wrapped BLOB NOT NULL,
        secret_key          BLOB,
        created_at          INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS devices (
        device_id             TEXT PRIMARY KEY,
        signing_pub           BLOB NOT NULL,
        agreement_pub         BLOB NOT NULL,
        name                  TEXT NOT NULL,
        created_at            INTEGER NOT NULL,
        last_seen             INTEGER NOT NULL,
        signing_key_wrapped   BLOB,
        agreement_key_wrapped BLOB,
        revoked_at            INTEGER
    );
    CREATE TABLE IF NOT EXISTS item_keys (
        vault_uuid TEXT NOT NULL,
        item_uuid  TEXT NOT NULL,
        wrapped    BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (vault_uuid, item_uuid)
    );
"#;

/// Per-item sync bookkeeping (schema v11).
///
/// `sync_items` is one row per item the sync stream knows about: the item-level
/// version vector as JSON (`{"<device id>": <counter>}`), a dirty flag that
/// makes a local write pending until it is pushed, and the last server revision
/// applied to the item (`NULL` until the first push/pull). `sync_conflicts`
/// keeps the two bodies of a concurrent write apart until the user resolves it;
/// both blobs stay sealed, so this table is opaque bytes plus clocks. `sync_meta`
/// is the account/file-level cursor and identity store.
///
/// Like the server's own rows (PROTOCOL.md keys them by account and item), the
/// sync tables are file-scoped: a database holds one account, and the item id
/// is the sync identity. The store's `items` table is additionally vault-scoped
/// because one file may hold several vaults; sync follows the account, not the
/// vault, and the sealed body carries the item.
/// Schema v11: per-item sync bookkeeping.
///
/// `vault_uuid` is what keeps one vault's pending items from being pushed while
/// another vault of the same account is unlocked; `body` is the last sealed body
/// the server acknowledged, and `body_clock` is the clock that sealed it (the
/// AAD binds it, so the two must be stored together).
const SYNC_SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS sync_items (
        item_id    TEXT PRIMARY KEY,
        vault_uuid TEXT NOT NULL,
        clock      TEXT NOT NULL,
        dirty      INTEGER NOT NULL DEFAULT 1,
        body       BLOB,
        body_clock TEXT
    );
    CREATE INDEX IF NOT EXISTS sync_items_pending
        ON sync_items(vault_uuid, dirty, item_id);
    CREATE TABLE IF NOT EXISTS sync_conflicts (
        item_id      TEXT PRIMARY KEY,
        vault_uuid   TEXT NOT NULL,
        local_clock  TEXT NOT NULL,
        remote_clock TEXT NOT NULL,
        local_body   BLOB NOT NULL,
        remote_body  BLOB NOT NULL,
        created_at   INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sync_conflicts_vault
        ON sync_conflicts(vault_uuid, item_id);
    CREATE TABLE IF NOT EXISTS sync_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
"#;

/// Field grants (schema v12): the allowlist for every principal.
///
/// One row is "this principal may read this field of this item". `expires_at`
/// is a unix timestamp, `NULL` for a grant with no deadline; `one_shot` marks a
/// grant that the read it authorizes deletes. A row never holds a value — the
/// item and field are plaintext ids, the content stays in the encrypted blob.
///
/// `mcp_audit` gains an item index because the per-item access editor asks for
/// one item's history; the audit itself stays a single table so a read is
/// recorded once regardless of which principal performed it.
const GRANTS_SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS grants (
        principal_kind TEXT NOT NULL,
        principal_id   TEXT NOT NULL,
        item_uuid      TEXT NOT NULL,
        field          TEXT NOT NULL,
        created_at     INTEGER NOT NULL,
        expires_at     INTEGER,
        one_shot       INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (principal_kind, principal_id, item_uuid, field)
    );
    CREATE INDEX IF NOT EXISTS grants_item ON grants(item_uuid);
    CREATE TABLE IF NOT EXISTS mcp_audit (
        id         INTEGER PRIMARY KEY,
        client     TEXT NOT NULL,
        item_uuid  TEXT NOT NULL,
        field      TEXT NOT NULL,
        at         INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS mcp_audit_item ON mcp_audit(item_uuid);
"#;

/// Rebuilt tables lose their indexes with the old table; these are the current
/// ones. `items_query` needs the v4 projection columns, so it is created after
/// [`Store::add_item_projection`] has run.
const REBUILT_INDEXES: &str = r#"
    CREATE INDEX IF NOT EXISTS item_versions_item
        ON item_versions(vault_uuid, item_uuid, version DESC);
    CREATE INDEX IF NOT EXISTS attachments_item ON attachments(vault_uuid, item_uuid);
    CREATE INDEX IF NOT EXISTS items_query
        ON items(vault_uuid, deleted_at, category, favorite);
"#;

impl Store {
    /// Create missing tables, then upgrade an existing database to
    /// [`SCHEMA_VERSION`].
    ///
    /// Everything that mutates the schema does so inside one transaction, and
    /// the version marker is written in that same transaction: a crash
    /// mid-upgrade leaves either the old database or the fully upgraded one,
    /// never a version marker that overstates the shape on disk.
    pub(crate) fn migrate(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(BASE_SCHEMA)?;
        let tx = self.conn.unchecked_transaction()?;
        self.add_deleted_at()?;
        self.add_key_version()?;
        self.add_item_projection()?;
        self.add_hello_table()?;
        self.add_mcp_tables()?;
        self.add_grants_table()?;
        self.add_autofill_table()?;
        self.add_browser_table()?;
        self.add_passkeys_table()?;
        self.add_recovery_table()?;
        self.add_account_tables()?;
        self.add_device_key_columns()?;
        self.add_device_revocation()?;
        self.widen_account_secret_key()?;
        self.add_sync_tables()?;
        self.rebuild_item_versions(&tx)?;
        self.rebuild_attachments(&tx)?;
        tx.execute_batch(REBUILT_INDEXES)?;
        self.record_schema_version()?;
        tx.commit()?;
        Ok(())
    }

    /// v2 added `items.deleted_at`; older vaults gain it in place.
    fn add_deleted_at(&self) -> Result<(), StoreError> {
        if !self.has_column("items", "deleted_at")? {
            self.conn
                .execute("ALTER TABLE items ADD COLUMN deleted_at INTEGER", [])?;
        }
        Ok(())
    }

    /// v3 added `vaults.key_version`: 1 = sealed with the master key,
    /// 2 = sealed with the per-vault derived key.
    ///
    /// Rows that predate the column keep 1 and are resolved on first read:
    /// `open_vault_name` tries the derived key, falls back to the master key
    /// for genuinely old rows, and records 2 once the row is rewritten.
    /// Guessing here would be wrong for either population — a vault created
    /// before per-vault keys is still master-sealed, while a v2 vault is
    /// already derived-sealed.
    fn add_key_version(&self) -> Result<(), StoreError> {
        if !self.has_column("vaults", "key_version")? {
            self.conn.execute(
                "ALTER TABLE vaults ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1",
                [],
            )?;
        }
        Ok(())
    }

    /// v4 added the plaintext query projection on `items`: `search_text` (the
    /// only searchable content), `category` and `favorite`. Older vaults gain
    /// the columns in place with `NULL`/`0`; the rows themselves are indexed
    /// on the next unlock, when the master key can read them
    /// ([`super::Store::backfill_search_index`]).
    fn add_item_projection(&self) -> Result<(), StoreError> {
        if !self.has_column("items", "search_text")? {
            self.conn
                .execute("ALTER TABLE items ADD COLUMN search_text TEXT", [])?;
        }
        if !self.has_column("items", "category")? {
            self.conn
                .execute("ALTER TABLE items ADD COLUMN category TEXT", [])?;
        }
        if !self.has_column("items", "favorite")? {
            self.conn.execute(
                "ALTER TABLE items ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        Ok(())
    }

    /// v5 added `hello`: one row per vault holding the Windows Hello-wrapped
    /// key material. Nothing existed to reshape, so `CREATE TABLE IF NOT
    /// EXISTS` is the whole step and re-running it on a v5 database is a
    /// no-op. Existing rows are kept; an enrolment is never silently dropped
    /// by an upgrade.
    fn add_hello_table(&self) -> Result<(), StoreError> {
        if !self.has_table("hello")? {
            self.conn.execute_batch(HELLO_SCHEMA)?;
        }
        Ok(())
    }

    /// v3 widened `item_versions`' identity so the same uuid may exist in two
    /// vaults. SQLite cannot change a primary key in place, so rebuild.
    fn rebuild_item_versions(&self, tx: &Transaction<'_>) -> Result<(), StoreError> {
        if self.pk_columns("item_versions")? == ["vault_uuid", "item_uuid", "version"] {
            return Ok(());
        }
        tx.execute_batch(
            r#"
            DROP TABLE IF EXISTS item_versions_v3;
            CREATE TABLE item_versions_v3 (
                vault_uuid  TEXT NOT NULL,
                item_uuid   TEXT NOT NULL,
                version     INTEGER NOT NULL,
                archived_at INTEGER NOT NULL,
                data        BLOB NOT NULL,
                PRIMARY KEY (vault_uuid, item_uuid, version)
            );
            INSERT INTO item_versions_v3(vault_uuid, item_uuid, version, archived_at, data)
                SELECT vault_uuid, item_uuid, version, archived_at, data FROM item_versions;
            DROP TABLE item_versions;
            ALTER TABLE item_versions_v3 RENAME TO item_versions;
            "#,
        )?;
        Ok(())
    }

    /// v3 widened `attachments`' identity the same way, for the same reason.
    fn rebuild_attachments(&self, tx: &Transaction<'_>) -> Result<(), StoreError> {
        if self.pk_columns("attachments")? == ["vault_uuid", "attachment_uuid"] {
            return Ok(());
        }
        tx.execute_batch(
            r#"
            DROP TABLE IF EXISTS attachments_v3;
            CREATE TABLE attachments_v3 (
                vault_uuid      TEXT NOT NULL,
                item_uuid       TEXT NOT NULL,
                attachment_uuid TEXT NOT NULL,
                name            TEXT NOT NULL,
                mime            TEXT NOT NULL,
                size            INTEGER NOT NULL,
                digest          TEXT NOT NULL,
                created_at      INTEGER NOT NULL,
                data            BLOB NOT NULL,
                PRIMARY KEY (vault_uuid, attachment_uuid)
            );
            INSERT INTO attachments_v3(vault_uuid, item_uuid, attachment_uuid, name, mime, size, digest, created_at, data)
                SELECT vault_uuid, item_uuid, attachment_uuid, name, mime, size, digest, created_at, data FROM attachments;
            DROP TABLE attachments;
            ALTER TABLE attachments_v3 RENAME TO attachments;
            "#,
        )?;
        Ok(())
    }

    fn record_schema_version(&self) -> Result<(), StoreError> {
        let current: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if current.as_deref() != Some(SCHEMA_VERSION.to_string().as_str()) {
            self.conn.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![SCHEMA_VERSION.to_string()],
            )?;
        }
        Ok(())
    }

    /// v6 added `mcp_grants` and `mcp_audit`: which client may read which
    /// item field, and what it actually read. Both are create-only steps.
    ///
    /// Neither table holds a value. A grant names an item and a field; the
    /// audit row records that the read happened. The values themselves stay in
    /// the encrypted blob, so a stolen database still reveals nothing.
    ///
    /// v12 replaces `mcp_grants` with the wider `grants` table; this step still
    /// creates the v6 shape first so a database that predates v12 has rows to
    /// copy. A fresh database creates it empty and [`Self::add_grants_table`]
    /// drops it in the same transaction.
    fn add_mcp_tables(&self) -> Result<(), StoreError> {
        // Each table is checked on its own: v12 drops `mcp_grants` but keeps
        // `mcp_audit`, so a later open must not try to recreate the audit table
        // just because the grant table is gone. A database that already has the
        // v12 `grants` table is never given the v6 one back.
        if !self.has_table("grants")? && !self.has_table("mcp_grants")? {
            self.conn.execute_batch(
                r#"
                CREATE TABLE mcp_grants (
                    client      TEXT NOT NULL,
                    item_uuid   TEXT NOT NULL,
                    field       TEXT NOT NULL,
                    created_at  INTEGER NOT NULL,
                    PRIMARY KEY (client, item_uuid, field)
                );
                "#,
            )?;
        }
        if !self.has_table("mcp_audit")? {
            self.conn.execute_batch(
                r#"
                CREATE TABLE mcp_audit (
                    id         INTEGER PRIMARY KEY,
                    client     TEXT NOT NULL,
                    item_uuid  TEXT NOT NULL,
                    field      TEXT NOT NULL,
                    at         INTEGER NOT NULL
                );
                "#,
            )?;
        }
        Ok(())
    }

    /// v12 replaced `mcp_grants(client, ...)` with
    /// `grants(principal_kind, principal_id, ...)` so a CLI token — and the
    /// per-item access editor — can hold the same kind of permission an MCP
    /// client already could, with a deadline and a one-shot flag.
    ///
    /// Existing rows keep their meaning: an `mcp` principal, no deadline, not
    /// one-shot. The old table is dropped only after the copy, in the same
    /// transaction as the version marker, so an interrupted upgrade leaves the
    /// rows in exactly one of the two tables. A database that already has
    /// `grants` (fresh, or a second run) only re-creates the indexes.
    fn add_grants_table(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(GRANTS_SCHEMA)?;
        if self.has_table("mcp_grants")? {
            self.conn.execute_batch(
                r#"
                INSERT OR IGNORE INTO grants(
                    principal_kind, principal_id, item_uuid, field,
                    created_at, expires_at, one_shot
                )
                    SELECT 'mcp', client, item_uuid, field, created_at, NULL, 0
                    FROM mcp_grants;
                DROP TABLE mcp_grants;
                "#,
            )?;
        }
        Ok(())
    }

    /// v6 also added `autofill_apps`: the per-application rule the UIA picker
    /// consults before it offers a fill. Create-only; a missing row means the
    /// default (`ask`), never `fill`.
    fn add_autofill_table(&self) -> Result<(), StoreError> {
        if !self.has_table("autofill_apps")? {
            self.conn.execute_batch(
                r#"
                CREATE TABLE autofill_apps (
                    exe        TEXT PRIMARY KEY,
                    mode       TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                "#,
            )?;
        }
        Ok(())
    }

    /// v7 added `browser_sites`: the per-origin rule the browser bridge
    /// consults before it offers to fill. Create-only; a missing row means
    /// `ask`, never `fill`.
    fn add_browser_table(&self) -> Result<(), StoreError> {
        if !self.has_table("browser_sites")? {
            self.conn.execute_batch(
                r#"
                CREATE TABLE browser_sites (
                    origin     TEXT PRIMARY KEY,
                    mode       TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                "#,
            )?;
        }
        Ok(())
    }

    /// v7 added `passkeys`: one row per WebAuthn credential.
    ///
    /// `credential_id` and `rp_id` are public identifiers, so they stay in the
    /// clear for lookup. The private key is sealed under the item's key and
    /// never leaves the core; `item_uuid` ties the credential to the login it
    /// belongs to, which is also what makes a vault lock revoke it.
    fn add_passkeys_table(&self) -> Result<(), StoreError> {
        if !self.has_table("passkeys")? {
            self.conn.execute_batch(
                r#"
                CREATE TABLE passkeys (
                    credential_id BLOB PRIMARY KEY,
                    item_uuid     TEXT NOT NULL,
                    rp_id         TEXT NOT NULL,
                    created_at    INTEGER NOT NULL,
                    last_used_at  INTEGER,
                    key_blob      BLOB NOT NULL
                );
                "#,
            )?;
        }
        Ok(())
    }

    /// v8 added `recovery`: one row per vault holding the master key sealed
    /// under a key derived from the printed recovery code. Create-only, like
    /// the other feature tables; an existing row is a kit the user already
    /// printed and is never dropped by an upgrade.
    fn add_recovery_table(&self) -> Result<(), StoreError> {
        if !self.has_table("recovery")? {
            self.conn.execute_batch(RECOVERY_SCHEMA)?;
        }
        Ok(())
    }

    /// v9 added the sync account tables: the account row (account key and
    /// Secret Key, both sealed under the master key), the device mirror and the
    /// per-item keys. Create-only, like every feature table; an existing row is
    /// key material the user already owns and is never dropped by an upgrade.
    /// The literal is the current (v10) shape: a fresh database needs no
    /// follow-up `ALTER`.
    fn add_account_tables(&self) -> Result<(), StoreError> {
        if !self.has_table("account")? {
            self.conn.execute_batch(ACCOUNT_SCHEMA)?;
        }
        Ok(())
    }

    /// v10 gave `devices` the two private halves of *this* device's keypairs,
    /// sealed under the master key. The public halves were already columns, so
    /// the mirror can still list other devices: their rows simply carry no
    /// sealed halves and this file cannot sign or unwrap for them.
    fn add_device_key_columns(&self) -> Result<(), StoreError> {
        if !self.has_column("devices", "signing_key_wrapped")? {
            self.conn
                .execute("ALTER TABLE devices ADD COLUMN signing_key_wrapped BLOB", [])?;
        }
        if !self.has_column("devices", "agreement_key_wrapped")? {
            self.conn.execute(
                "ALTER TABLE devices ADD COLUMN agreement_key_wrapped BLOB",
                [],
            )?;
        }
        Ok(())
    }

    /// v13 added `devices.revoked_at`: the moment this device's sync access was
    /// withdrawn. The row is kept — it is the local audit trail of a device that
    /// existed and was revoked — so the column is nullable and old rows gain an
    /// empty value.
    fn add_device_revocation(&self) -> Result<(), StoreError> {
        if !self.has_column("devices", "revoked_at")? {
            self.conn
                .execute("ALTER TABLE devices ADD COLUMN revoked_at INTEGER", [])?;
        }
        Ok(())
    }

    /// v10 made `account.secret_key` nullable. A device that *joins* an account
    /// receives the account key and never the printed Secret Key, which exists
    /// only on the device that minted the account; storing a fake value there
    /// would make `account_secret_key` claim a secret this device does not have.
    ///
    /// SQLite cannot relax a `NOT NULL` in place, so a v9 table is rebuilt with
    /// the column nullable and the rows copied unchanged. A fresh database
    /// already has the new shape and this step is a no-op.
    fn widen_account_secret_key(&self) -> Result<(), StoreError> {
        if !self.column_is_not_null("account", "secret_key")? {
            return Ok(());
        }
        self.conn.execute_batch(
            r#"
            CREATE TABLE account_v10 (
                account_id          TEXT PRIMARY KEY,
                account_key_wrapped BLOB NOT NULL,
                secret_key          BLOB,
                created_at          INTEGER NOT NULL
            );
            INSERT INTO account_v10(account_id, account_key_wrapped, secret_key, created_at)
                SELECT account_id, account_key_wrapped, secret_key, created_at FROM account;
            DROP TABLE account;
            ALTER TABLE account_v10 RENAME TO account;
            "#,
        )?;
        Ok(())
    }

    /// v11 added the per-item sync tables: the item clock plus dirty flag, the
    /// two sealed bodies of an unresolved conflict, and the sync-wide key/value
    /// metadata. Create-only, like every feature table: a downgrade that lost
    /// the tables gets them back empty, and rows that exist are never dropped.
    fn add_sync_tables(&self) -> Result<(), StoreError> {
        if !self.has_table("sync_items")? {
            self.conn.execute_batch(SYNC_SCHEMA)?;
        }
        Ok(())
    }

    /// Whether `table` currently exists. Used by create-only upgrade steps;
    /// the table name is always a literal from this module, never user input.
    fn has_table(&self, table: &str) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Whether `table` currently has a `column`. Used for in-place upgrades;
    /// the table name is always a literal from this module, never user input.
    fn has_column(&self, table: &str, column: &str) -> Result<bool, StoreError> {
        let mut stmt = self.conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
        for row in rows {
            if row? == column {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether `table.column` currently has a `NOT NULL` constraint. Used by
    /// in-place upgrades that have to rebuild a table to relax one.
    fn column_is_not_null(&self, table: &str, column: &str) -> Result<bool, StoreError> {
        let mut stmt = self.conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, i64>(3)?)))?;
        for row in rows {
            let (name, not_null) = row?;
            if name == column {
                return Ok(not_null != 0);
            }
        }
        Ok(false)
    }

    /// Primary-key columns of `table`, in key order.
    fn pk_columns(&self, table: &str) -> Result<Vec<String>, StoreError> {
        let mut stmt = self.conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(5)?, r.get::<_, String>(1)?)))?;
        let mut keyed: Vec<(i64, String)> = Vec::new();
        for row in rows {
            keyed.push(row?);
        }
        keyed.sort();
        Ok(keyed
            .into_iter()
            .filter(|(pk, _)| *pk > 0)
            .map(|(_, name)| name)
            .collect())
    }
}
