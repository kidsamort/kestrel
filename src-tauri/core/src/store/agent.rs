//! Which vault items the SSH agent may offer.
//!
//! One row per item the user turned **off**: `served = 0`. A missing row means
//! served, so the default needs no migration and a key created by an older
//! build is offered exactly as before. The flag is policy, not content, so it
//! lives in plain columns next to the encrypted item blob: the agent has to
//! read it before it can decide whether to decrypt a private key at all.
//!
//! # Why the table is created here
//!
//! The agent's table is owned by this module and created lazily with
//! `CREATE TABLE IF NOT EXISTS`, the same way a feature module owns its own
//! storage without forcing a schema version bump for every new setting. Every
//! entry point runs the (idempotent) DDL first, so a database written by an
//! older build, or a vault that has never seen the agent settings, needs no
//! upgrade step.

use super::{Store, StoreError};
use rusqlite::{params, OptionalExtension};

const CREATE_TABLE: &str = "CREATE TABLE IF NOT EXISTS agent_keys (
        item_uuid TEXT PRIMARY KEY,
        served INTEGER NOT NULL DEFAULT 1
    )";

impl Store {
    /// Whether the agent may offer `item_uuid`.
    ///
    /// A missing row is `true`: the agent serves every parseable key until the
    /// user says otherwise, which is the behaviour the settings card documents.
    pub fn agent_served(&self, item_uuid: &str) -> Result<bool, StoreError> {
        self.ensure_agent_table()?;
        let stored: Option<i64> = self
            .conn()
            .query_row(
                "SELECT served FROM agent_keys WHERE item_uuid = ?1",
                params![item_uuid],
                |row| row.get(0),
            )
            .optional()?;
        Ok(stored.map(|value| value != 0).unwrap_or(true))
    }

    /// Record the user's decision for `item_uuid`.
    ///
    /// An empty id is rejected: a policy row without an item names nothing and
    /// would silently apply to nothing.
    pub fn set_agent_served(&self, item_uuid: &str, served: bool) -> Result<(), StoreError> {
        if item_uuid.trim().is_empty() {
            return Err(StoreError::Invalid(
                "an agent rule needs an item id".to_string(),
            ));
        }
        self.ensure_agent_table()?;
        self.conn().execute(
            "INSERT INTO agent_keys(item_uuid, served) VALUES(?1, ?2)
             ON CONFLICT(item_uuid) DO UPDATE SET served = excluded.served",
            params![item_uuid, if served { 1 } else { 0 }],
        )?;
        Ok(())
    }

    fn ensure_agent_table(&self) -> Result<(), StoreError> {
        self.conn().execute_batch(CREATE_TABLE)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A throwaway database. `Store::open` migrates it, so the tests exercise
    /// the real file and its WAL, not a hand-built connection.
    struct TempStore {
        path: PathBuf,
        store: Store,
    }

    impl TempStore {
        fn new() -> TempStore {
            let path = std::env::temp_dir()
                .join(format!("kestrel-agent-policy-{}.db", uuid::Uuid::new_v4()));
            let store = Store::open(&path).expect("store opens");
            TempStore { path, store }
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(self.path.with_extension("db-wal"));
            let _ = std::fs::remove_file(self.path.with_extension("db-shm"));
        }
    }

    #[test]
    fn a_missing_row_is_served() {
        let temp = TempStore::new();
        assert!(
            temp.store.agent_served("never-configured").unwrap(),
            "the default must be `served`"
        );
    }

    #[test]
    fn a_decision_is_durable() {
        let temp = TempStore::new();
        temp.store.set_agent_served("item-1", false).unwrap();
        assert!(!temp.store.agent_served("item-1").unwrap());
        assert!(
            temp.store.agent_served("item-2").unwrap(),
            "a rule for one item must not affect another"
        );

        // Read the row through a separate raw connection: the decision must be
        // in the database, not just in this connection's page cache.
        let raw = rusqlite::Connection::open(temp.store.path()).expect("raw connection");
        let stored: i64 = raw
            .query_row(
                "SELECT served FROM agent_keys WHERE item_uuid = 'item-1'",
                [],
                |row| row.get(0),
            )
            .expect("stored row");
        assert_eq!(stored, 0, "the disabled state must be committed");
        drop(raw);

        temp.store.set_agent_served("item-1", true).unwrap();
        assert!(
            temp.store.agent_served("item-1").unwrap(),
            "turning the key back on must be recorded"
        );
    }

    #[test]
    fn an_empty_item_id_is_rejected() {
        let temp = TempStore::new();
        assert!(matches!(
            temp.store.set_agent_served("  ", false),
            Err(StoreError::Invalid(_))
        ));
    }
}
