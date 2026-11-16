//! Per-item sync bookkeeping: clocks, dirty flags, conflicts and metadata.
//!
//! Everything here is metadata. The two bodies in a conflict row are already
//! sealed by [`crate::sync::body::seal_body`], so this module never needs a key
//! and never looks inside a body. `clock` columns are JSON version vectors
//! (`{"<device id>": <counter>}`); a malformed one is an error, never a silent
//! empty clock — a wrong clock would let a stale write win.
//!
//! **Rows are vault-scoped.** One database can hold several vaults and they all
//! share one account, so a sync row without a vault column would let vault A's
//! item be pushed as a tombstone while vault B is unlocked, or a pulled item be
//! written into whichever vault happens to be open. Every method here takes the
//! vault uuid and filters on it; the engine passes the vault it was given.
//!
//! The metadata table (`cursor`, `server`, `last_sync_at`, `state`, `error`) is
//! deliberately **not** vault-scoped: the cursor belongs to the account's change
//! log, which is shared by every vault of that account.

use super::{Store, StoreError};
use crate::sync::Clock;
use rusqlite::{params, OptionalExtension};

/// The sync state of one item: its item-level clock, whether a local write is
/// still pending, and the sealed body the server last acknowledged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemSyncState {
    /// The item this row belongs to.
    pub item_id: String,
    /// Version vector of the last known item state.
    pub clock: Clock,
    /// `true` when a local change has not been pushed yet.
    pub dirty: bool,
    /// The sealed body the server last acknowledged for this item.
    ///
    /// It is what a push diffs against: the item-level clock says *that*
    /// something changed, and this copy says *which field paths* changed, so the
    /// new body can carry per-path clocks instead of bumping all of them. It is
    /// ciphertext the store never opens, and `None` until the first push.
    pub body: Option<Vec<u8>>,
    /// The clock that sealed [`ItemSyncState::body`].
    ///
    /// The body's AAD binds the clock it was sealed at, and the row's clock moves
    /// on every local write, so the baseline needs its own. Opening the baseline
    /// with the current clock would fail to authenticate.
    pub body_clock: Option<Clock>,
}

/// One unresolved conflict: both sealed bodies and the clocks they arrived
/// with. The store treats the bodies as opaque bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncConflictRow {
    /// The item both bodies describe.
    pub item_id: String,
    /// Clock of the local body.
    pub local_clock: Clock,
    /// Clock of the remote body.
    pub remote_clock: Clock,
    /// Local body, sealed (never opened here).
    pub local_body: Vec<u8>,
    /// Remote body, sealed (never opened here).
    pub remote_body: Vec<u8>,
    /// Unix seconds when the conflict row was written.
    pub created_at: i64,
}

impl Store {
    /// Read one item's sync row, or `None` when the item has never synced.
    ///
    /// A malformed stored clock is [`StoreError::Json`]; it is never replaced
    /// with an empty clock.
    pub fn sync_state(
        &self,
        vault: &str,
        item_id: &str,
    ) -> Result<Option<ItemSyncState>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT clock, dirty, body, body_clock FROM sync_items
                 WHERE vault_uuid = ?1 AND item_id = ?2",
                params![vault, item_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Option<Vec<u8>>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((clock, dirty, body, body_clock)) => Ok(Some(ItemSyncState {
                item_id: item_id.to_string(),
                clock: decode_clock(&clock)?,
                dirty: dirty != 0,
                body,
                body_clock: match body_clock {
                    Some(text) => Some(decode_clock(&text)?),
                    None => None,
                },
            })),
        }
    }

    /// Pending local writes of one vault, ordered by item id, at most `limit`.
    ///
    /// The ordering makes a push deterministic and the limit bounds one batch
    /// without relying on row insertion order.
    pub fn sync_dirty(&self, vault: &str, limit: usize) -> Result<Vec<ItemSyncState>, StoreError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = self.conn.prepare(
            "SELECT item_id, clock, dirty, body, body_clock FROM sync_items
             WHERE vault_uuid = ?1 AND dirty = 1 ORDER BY item_id LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![vault, limit], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<Vec<u8>>>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?;
        let mut dirty = Vec::new();
        for row in rows {
            let (item_id, clock, flag, body, body_clock) = row?;
            dirty.push(ItemSyncState {
                item_id,
                clock: decode_clock(&clock)?,
                dirty: flag != 0,
                body,
                body_clock: match body_clock {
                    Some(text) => Some(decode_clock(&text)?),
                    None => None,
                },
            });
        }
        Ok(dirty)
    }

    /// Record a local write: the clock becomes `clock` and the dirty flag is
    /// set as asked. The stored baseline body is left alone, because it still
    /// names what the server holds.
    ///
    /// An empty (or all-zero) clock is refused: a write must bump at least one
    /// counter, and storing a vector that claims no write would lose to its own
    /// previous state on the next sync.
    pub fn sync_upsert(
        &self,
        vault: &str,
        item_id: &str,
        clock: &Clock,
        dirty: bool,
    ) -> Result<(), StoreError> {
        require_write_clock(clock)?;
        let clock = encode_clock(clock)?;
        self.conn.execute(
            "INSERT INTO sync_items(vault_uuid, item_id, clock, dirty) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(item_id) DO UPDATE SET
                 vault_uuid = excluded.vault_uuid,
                 clock = excluded.clock,
                 dirty = excluded.dirty",
            params![vault, item_id, clock, dirty as i64],
        )?;
        Ok(())
    }

    /// Record that the item is now in sync: store the settled clock and clear
    /// the dirty flag.
    ///
    /// Fails with [`StoreError::NotFound`] when there is no row to mark, so a
    /// caller cannot silently acknowledge an item it never tracked.
    pub fn sync_mark_clean(
        &self,
        vault: &str,
        item_id: &str,
        clock: &Clock,
    ) -> Result<(), StoreError> {
        let clock = encode_clock(clock)?;
        let changed = self.conn.execute(
            "UPDATE sync_items SET clock = ?3, dirty = 0
             WHERE vault_uuid = ?1 AND item_id = ?2",
            params![vault, item_id, clock],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Store the sealed body the server acknowledged. Called after a push is
    /// accepted, so the next push can diff against what the server holds.
    pub fn sync_set_body(
        &self,
        vault: &str,
        item_id: &str,
        body: &[u8],
        clock: &Clock,
    ) -> Result<(), StoreError> {
        let clock = encode_clock(clock)?;
        let changed = self.conn.execute(
            "UPDATE sync_items SET body = ?3, body_clock = ?4
             WHERE vault_uuid = ?1 AND item_id = ?2",
            params![vault, item_id, body, clock],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Give every item of one vault a sync row, so the first sync after an
    /// account exists uploads what the vault already holds.
    ///
    /// Items created before this device had a keypair were saved when
    /// [`Store::mark_sync_dirty`] had no identity to attribute a write to, so
    /// they carry no row. Seeding them here — rather than at account creation —
    /// keeps one code path for every way an account can arrive: create, enrol,
    /// or a vault that was restored from a backup.
    ///
    /// Idempotent: rows that already exist are untouched, so a second call
    /// cannot re-push an item the server already has. Returns how many rows were
    /// created.
    pub fn sync_backfill(&self, vault: &str, device: &str) -> Result<u64, StoreError> {
        if device.is_empty() {
            return Err(StoreError::Invalid("a device id is required".to_string()));
        }
        let mut clock = Clock::new();
        crate::sync::bump(&mut clock, device);
        let clock = encode_clock(&clock)?;
        let created = self.conn.execute(
            "INSERT INTO sync_items(vault_uuid, item_id, clock, dirty)
             SELECT ?1, item_uuid, ?2, 1 FROM items
             WHERE vault_uuid = ?1
               AND item_uuid NOT IN (SELECT item_id FROM sync_items)
             ON CONFLICT(item_id) DO NOTHING",
            params![vault, clock],
        )?;
        Ok(created as u64)
    }

    /// Mark one item as changed locally: bump this device's counter in its
    /// clock and set the pending flag.
    ///
    /// Every write path calls this, so a save is visible to the engine without
    /// the caller remembering to announce it. A vault with no device row (no
    /// account yet) records nothing here: [`Store::sync_backfill`] seeds those
    /// items when a device identity first exists.
    pub(crate) fn mark_sync_dirty(&self, vault: &str, item_id: &str) -> Result<(), StoreError> {
        let Some(device) = self.local_device_id()? else {
            return Ok(());
        };
        let mut clock = self
            .sync_state(vault, item_id)?
            .map(|state| state.clock)
            .unwrap_or_default();
        crate::sync::bump(&mut clock, &device);
        self.sync_upsert(vault, item_id, &clock, true)
    }

    /// Read a sync-wide metadata value (cursor, server, last sync, …).
    pub fn sync_meta_get(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT value FROM sync_meta WHERE key = ?1",
                params![key],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
    }

    /// Write a sync-wide metadata value, replacing the previous one.
    pub fn sync_meta_set(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO sync_meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Drop one metadata value. Clearing the server URL and the error line is
    /// how "forget the service" is spelled.
    pub fn sync_meta_remove(&self, key: &str) -> Result<(), StoreError> {
        self.conn()
            .execute("DELETE FROM sync_meta WHERE key = ?1", params![key])?;
        Ok(())
    }

    /// Store (or replace) the conflict for `row.item_id`.
    ///
    /// There is at most one conflict per item: a second concurrent arrival
    /// replaces the first, because the user is asked about the item, not about
    /// a queue of intermediate remote revisions.
    pub fn sync_conflict_put(
        &self,
        vault: &str,
        row: &SyncConflictRow,
    ) -> Result<(), StoreError> {
        let local_clock = encode_clock(&row.local_clock)?;
        let remote_clock = encode_clock(&row.remote_clock)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO sync_conflicts(
                 vault_uuid, item_id, local_clock, remote_clock, local_body, remote_body, created_at
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                vault,
                row.item_id,
                local_clock,
                remote_clock,
                row.local_body,
                row.remote_body,
                row.created_at
            ],
        )?;
        Ok(())
    }

    /// Every unresolved conflict of one vault, ordered by item id.
    pub fn sync_conflicts(&self, vault: &str) -> Result<Vec<SyncConflictRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT item_id, local_clock, remote_clock, local_body, remote_body, created_at
             FROM sync_conflicts WHERE vault_uuid = ?1 ORDER BY item_id",
        )?;
        let rows = stmt.query_map(params![vault], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        let mut conflicts = Vec::new();
        for row in rows {
            let (item_id, local_clock, remote_clock, local_body, remote_body, created_at) = row?;
            conflicts.push(SyncConflictRow {
                item_id,
                local_clock: decode_clock(&local_clock)?,
                remote_clock: decode_clock(&remote_clock)?,
                local_body,
                remote_body,
                created_at,
            });
        }
        Ok(conflicts)
    }

    /// Drop the conflict for one item, after the user resolved it — or because
    /// a later operation made it moot.
    pub fn sync_conflict_clear(&self, vault: &str, item_id: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM sync_conflicts WHERE vault_uuid = ?1 AND item_id = ?2",
            params![vault, item_id],
        )?;
        Ok(())
    }

    /// `(dirty items, stored conflicts)` for one vault. Both are counts of rows
    /// the status line shows; neither needs a key, so they answer while the
    /// vault is locked.
    pub fn sync_counts(&self, vault: &str) -> Result<(u32, u32), StoreError> {
        let dirty: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM sync_items WHERE vault_uuid = ?1 AND dirty = 1",
            params![vault],
            |row| row.get(0),
        )?;
        let conflicts: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM sync_conflicts WHERE vault_uuid = ?1",
            params![vault],
            |row| row.get(0),
        )?;
        Ok((dirty as u32, conflicts as u32))
    }

    /// `(dirty items, stored conflicts)` across every vault in the file.
    ///
    /// The status line shows one number for the file, and it has to answer while
    /// the vault is locked, when no vault uuid is available. The engine still
    /// uses [`Store::sync_counts`] for its own per-vault decision.
    pub fn sync_counts_all(&self) -> Result<(u32, u32), StoreError> {
        let dirty: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM sync_items WHERE dirty = 1",
            [],
            |row| row.get(0),
        )?;
        let conflicts: i64 =
            self.conn()
                .query_row("SELECT COUNT(*) FROM sync_conflicts", [], |row| row.get(0))?;
        Ok((dirty as u32, conflicts as u32))
    }

    /// Forget the service but keep what this device knows about each item.
    ///
    /// The cursor and the conflicts belong to one server; the per-item clocks do
    /// not. Deleting them would re-seed every item at `{device: 1}` on the next
    /// run, and a server clock of `{device: 3}` would then dominate a locally
    /// edited item and overwrite it. Clearing the metadata alone restarts the
    /// log from zero while every item keeps the clock that protects its content.
    pub fn sync_forget_server(&self) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM sync_conflicts", [])?;
        tx.execute("DELETE FROM sync_meta", [])?;
        tx.commit()?;
        Ok(())
    }

    /// Queue every item for a full upload and drop the baselines.
    ///
    /// Used when the service origin changes: another server has never seen this
    /// vault, so every item must be pushed, and the previous server's
    /// acknowledged bodies mean nothing to it. Clocks are kept, so an item that
    /// comes back from the new log still compares correctly.
    pub fn sync_requeue_all(&self) -> Result<u64, StoreError> {
        let changed = self.conn.execute(
            "UPDATE sync_items SET dirty = 1, body = NULL, body_clock = NULL",
            [],
        )?;
        Ok(changed as u64)
    }

    /// Wipe every sync row: item states, conflicts and metadata.
    ///
    /// Used when the account or the server changes (a different account must
    /// never inherit another account's clocks or cursor). Runs in one
    /// transaction so a crash cannot leave half of one account's state behind.
    pub fn sync_reset(&self) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM sync_conflicts", [])?;
        tx.execute("DELETE FROM sync_items", [])?;
        tx.execute("DELETE FROM sync_meta", [])?;
        tx.commit()?;
        Ok(())
    }
}

fn encode_clock(clock: &Clock) -> Result<String, StoreError> {
    Ok(serde_json::to_string(clock)?)
}

fn decode_clock(raw: &str) -> Result<Clock, StoreError> {
    Ok(serde_json::from_str(raw)?)
}

/// A clock that represents a write must have at least one non-zero counter.
fn require_write_clock(clock: &Clock) -> Result<(), StoreError> {
    if clock.values().any(|&counter| counter > 0) {
        return Ok(());
    }
    Err(StoreError::Invalid(
        "a sync write needs a non-empty clock".to_string(),
    ))
}
