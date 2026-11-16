//! SQLite storage: one file, one schema version, every query in this module.
//!
//! What is stored is deliberately narrow. The `items` table holds an opaque
//! item id, a version vector, a deletion flag, the ciphertext and its size.
//! There is no column for a title, a URL, a username, a category, a tag or a
//! field name, and no table that counts fields — a server cannot leak what it
//! never stored.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::clock::{relation, Clock, Relation};

pub const SCHEMA_VERSION: i64 = 2;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
) WITHOUT ROWID;

-- `device_id` is the primary key, not `(account_id, device_id)`: a request is
-- authenticated by device id alone, before the account is known, so a device id
-- must be unique server-wide. Ids are 128-bit random, so this costs nothing.
CREATE TABLE IF NOT EXISTS devices (
    device_id     TEXT PRIMARY KEY,
    account_id    TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    signing_pub   BLOB NOT NULL,
    agreement_pub BLOB NOT NULL,
    name          TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    -- NULL while the device may sign. Revocation sets the time and keeps the
    -- row: who was enrolled, and when their access ended, is the audit trail.
    revoked_at    INTEGER
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS devices_account ON devices(account_id);

-- An offer is the existing device's half of enrolment. It is keyed by the
-- device that will use it, so a claim must present both the code hash and the
-- device id. `claimed_*` is what the new device sent at claim time; the device
-- row is only written by `ack`, which is why an abandoned enrolment leaves no
-- device behind.
CREATE TABLE IF NOT EXISTS enroll_offers (
    account_id            TEXT NOT NULL,
    new_device_id         TEXT NOT NULL,
    code_hash             TEXT NOT NULL,
    sealed                BLOB NOT NULL,
    expires_at            INTEGER NOT NULL,
    created_at            INTEGER NOT NULL,
    claimed_at            INTEGER,
    claimed_signing_pub   BLOB,
    claimed_agreement_pub BLOB,
    claimed_name          TEXT,
    acked_at              INTEGER,
    PRIMARY KEY (account_id, new_device_id)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS enroll_code ON enroll_offers(code_hash);

-- `seq` is a per-account monotonically increasing revision. It is not the
-- item's position in a list; a new revision of an existing item gets a new
-- `seq`, which is what makes pull-by-`since` a complete log of changes.
--
-- The ciphertext itself lives in the blob directory, named by its SHA-256, so
-- the database row is a reference and a clock. `blob` is CSV-safe hex and is
-- empty for a tombstone; `size` is the blob length in bytes, kept in the row so
-- `state` never has to stat the filesystem.
CREATE TABLE IF NOT EXISTS items (
    account_id TEXT NOT NULL,
    item_id    TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    clock      TEXT NOT NULL,
    deleted    INTEGER NOT NULL,
    blob       TEXT NOT NULL,
    size       INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (account_id, item_id)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS items_seq ON items(account_id, seq);
";

/// v2 added `devices.revoked_at`. `CREATE TABLE IF NOT EXISTS` leaves an
/// existing v1 table alone, so the one new column is added in place. Nothing
/// else about the schema changed, and no row is touched.
fn migrate(conn: &Connection) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare("PRAGMA table_info(devices)")?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut has_revoked = false;
    for column in columns {
        if column? == "revoked_at" {
            has_revoked = true;
            break;
        }
    }
    drop(stmt);
    if !has_revoked {
        conn.execute("ALTER TABLE devices ADD COLUMN revoked_at INTEGER", [])?;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("stored clock is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("stored row is inconsistent: {0}")]
    Corrupt(String),
}

pub struct Store {
    conn: Connection,
    blob_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    pub device_id: String,
    pub account_id: String,
    pub signing_pub: [u8; 32],
    /// Unix seconds when this device was revoked; `None` while it may sign.
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredOp {
    pub seq: u64,
    pub item_id: String,
    pub clock: Clock,
    pub deleted: bool,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub struct PushOutcome {
    pub applied: Vec<String>,
    pub conflicts: Vec<StoredOp>,
}

#[derive(Debug)]
pub struct PullPage {
    pub ops: Vec<StoredOp>,
    pub next_seq: u64,
    pub has_more: bool,
}

#[derive(Debug)]
pub struct Snapshot {
    pub devices: Vec<DeviceInfo>,
    pub items: u64,
    pub bytes: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CreateAccount {
    Created,
    AccountExists,
    DeviceExists,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OfferOutcome {
    Stored,
    AlreadyEnrolled,
}

#[derive(Debug)]
pub struct ClaimedOffer {
    pub account_id: String,
    pub sealed: Vec<u8>,
    pub devices: Vec<DeviceInfo>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClaimError {
    InvalidCode,
    Expired,
    AlreadyEnrolled,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AckOutcome {
    Acknowledged,
    AlreadyAcknowledged,
    NotFound,
    NotClaimed,
    Expired,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// The row was live and now carries this revocation time.
    Revoked(i64),
    /// Already revoked; the original time is returned, so a retry is stable.
    AlreadyRevoked(i64),
    /// No such device in the requesting account.
    Unknown,
    /// An actor cannot withdraw its own access; that would leave an account
    /// whose owner has no way to sign.
    SelfRevoke,
}

impl Store {
    pub fn open(path: &Path, blob_dir: &Path) -> Result<Store, StoreError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::create_dir_all(blob_dir)?;
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )?;
        conn.execute_batch(SCHEMA)?;
        migrate(&conn)?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [SCHEMA_VERSION.to_string()],
        )?;
        Ok(Store {
            conn,
            blob_dir: blob_dir.to_path_buf(),
        })
    }

    pub fn account_count(&self) -> Result<u64, StoreError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get(0))?;
        Ok(count.max(0) as u64)
    }

    pub fn create_account(
        &mut self,
        account_id: &str,
        device_id: &str,
        signing_pub: &[u8; 32],
        agreement_pub: &[u8; 32],
        device_name: &str,
        now: i64,
    ) -> Result<CreateAccount, StoreError> {
        let tx = self.conn.transaction()?;
        let account_exists: i64 = tx.query_row(
            "SELECT COUNT(*) FROM accounts WHERE account_id = ?1",
            [account_id],
            |row| row.get(0),
        )?;
        if account_exists > 0 {
            return Ok(CreateAccount::AccountExists);
        }
        let device_exists: i64 = tx.query_row(
            "SELECT COUNT(*) FROM devices WHERE device_id = ?1",
            [device_id],
            |row| row.get(0),
        )?;
        if device_exists > 0 {
            return Ok(CreateAccount::DeviceExists);
        }
        tx.execute(
            "INSERT INTO accounts (account_id, created_at) VALUES (?1, ?2)",
            params![account_id, now],
        )?;
        tx.execute(
            "INSERT INTO devices (device_id, account_id, signing_pub, agreement_pub, name, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![device_id, account_id, signing_pub.as_slice(), agreement_pub.as_slice(), device_name, now],
        )?;
        tx.commit()?;
        Ok(CreateAccount::Created)
    }

    pub fn device(&self, device_id: &str) -> Result<Option<DeviceRow>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT account_id, signing_pub, revoked_at FROM devices WHERE device_id = ?1",
                [device_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((account_id, key, revoked_at)) => {
                let signing_pub: [u8; 32] = key.try_into().map_err(|_| {
                    StoreError::Corrupt(format!("device {device_id} has a bad signing key"))
                })?;
                Ok(Some(DeviceRow {
                    device_id: device_id.to_string(),
                    account_id,
                    signing_pub,
                    revoked_at,
                }))
            }
        }
    }

    /// Inserts or replaces an offer for `(account, new_device)`. Replacing is
    /// intentional: an expired or abandoned offer is retried with a new code,
    /// and an offer that was already acknowledged is refused because that
    /// device exists.
    pub fn put_offer(
        &mut self,
        account_id: &str,
        new_device_id: &str,
        code_hash: &str,
        sealed: &[u8],
        expires_at: i64,
        now: i64,
    ) -> Result<OfferOutcome, StoreError> {
        let tx = self.conn.transaction()?;
        let already_device: i64 = tx.query_row(
            "SELECT COUNT(*) FROM devices WHERE device_id = ?1 AND account_id = ?2",
            params![new_device_id, account_id],
            |row| row.get(0),
        )?;
        if already_device > 0 {
            return Ok(OfferOutcome::AlreadyEnrolled);
        }
        // `acked_at IS NOT NULL` is what makes the read typed: an unacked offer
        // stores NULL there, and reading a NULL into `i64` is a column-type
        // error, not a `None`. Without the predicate a second offer for the same
        // device — a normal retry after a lost response — is a 500.
        let acked: Option<i64> = tx
            .query_row(
                "SELECT acked_at FROM enroll_offers
                 WHERE account_id = ?1 AND new_device_id = ?2 AND acked_at IS NOT NULL",
                params![account_id, new_device_id],
                |row| row.get(0),
            )
            .optional()?;
        if acked.is_some() {
            return Ok(OfferOutcome::AlreadyEnrolled);
        }
        tx.execute(
            "INSERT INTO enroll_offers
                 (account_id, new_device_id, code_hash, sealed, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(account_id, new_device_id) DO UPDATE SET
                 code_hash = excluded.code_hash,
                 sealed = excluded.sealed,
                 expires_at = excluded.expires_at,
                 created_at = excluded.created_at,
                 claimed_at = NULL, claimed_signing_pub = NULL,
                 claimed_agreement_pub = NULL, claimed_name = NULL",
            params![account_id, new_device_id, code_hash, sealed, expires_at, now],
        )?;
        tx.commit()?;
        Ok(OfferOutcome::Stored)
    }

    /// Records the new device's claim and hands back the sealed key envelope
    /// plus the current device list. The device row is *not* created here: an
    /// unacknowledged claim cannot authenticate anything.
    pub fn claim_offer(
        &mut self,
        code_hash: &str,
        new_device_id: &str,
        signing_pub: &[u8; 32],
        agreement_pub: &[u8; 32],
        device_name: &str,
        now: i64,
    ) -> Result<Result<ClaimedOffer, ClaimError>, StoreError> {
        let tx = self.conn.transaction()?;
        let row = tx
            .query_row(
                "SELECT account_id, sealed, expires_at, acked_at FROM enroll_offers
                 WHERE code_hash = ?1 AND new_device_id = ?2
                 ORDER BY created_at DESC LIMIT 1",
                params![code_hash, new_device_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                },
            )
            .optional()?;

        let Some((account_id, sealed, expires_at, acked_at)) = row else {
            return Ok(Err(ClaimError::InvalidCode));
        };
        if acked_at.is_some() {
            return Ok(Err(ClaimError::AlreadyEnrolled));
        }
        if expires_at < now {
            return Ok(Err(ClaimError::Expired));
        }
        let already_device: i64 = tx.query_row(
            "SELECT COUNT(*) FROM devices WHERE device_id = ?1",
            [new_device_id],
            |row| row.get(0),
        )?;
        if already_device > 0 {
            return Ok(Err(ClaimError::AlreadyEnrolled));
        }

        tx.execute(
            "UPDATE enroll_offers SET
                 claimed_at = ?3,
                 claimed_signing_pub = ?4,
                 claimed_agreement_pub = ?5,
                 claimed_name = ?6
             WHERE account_id = ?1 AND new_device_id = ?2",
            params![
                account_id,
                new_device_id,
                now,
                signing_pub.as_slice(),
                agreement_pub.as_slice(),
                device_name
            ],
        )?;

        let devices = devices(&tx, &account_id)?;
        tx.commit()?;
        Ok(Ok(ClaimedOffer {
            account_id,
            sealed,
            devices,
        }))
    }

    /// Turns a claim into a device row. This is the only path that creates a
    /// device after account creation, and it runs on an authenticated request
    /// from an existing device of the same account.
    pub fn ack_offer(
        &mut self,
        account_id: &str,
        new_device_id: &str,
        now: i64,
    ) -> Result<AckOutcome, StoreError> {
        let tx = self.conn.transaction()?;
        let row = tx
            .query_row(
                "SELECT expires_at, claimed_at, acked_at,
                        claimed_signing_pub, claimed_agreement_pub, claimed_name
                 FROM enroll_offers WHERE account_id = ?1 AND new_device_id = ?2",
                params![account_id, new_device_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()?;

        let Some((expires_at, claimed_at, acked_at, signing_pub, agreement_pub, name)) = row else {
            return Ok(AckOutcome::NotFound);
        };
        if acked_at.is_some() {
            return Ok(AckOutcome::AlreadyAcknowledged);
        }
        if claimed_at.is_none() {
            return Ok(AckOutcome::NotClaimed);
        }
        if expires_at < now {
            return Ok(AckOutcome::Expired);
        }
        let (Some(signing_pub), Some(agreement_pub), Some(name)) =
            (signing_pub, agreement_pub, name)
        else {
            return Ok(AckOutcome::NotClaimed);
        };

        let device_exists: i64 = tx.query_row(
            "SELECT COUNT(*) FROM devices WHERE device_id = ?1",
            [new_device_id],
            |row| row.get(0),
        )?;
        if device_exists > 0 {
            return Ok(AckOutcome::AlreadyAcknowledged);
        }
        tx.execute(
            "INSERT INTO devices (device_id, account_id, signing_pub, agreement_pub, name, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![new_device_id, account_id, signing_pub, agreement_pub, name, now],
        )?;
        tx.execute(
            "UPDATE enroll_offers SET acked_at = ?3
             WHERE account_id = ?1 AND new_device_id = ?2",
            params![account_id, new_device_id, now],
        )?;
        tx.commit()?;
        Ok(AckOutcome::Acknowledged)
    }

    /// Withdraw one device's access inside the actor's account.
    ///
    /// The row is updated, never deleted: `devices` is the record of what was
    /// enrolled and when it stopped being trusted. A retry returns the original
    /// timestamp instead of moving it, and an actor cannot revoke itself.
    pub fn revoke_device(
        &mut self,
        account_id: &str,
        actor_device_id: &str,
        target_device_id: &str,
        now: i64,
    ) -> Result<RevokeOutcome, StoreError> {
        if actor_device_id == target_device_id {
            return Ok(RevokeOutcome::SelfRevoke);
        }
        let tx = self.conn.transaction()?;
        let target: Option<Option<i64>> = tx
            .query_row(
                "SELECT revoked_at FROM devices WHERE device_id = ?1 AND account_id = ?2",
                params![target_device_id, account_id],
                |row| row.get(0),
            )
            .optional()?;
        let outcome = match target {
            None => RevokeOutcome::Unknown,
            Some(Some(revoked_at)) => RevokeOutcome::AlreadyRevoked(revoked_at),
            Some(None) => {
                tx.execute(
                    "UPDATE devices SET revoked_at = ?3
                     WHERE device_id = ?1 AND account_id = ?2",
                    params![target_device_id, account_id, now],
                )?;
                RevokeOutcome::Revoked(now)
            }
        };
        tx.commit()?;
        Ok(outcome)
    }

    /// Applies a validated batch atomically. The merge rule is the whole point:
    /// a dominating clock overwrites, a dominated one is ignored (the sender is
    /// behind and will see the newer op on pull), an equal clock with identical
    /// content is idempotent, and everything else is concurrent and reported
    /// back untouched so the client can merge and push again.
    ///
    /// Ciphertext is written to the blob directory *before* the row that
    /// references it commits. A crash in between leaves an unreferenced blob,
    /// which is harmless; the reverse order could leave a committed row whose
    /// payload does not exist, which is not.
    pub fn push(
        &mut self,
        account_id: &str,
        ops: &[crate::api::IncomingOp],
        now: i64,
    ) -> Result<PushOutcome, StoreError> {
        let blob_dir = self.blob_dir.clone();
        let tx = self.conn.transaction()?;
        let mut next_seq: i64 = tx.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM items WHERE account_id = ?1",
            [account_id],
            |row| row.get(0),
        )?;
        let mut applied = Vec::new();
        let mut conflicts = Vec::new();

        for op in ops {
            let incoming_blob = if op.deleted {
                String::new()
            } else {
                blob_hash(&op.ciphertext)
            };

            let stored = tx
                .query_row(
                    "SELECT seq, clock, deleted, blob FROM items
                     WHERE account_id = ?1 AND item_id = ?2",
                    params![account_id, op.item_id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, String>(3)?,
                        ))
                    },
                )
                .optional()?;

            let Some((seq, clock_json, deleted, stored_blob)) = stored else {
                next_seq += 1;
                if !op.deleted {
                    write_blob(&blob_dir, &incoming_blob, &op.ciphertext)?;
                }
                tx.execute(
                    "INSERT INTO items
                         (account_id, item_id, seq, clock, deleted, blob, size, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        account_id,
                        op.item_id,
                        next_seq,
                        serde_json::to_string(&op.clock)?,
                        op.deleted as i64,
                        incoming_blob,
                        op.ciphertext.len() as i64,
                        now
                    ],
                )?;
                applied.push(op.item_id.clone());
                continue;
            };

            let stored_clock: Clock = serde_json::from_str(&clock_json)?;
            match relation(&op.clock, &stored_clock) {
                Relation::Dominates => {
                    next_seq += 1;
                    if !op.deleted {
                        write_blob(&blob_dir, &incoming_blob, &op.ciphertext)?;
                    }
                    tx.execute(
                        "UPDATE items SET seq = ?3, clock = ?4, deleted = ?5,
                                          blob = ?6, size = ?7, updated_at = ?8
                         WHERE account_id = ?1 AND item_id = ?2",
                        params![
                            account_id,
                            op.item_id,
                            next_seq,
                            serde_json::to_string(&op.clock)?,
                            op.deleted as i64,
                            incoming_blob,
                            op.ciphertext.len() as i64,
                            now
                        ],
                    )?;
                    applied.push(op.item_id.clone());
                }
                Relation::Equal => {
                    if deleted == op.deleted as i64 && stored_blob == incoming_blob {
                        applied.push(op.item_id.clone());
                    } else {
                        conflicts.push(StoredOp {
                            seq: seq.max(0) as u64,
                            item_id: op.item_id.clone(),
                            clock: stored_clock,
                            deleted: deleted != 0,
                            ciphertext: read_blob(&blob_dir, &stored_blob)?,
                        });
                    }
                }
                Relation::Dominated => {}
                Relation::Concurrent => conflicts.push(StoredOp {
                    seq: seq.max(0) as u64,
                    item_id: op.item_id.clone(),
                    clock: stored_clock,
                    deleted: deleted != 0,
                    ciphertext: read_blob(&blob_dir, &stored_blob)?,
                }),
            }
        }

        tx.commit()?;
        Ok(PushOutcome { applied, conflicts })
    }

    pub fn pull(&self, account_id: &str, since: u64, limit: u64) -> Result<PullPage, StoreError> {
        let since = since.min(i64::MAX as u64) as i64;
        let limit = limit.max(1).min(i64::MAX as u64) as i64;
        let mut stmt = self.conn.prepare(
            "SELECT seq, item_id, clock, deleted, blob FROM items
             WHERE account_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![account_id, since, limit + 1], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;

        let mut ops = Vec::new();
        for row in rows {
            let (seq, item_id, clock_json, deleted, blob) = row?;
            let clock: Clock = serde_json::from_str(&clock_json)?;
            ops.push(StoredOp {
                seq: seq.max(0) as u64,
                item_id,
                clock,
                deleted: deleted != 0,
                ciphertext: read_blob(&self.blob_dir, &blob)?,
            });
        }

        let has_more = ops.len() > limit as usize;
        ops.truncate(limit as usize);
        let next_seq = ops.last().map_or(since.max(0) as u64, |op| op.seq);
        Ok(PullPage {
            ops,
            next_seq,
            has_more,
        })
    }

    pub fn snapshot(&self, account_id: &str) -> Result<Snapshot, StoreError> {
        let devices = devices(&self.conn, account_id)?;
        let (items, bytes) = self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM items WHERE account_id = ?1",
            [account_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        Ok(Snapshot {
            devices,
            items: items.max(0) as u64,
            bytes: bytes.max(0) as u64,
        })
    }
}

fn devices(conn: &Connection, account_id: &str) -> Result<Vec<DeviceInfo>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT device_id, name, created_at, revoked_at FROM devices
         WHERE account_id = ?1 ORDER BY created_at, device_id",
    )?;
    let rows = stmt.query_map([account_id], |row| {
        Ok(DeviceInfo {
            device_id: row.get(0)?,
            device_name: row.get(1)?,
            created_at: row.get(2)?,
            revoked_at: row.get(3)?,
        })
    })?;
    let mut devices = Vec::new();
    for row in rows {
        devices.push(row?);
    }
    Ok(devices)
}

// ---------------------------------------------------------------------------
// Blobs
// ---------------------------------------------------------------------------

/// Content-addressed, like a Git object: the path is derived from the bytes, so
/// writing the same ciphertext twice is a no-op and a blob can never be
/// overwritten with different content.
fn blob_hash(ciphertext: &[u8]) -> String {
    hex::encode(Sha256::digest(ciphertext))
}

/// `<blob_dir>/<first two hex characters>/<full hex>`. Two levels keep any one
/// directory from holding every object in the account.
fn blob_path(blob_dir: &Path, hash: &str) -> Result<PathBuf, StoreError> {
    if hash.len() < 2 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StoreError::Corrupt(format!("bad blob reference {hash:?}")));
    }
    Ok(blob_dir.join(&hash[..2]).join(hash))
}

/// Writes `data` if no blob with that hash exists yet. The temporary file plus
/// rename means a reader never sees a partial object, and the `sync_all` means
/// a committed row's payload survives a power cut.
fn write_blob(blob_dir: &Path, hash: &str, data: &[u8]) -> Result<(), StoreError> {
    if hash.is_empty() {
        return Ok(());
    }
    debug_assert_eq!(hash, blob_hash(data));
    let path = blob_path(blob_dir, hash)?;
    if path.is_file() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    {
        use std::io::Write as _;
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, &path)?;
    Ok(())
}

fn read_blob(blob_dir: &Path, hash: &str) -> Result<Vec<u8>, StoreError> {
    if hash.is_empty() {
        return Ok(Vec::new());
    }
    let path = blob_path(blob_dir, hash)?;
    std::fs::read(&path).map_err(|error| {
        StoreError::Corrupt(format!("blob {} is unreadable: {error}", path.display()))
    })
}
