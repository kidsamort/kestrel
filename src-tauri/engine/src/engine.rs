//! One pull-then-push loop over one vault and one account.
//!
//! The loop is the only place that turns a remote operation into a local row
//! and a local row into a wire operation. Its rules are the ones in
//! `PROTOCOL.md` and [`kestrel_core::sync::merge`]:
//!
//! * the item-level clock decides whether a whole side wins; only genuinely
//!   concurrent copies are walked field by field;
//! * a field both sides changed is never resolved by a timestamp — the engine
//!   stores both sealed bodies and surfaces the conflict;
//! * a tombstone applies only when it dominates the item, so a delete
//!   concurrent with an edit is a conflict, not a lost password;
//! * the merged clock always dominates both inputs, so pushing it settles the
//!   server-side conflict on the next round.
//!
//! **The baseline.** The store keeps the sealed body the server last
//! acknowledged in `sync_items.body`. A local edit only bumps the item clock,
//! so the engine opens that acknowledged body and diffs the current item
//! against it: the paths whose value actually changed get the new item clock,
//! the rest keep theirs. Without the baseline every field would look changed
//! and a disjoint edit would be reported as a conflict.
//!
//! **Idempotence.** The cursor is exclusive and is persisted after every page,
//! so an acknowledged operation is never applied twice. A round with no applied
//! remote operation and no accepted push stops the loop, which is why a second
//! [`sync_once`] with nothing to do does no work.

use std::collections::{BTreeMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use kestrel_core::crypto::SymKey;
use kestrel_core::model::{Field, Item};
use kestrel_core::store::sync::{ItemSyncState, SyncConflictRow};
use kestrel_core::store::{Store, StoreError, VaultMeta};
use kestrel_core::sync::body::{open_body, seal_body};
use kestrel_core::sync::merge::{field_paths, merge_bodies, Merge, SyncBody, DELETED_PATH};
use kestrel_core::sync::{bump, compare, merge_clocks, Clock, Ordering};
use kestrel_net::{Conflict, PullOp, PushOp, PushRequest, SyncClient};

use crate::codec;
use crate::error::EngineError;

/// Rounds in one run. Three is enough for pull → push → adopt the settlement;
/// more would only retry an unresolved conflict, which the user has to answer.
const MAX_ROUNDS: usize = 3;
/// The service's default and the page size the engine asks for.
const PULL_LIMIT: u64 = 200;
/// One push request; the protocol accepts up to 1000, and 200 keeps one bad
/// batch from being an outsized failure.
const PUSH_LIMIT: usize = 200;

/// Everything one run needs: the vault, its keys, the account and the wire.
///
/// The caller owns every value; the context only borrows them for the length
/// of a call, so no key outlives the session that unlocked it.
pub struct SyncContext<'a> {
    /// The vault store and the rows to sync.
    pub store: &'a Store,
    /// The master key, which opens the local item rows.
    pub master: &'a SymKey,
    /// The vault identity the item rows are bound to.
    pub meta: &'a VaultMeta,
    /// The account every body is sealed under.
    pub account_id: &'a str,
    /// The account key shared by the account's devices.
    pub account_key: &'a SymKey,
    /// This device's id, also this unit in every clock.
    pub device_id: &'a str,
    /// The authenticated connection to the service.
    pub client: &'a SyncClient,
}

/// What one [`sync_once`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncReport {
    /// Remote operations that changed local state, including state-only
    /// tombstones for an item this device had never seen. Reading an
    /// operation that was already applied or is older than the local copy is
    /// not a pull.
    pub pulled: u64,
    /// Operations the service reported as applied. A retried operation that
    /// was already byte-identical counts too, because the service lists it in
    /// `applied`; the push is nevertheless idempotent.
    pub pushed: u64,
    /// Unresolved conflicts stored for this vault after the run.
    pub conflicts: u64,
    /// The cursor after the run, i.e. the last server revision this device has
    /// seen. The next run pulls strictly after it.
    pub cursor: u64,
}

/// Run the sync loop: up to three pull-then-push rounds, stopping early when a
/// round changes nothing.
///
/// On success the cursor, `last_sync_at`, `state` (`idle` or `conflict`) and the
/// cleared `error` line are written. On failure `state` is set to `error` and
/// `error` carries the message; the returned error is the cause, not the
/// bookkeeping.
///
/// A conflict is not an error: the item keeps its local value, both sealed
/// bodies are stored, and the report's `conflicts` counts them.
pub fn sync_once(ctx: &SyncContext<'_>) -> Result<SyncReport, EngineError> {
    // A run can take as long as the network does, so the status line says so
    // while it happens: another window reading `sync_status` must not show
    // "Synced" during an upload.
    let _ = ctx.store.sync_meta_set("state", "syncing");
    match sync_inner(ctx) {
        Ok(report) => Ok(report),
        Err(error) => {
            // Best effort by design: the status line must say "error" even when
            // the failure came from the store itself. The error the caller gets
            // is the one that actually happened, never a bookkeeping failure.
            // A service that cannot be reached is "offline", not "error": the
            // difference is whether the vault is wrong or the network is.
            let state = if matches!(error, EngineError::Wire(_)) {
                "offline"
            } else {
                "error"
            };
            let _ = ctx.store.sync_meta_set("state", state);
            let _ = ctx.store.sync_meta_set("error", &error.to_string());
            Err(error)
        }
    }
}

fn sync_inner(ctx: &SyncContext<'_>) -> Result<SyncReport, EngineError> {
    ensure_account(ctx)?;
    // A vault that already holds items when sync is switched on has no sync
    // rows for them: they were saved before this device had an identity. Seed
    // them now, so the first run uploads the vault instead of reporting "nothing
    // to do". Idempotent, so every run may call it.
    ctx.store.sync_backfill(&ctx.meta.vault_uuid, ctx.device_id)?;
    let mut cursor = load_cursor(ctx)?;
    let mut pulled = 0u64;
    let mut pushed = 0u64;

    for _ in 0..MAX_ROUNDS {
        let mut changed = false;
        changed |= pull(ctx, &mut cursor, &mut pulled)?;
        changed |= push(ctx, &mut pushed)?;
        if !changed {
            break;
        }
    }

    let conflicts = u64::from(ctx.store.sync_counts(&ctx.meta.vault_uuid)?.1);
    ctx.store.sync_meta_set("cursor", &cursor.to_string())?;
    ctx.store
        .sync_meta_set("last_sync_at", &now_secs().to_string())?;
    ctx.store.sync_meta_set(
        "state",
        if conflicts > 0 { "conflict" } else { "idle" },
    )?;
    ctx.store.sync_meta_remove("error")?;
    Ok(SyncReport {
        pulled,
        pushed,
        conflicts,
        cursor,
    })
}

/// The account guard shared with the conflict surface.
///
/// Refuses a call when the vault has no account, or when the vault or the
/// client is bound to a different account than the one in the context. Sealing
/// a body under the wrong account would only fail later, as an authentication
/// error on the other device.
pub(crate) fn ensure_account(ctx: &SyncContext<'_>) -> Result<(), EngineError> {
    let status = ctx.store.account_status()?;
    if !status.exists {
        return Err(EngineError::NoAccount);
    }
    if let Some(stored) = status.account_id.as_deref() {
        if stored != ctx.account_id {
            return Err(EngineError::AccountMismatch {
                given: ctx.account_id.to_string(),
                bound_by: "vault",
                found: stored.to_string(),
            });
        }
    }
    // One account, one vault. A file with several vaults shares one account and
    // one change log, and a pulled body cannot say which vault it belongs to;
    // writing it into whichever vault is unlocked would move items between
    // vaults. Refuse instead, loudly, until vault identity is exchanged on the
    // wire.
    if ctx.store.vault_count()? > 1 {
        return Err(EngineError::MultipleVaults);
    }
    if ctx.client.account_id() != ctx.account_id {
        return Err(EngineError::AccountMismatch {
            given: ctx.account_id.to_string(),
            bound_by: "client",
            found: ctx.client.account_id().to_string(),
        });
    }
    Ok(())
}

/* ------------------------------------------------------------------ pull ---- */

fn pull(
    ctx: &SyncContext<'_>,
    cursor: &mut u64,
    pulled: &mut u64,
) -> Result<bool, EngineError> {
    let mut changed = false;
    let mut since = *cursor;
    loop {
        let page = ctx.client.pull(since, Some(PULL_LIMIT))?;
        let next_seq = page.next_seq;
        if next_seq < since {
            return Err(EngineError::Payload(format!(
                "pull returned next_seq {next_seq} behind since {since}"
            )));
        }
        for op in &page.ops {
            if apply_pull_op(ctx, op)? {
                *pulled += 1;
                changed = true;
            }
        }
        // The cursor is exclusive: persisting `next_seq` after the page means
        // the operations just applied are never offered again.
        *cursor = next_seq;
        ctx.store.sync_meta_set("cursor", &cursor.to_string())?;
        // An empty page that claims more would loop forever on the same
        // `since`; the service never sends one, and refusing to spin is safer
        // than trusting it.
        if !page.has_more || page.ops.is_empty() {
            break;
        }
        since = next_seq;
    }
    Ok(changed)
}

/// Apply one change-log row. Returns whether it changed local state.
fn apply_pull_op(ctx: &SyncContext<'_>, op: &PullOp) -> Result<bool, EngineError> {
    // The change log belongs to the account, and one account can hold several
    // vaults. An id this vault has never tracked and does not contain is another
    // vault's item: it is skipped here and applied when that vault is unlocked.
    // Anything this vault does know must open, so corruption is still an error.
    let known = ctx.store.sync_state(&ctx.meta.vault_uuid, &op.item_id)?.is_some()
        || ctx.store.get(ctx.master, ctx.meta, &op.item_id).is_ok();
    let remote = match open_remote(ctx, &op.item_id, op.deleted, &op.ciphertext, &op.clock) {
        Ok(remote) => remote,
        Err(_) if !known => return Ok(false),
        Err(error) => return Err(error),
    };
    match ctx.store.sync_state(&ctx.meta.vault_uuid, &op.item_id)? {
        None => apply_unseen(ctx, op, &remote),
        Some(state) => match compare(&state.clock, &op.clock) {
            Ordering::Dominated => {
                adopt_remote(ctx, &op.item_id, &remote, &op.clock)?;
                Ok(true)
            }
            Ordering::Dominates | Ordering::Equal => Ok(false),
            Ordering::Concurrent => merge_remote(ctx, &state, op, &remote),
        },
    }
}

/// The item has no sync row: this device has never seen it.
///
/// A live body is written and acknowledged. A tombstone has nothing to trash,
/// but its clock is recorded so a later dominating live operation can land.
fn apply_unseen(
    ctx: &SyncContext<'_>,
    op: &PullOp,
    remote: &RemoteBody,
) -> Result<bool, EngineError> {
    match (&remote.body, &remote.sealed) {
        (Some(body), Some(sealed)) => {
            ctx.store
                .save_item(ctx.master, ctx.meta, body.item.clone())?;
            set_trashed(ctx, &op.item_id, false)?;
            ctx.store
                .sync_upsert(&ctx.meta.vault_uuid, &op.item_id, &op.clock, false)?;
            ctx.store
                .sync_set_body(&ctx.meta.vault_uuid, &op.item_id, sealed, &op.clock)?;
            ctx.store
                .sync_mark_clean(&ctx.meta.vault_uuid, &op.item_id, &op.clock)?;
        }
        _ => {
            ctx.store
                .sync_upsert(&ctx.meta.vault_uuid, &op.item_id, &op.clock, false)?;
        }
    }
    Ok(true)
}

/// Adopt a remote operation that dominates the local item.
fn adopt_remote(
    ctx: &SyncContext<'_>,
    item_id: &str,
    remote: &RemoteBody,
    clock: &Clock,
) -> Result<(), EngineError> {
    match &remote.body {
        Some(body) => {
            ctx.store
                .save_item(ctx.master, ctx.meta, body.item.clone())?;
            set_trashed(ctx, item_id, false)?;
        }
        None => set_trashed(ctx, item_id, true)?,
    }
    if let Some(sealed) = &remote.sealed {
        ctx.store
            .sync_set_body(&ctx.meta.vault_uuid, item_id, sealed, clock)?;
    }
    ctx.store
        .sync_mark_clean(&ctx.meta.vault_uuid, item_id, clock)?;
    // A settled item no longer has anything to ask the user about.
    ctx.store
        .sync_conflict_clear(&ctx.meta.vault_uuid, item_id)?;
    Ok(())
}

/// The local and remote clocks are concurrent: merge field by field.
fn merge_remote(
    ctx: &SyncContext<'_>,
    state: &ItemSyncState,
    op: &PullOp,
    remote: &RemoteBody,
) -> Result<bool, EngineError> {
    let baseline = match (&state.body, &state.body_clock) {
        (Some(sealed), Some(at)) => Some((sealed.as_slice(), at)),
        _ => None,
    };
    let local = match local_body(ctx, &state.item_id, &state.clock, baseline)? {
        Some(body) => body,
        // The local row is gone and there is no acknowledged body to describe
        // it. Two tombstones carry no value to lose, so settle the clock; a
        // live remote side still conflicts with the local deletion.
        None => match &remote.body {
            None => {
                let mut clock = merge_clocks(&state.clock, &op.clock);
                bump(&mut clock, ctx.device_id);
                ctx.store
                    .sync_upsert(&ctx.meta.vault_uuid, &state.item_id, &clock, false)?;
                ctx.store
                    .sync_mark_clean(&ctx.meta.vault_uuid, &state.item_id, &clock)?;
                ctx.store
                    .sync_conflict_clear(&ctx.meta.vault_uuid, &state.item_id)?;
                return Ok(true);
            }
            Some(body) => SyncBody {
                item: body.item.clone(),
                deleted: true,
                clocks: BTreeMap::new(),
            },
        },
    };
    let remote_body = remote_body(local.clone(), remote);

    match merge_bodies(
        &local,
        &state.clock,
        &remote_body,
        &op.clock,
        ctx.device_id,
    ) {
        Merge::Local => Ok(false),
        Merge::Remote => {
            adopt_remote(ctx, &state.item_id, remote, &op.clock)?;
            Ok(true)
        }
        Merge::Merged { body, clock, conflicts } => {
            if conflicts.is_empty() {
                write_merged(ctx, &body, &clock)?;
            } else {
                store_conflict(
                    ctx,
                    &state.item_id,
                    &state.clock,
                    &op.clock,
                    &local,
                    &remote_body,
                )?;
                // Keep the local write pending so it cannot be lost while the
                // user decides; a clean row becomes dirty again on purpose.
                if !state.dirty {
                    ctx.store
                        .sync_upsert(&ctx.meta.vault_uuid, &state.item_id, &state.clock, true)?;
                }
            }
            Ok(true)
        }
    }
}

/// Open a remote operation: a live one carries a sealed body, a tombstone does
/// not.
fn open_remote(
    ctx: &SyncContext<'_>,
    item_id: &str,
    deleted: bool,
    ciphertext: &str,
    clock: &Clock,
) -> Result<RemoteBody, EngineError> {
    if deleted {
        if !ciphertext.is_empty() {
            return Err(EngineError::Payload(format!(
                "the tombstone for {item_id} carried a ciphertext"
            )));
        }
        return Ok(RemoteBody {
            body: None,
            sealed: None,
        });
    }
    if ciphertext.is_empty() {
        return Err(EngineError::Payload(format!(
            "the live operation for {item_id} carried no ciphertext"
        )));
    }
    let sealed = codec::decode(ciphertext)?;
    let body = open_body(
        ctx.account_key,
        ctx.account_id,
        item_id,
        clock,
        &sealed,
    )?;
    Ok(RemoteBody {
        body: Some(body),
        sealed: Some(sealed),
    })
}

struct RemoteBody {
    body: Option<SyncBody>,
    sealed: Option<Vec<u8>>,
}

/// A tombstone carries no body; the merge still needs a shape. Its fields are
/// the local ones (a delete removes the item, not its values) and its clocks
/// are the local clocks, so no field is reported as changed by the delete.
fn remote_body(local: SyncBody, remote: &RemoteBody) -> SyncBody {
    match &remote.body {
        Some(body) => body.clone(),
        None => SyncBody {
            item: local.item,
            deleted: true,
            clocks: local.clocks,
        },
    }
}

/* -------------------------------------------------------------- baselines ---- */

/// The local item as a sync body, attributed against the acknowledged baseline.
///
/// * No row and no baseline: nothing to send as a body; the caller pushes a
///   tombstone.
/// * No row but a baseline: the item was purged locally; the baseline content
///   becomes a tombstone body for the conflict screen.
/// * A row without a baseline: the whole item is treated as this device's
///   write at `clock` (a first push takes everything).
/// * Both: only the paths whose value differs from the baseline take `clock`.
fn local_body(
    ctx: &SyncContext<'_>,
    item_id: &str,
    clock: &Clock,
    baseline: Option<(&[u8], &Clock)>,
) -> Result<Option<SyncBody>, EngineError> {
    let current = match ctx.store.get(ctx.master, ctx.meta, item_id) {
        Ok(item) => Some(item),
        Err(StoreError::NotFound) => None,
        Err(error) => return Err(error.into()),
    };
    let trashed = match ctx.store.is_trashed(ctx.meta, item_id) {
        Ok(flag) => flag,
        // A purged row is a tombstone in every sense that matters here.
        Err(StoreError::NotFound) => true,
        Err(error) => return Err(error.into()),
    };

    match (current, baseline) {
        (None, None) => Ok(None),
        (None, Some((sealed, sealed_at))) => {
            let mut body = open_body(
                ctx.account_key,
                ctx.account_id,
                item_id,
                sealed_at,
                sealed,
            )?;
            body.deleted = true;
            Ok(Some(body))
        }
        (Some(item), None) => {
            let mut clocks = BTreeMap::new();
            for path in field_paths(&item) {
                clocks.insert(path, clock.clone());
            }
            clocks.insert(DELETED_PATH.to_string(), clock.clone());
            Ok(Some(SyncBody {
                item,
                deleted: trashed,
                clocks,
            }))
        }
        (Some(item), Some((sealed, sealed_at))) => {
            let base = open_body(
                ctx.account_key,
                ctx.account_id,
                item_id,
                sealed_at,
                sealed,
            )?;
            Ok(Some(rebuild_body(&base, &item, trashed, clock)))
        }
    }
}

/// Diff `item` against the acknowledged body and give every changed path the
/// new item clock, keeping the acknowledged clock for the paths that did not
/// move.
fn rebuild_body(base: &SyncBody, item: &Item, trashed: bool, clock: &Clock) -> SyncBody {
    let mut paths = field_paths(item);
    paths.extend(field_paths(&base.item));
    paths.extend(base.clocks.keys().cloned());
    paths.insert(DELETED_PATH.to_string());

    let mut clocks = BTreeMap::new();
    for path in paths {
        let known = base.clocks.get(&path).cloned().unwrap_or_default();
        let changed = match path.as_str() {
            DELETED_PATH => trashed != base.deleted,
            "title" => item.title != base.item.title,
            "category" => item.category != base.item.category,
            "notes" => item.notes != base.item.notes,
            "urls" => item.urls != base.item.urls,
            "tags" => item.tags != base.item.tags,
            "favorite" => item.favorite != base.item.favorite,
            "totp_secret" => item.totp_secret != base.item.totp_secret,
            other => match other.strip_prefix("fields.") {
                Some(field_id) => !fields_equal(field_at(item, field_id), field_at(&base.item, field_id)),
                // A path from a body this build does not know is left alone.
                None => false,
            },
        };
        let path_clock = if changed {
            merge_clocks(&known, clock)
        } else {
            known
        };
        if !path_clock.is_empty() {
            clocks.insert(path, path_clock);
        }
    }

    SyncBody {
        item: item.clone(),
        deleted: trashed,
        clocks,
    }
}

fn field_at<'a>(item: &'a Item, id: &str) -> Option<&'a Field> {
    item.fields.iter().find(|field| field.id == id)
}

fn fields_equal(left: Option<&Field>, right: Option<&Field>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.id == right.id
                && left.label == right.label
                && left.kind == right.kind
                && left.value == right.value
                && left.sensitive == right.sensitive
        }
        _ => false,
    }
}

/* ------------------------------------------------------------------ push ---- */

fn push(ctx: &SyncContext<'_>, pushed: &mut u64) -> Result<bool, EngineError> {
    // Read the dirty set once and push it in 200-operation batches. Re-reading
    // the same ordered window after a batch would let a block of unresolved
    // conflicts at the front starve every item behind them; a snapshot cannot.
    let dirty = ctx.store.sync_dirty(&ctx.meta.vault_uuid, usize::MAX)?;
    let mut changed = false;
    for batch in dirty.chunks(PUSH_LIMIT) {
        let outcome = push_batch(ctx, batch)?;
        *pushed += outcome.applied;
        // `stale` means the server neither applied nor conflicted the push: its
        // stored clock dominates ours, so another round should pull it.
        changed |= outcome.applied > 0 || outcome.merged > 0 || outcome.stale > 0;
    }
    Ok(changed)
}

#[derive(Default)]
struct PushOutcome {
    applied: u64,
    merged: u64,
    stale: u64,
}

struct PendingOp {
    op: PushOp,
    clock: Clock,
    body: Option<SyncBody>,
    /// The sealed bytes exactly as sent, for a live operation.
    sealed: Option<Vec<u8>>,
}

fn push_batch(
    ctx: &SyncContext<'_>,
    batch: &[ItemSyncState],
) -> Result<PushOutcome, EngineError> {
    let mut pending = Vec::with_capacity(batch.len());
    for state in batch {
        let baseline = match (&state.body, &state.body_clock) {
            (Some(sealed), Some(at)) => Some((sealed.as_slice(), at)),
            _ => None,
        };
        let body = local_body(ctx, &state.item_id, &state.clock, baseline)?;
        let (op, sealed) = match &body {
            Some(body) if !body.deleted => {
                let sealed = seal_body(
                    ctx.account_key,
                    ctx.account_id,
                    &state.item_id,
                    &state.clock,
                    body,
                )?;
                let op = PushOp::live(
                    state.item_id.clone(),
                    state.clock.clone(),
                    codec::encode(&sealed),
                );
                (op, Some(sealed))
            }
            // A trashed row still has an item; the wire form is a tombstone and
            // carries no ciphertext. A purged row has no body at all.
            _ => (
                PushOp::tombstone(state.item_id.clone(), state.clock.clone()),
                None,
            ),
        };
        pending.push(PendingOp {
            op,
            clock: state.clock.clone(),
            body,
            sealed,
        });
    }

    let response = ctx.client.push(PushRequest {
        ops: pending.iter().map(|entry| entry.op.clone()).collect(),
    })?;

    let mut outcome = PushOutcome::default();
    let mut settled: HashSet<&str> = HashSet::new();
    for item_id in &response.applied {
        let entry = pending
            .iter()
            .find(|entry| &entry.op.item_id == item_id)
            .ok_or_else(|| {
                EngineError::Payload(format!(
                    "the service applied {item_id}, which was not in the batch"
                ))
            })?;
        // The acknowledged body is the next baseline, so the following push can
        // attribute a local edit to the fields that moved.
        if let Some(sealed) = &entry.sealed {
            ctx.store
                .sync_set_body(&ctx.meta.vault_uuid, item_id, sealed, &entry.clock)?;
        }
        ctx.store
            .sync_mark_clean(&ctx.meta.vault_uuid, item_id, &entry.clock)?;
        settled.insert(entry.op.item_id.as_str());
        outcome.applied += 1;
    }

    for conflict in &response.conflicts {
        let entry = pending
            .iter()
            .find(|entry| entry.op.item_id == conflict.item_id)
            .ok_or_else(|| {
                let item_id = &conflict.item_id;
                EngineError::Payload(format!(
                    "the service reported a conflict for {item_id}, which was not in the batch"
                ))
            })?;
        settled.insert(entry.op.item_id.as_str());
        if merge_push_conflict(ctx, entry, conflict)? {
            outcome.merged += 1;
        }
    }

    let stale = pending
        .iter()
        .filter(|entry| !settled.contains(entry.op.item_id.as_str()))
        .count();
    outcome.stale = u64::try_from(stale).unwrap_or(u64::MAX);
    Ok(outcome)
}

/// The server kept a stored operation concurrent with this push. Merge exactly
/// as the pull path does; the item stays dirty unless the remote side wholly
/// dominated it.
fn merge_push_conflict(
    ctx: &SyncContext<'_>,
    entry: &PendingOp,
    conflict: &Conflict,
) -> Result<bool, EngineError> {
    let remote = open_remote(
        ctx,
        &conflict.item_id,
        conflict.deleted,
        &conflict.ciphertext,
        &conflict.clock,
    )?;

    let local = match (&entry.body, &remote.body) {
        (Some(body), _) => body.clone(),
        (None, Some(body)) => SyncBody {
            item: body.item.clone(),
            deleted: true,
            clocks: BTreeMap::new(),
        },
        (None, None) => {
            // Two content-free tombstones: nothing to merge, but the clock has
            // to dominate both or every later push would conflict again.
            let mut clock = merge_clocks(&entry.clock, &conflict.clock);
            bump(&mut clock, ctx.device_id);
            ctx.store
                .sync_upsert(&ctx.meta.vault_uuid, &conflict.item_id, &clock, true)?;
            return Ok(true);
        }
    };
    let remote_body = remote_body(local.clone(), &remote);

    match merge_bodies(
        &local,
        &entry.clock,
        &remote_body,
        &conflict.clock,
        ctx.device_id,
    ) {
        Merge::Local if local == remote_body => {
            // The server holds exactly this content under this clock: the push
            // it is "conflicting" with is our own earlier push whose response we
            // never saw. Sealing is randomised, so the ciphertexts differ even
            // though the bodies do not — the server cannot see that, and we can.
            // Acknowledge it here or the row stays dirty forever.
            if let Some(sealed) = &entry.sealed {
                ctx.store.sync_set_body(
                    &ctx.meta.vault_uuid,
                    &conflict.item_id,
                    sealed,
                    &entry.clock,
                )?;
            }
            ctx.store.sync_mark_clean(
                &ctx.meta.vault_uuid,
                &conflict.item_id,
                &entry.clock,
            )?;
            Ok(false)
        }
        Merge::Local => {
            // Equal clocks carrying different content: the service refuses to
            // pick a winner, and so does the engine. Store the pair so the user
            // sees it; without the row the item would be pushed forever.
            if local != remote_body {
                store_conflict(
                    ctx,
                    &conflict.item_id,
                    &entry.clock,
                    &conflict.clock,
                    &local,
                    &remote_body,
                )?;
            }
            Ok(false)
        }
        Merge::Remote => {
            adopt_remote(ctx, &conflict.item_id, &remote, &conflict.clock)?;
            Ok(true)
        }
        Merge::Merged { body, clock, conflicts } => {
            if conflicts.is_empty() {
                write_merged(ctx, &body, &clock)?;
                Ok(true)
            } else {
                store_conflict(
                    ctx,
                    &conflict.item_id,
                    &entry.clock,
                    &conflict.clock,
                    &local,
                    &remote_body,
                )?;
                // The row is already dirty; it stays that way until the user
                // resolves the conflict.
                Ok(false)
            }
        }
    }
}

/* --------------------------------------------------------------- writes ---- */

/// Write a merged body and queue it for the next push.
fn write_merged(
    ctx: &SyncContext<'_>,
    body: &SyncBody,
    clock: &Clock,
) -> Result<(), EngineError> {
    let item_id = body.item.id.as_str();
    if body.deleted {
        set_trashed(ctx, item_id, true)?;
    } else {
        ctx.store
            .save_item(ctx.master, ctx.meta, body.item.clone())?;
        set_trashed(ctx, item_id, false)?;
    }
    let sealed = seal_body(
        ctx.account_key,
        ctx.account_id,
        item_id,
        clock,
        body,
    )?;
    ctx.store
        .sync_upsert(&ctx.meta.vault_uuid, item_id, clock, true)?;
    ctx.store
        .sync_set_body(&ctx.meta.vault_uuid, item_id, &sealed, clock)?;
    // The item is settled by a dominating clock, so a row left from an earlier
    // concurrent round no longer describes it.
    ctx.store
        .sync_conflict_clear(&ctx.meta.vault_uuid, item_id)?;
    Ok(())
}

/// Store both sealed bodies for the conflict screen.
#[allow(clippy::too_many_arguments)]
fn store_conflict(
    ctx: &SyncContext<'_>,
    item_id: &str,
    local_clock: &Clock,
    remote_clock: &Clock,
    local: &SyncBody,
    remote: &SyncBody,
) -> Result<(), EngineError> {
    // Both sides are re-sealed here with the clocks stored beside them. Keeping
    // the sender's bytes would be marginally cheaper and would let the row's
    // clock drift from the ciphertext's AAD, which is exactly the bug that makes
    // a conflict unopenable.
    let local_body = seal_body(
        ctx.account_key,
        ctx.account_id,
        item_id,
        local_clock,
        local,
    )?;
    let remote_body = seal_body(
        ctx.account_key,
        ctx.account_id,
        item_id,
        remote_clock,
        remote,
    )?;
    ctx.store
        .sync_conflict_put(&ctx.meta.vault_uuid, &SyncConflictRow {
        item_id: item_id.to_string(),
        local_clock: local_clock.clone(),
        remote_clock: remote_clock.clone(),
        local_body,
        remote_body,
        created_at: now_secs(),
    })?;
    Ok(())
}

fn set_trashed(ctx: &SyncContext<'_>, item_id: &str, trashed: bool) -> Result<(), EngineError> {
    match ctx.store.set_trashed(ctx.meta, item_id, trashed) {
        Ok(()) | Err(StoreError::NotFound) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/* ----------------------------------------------------------------- misc ---- */

fn load_cursor(ctx: &SyncContext<'_>) -> Result<u64, EngineError> {
    match ctx.store.sync_meta_get("cursor")? {
        None => Ok(0),
        Some(text) => text
            .parse::<u64>()
            .map_err(|_| EngineError::Cursor(text)),
    }
}

fn now_secs() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}
