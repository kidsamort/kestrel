//! The conflict surface: what to show the user, and what their answer means.
//!
//! A conflict row stores two sealed bodies and the item clocks they arrived
//! with. This module opens both, names every field whose local and remote
//! clocks are concurrent, and turns a [`ResolveChoice`] into an ordinary local
//! write that the next push settles. Nothing here picks a winner on its own:
//! an unresolved item keeps its local value and stays dirty.

use std::collections::BTreeSet;

use serde::Serialize;

use kestrel_core::store::StoreError;
use kestrel_core::sync::body::open_body;
use kestrel_core::sync::merge::{field_paths, SyncBody, DELETED_PATH};
use kestrel_core::sync::{bump, compare, merge_clocks, Clock, Ordering};

use crate::codec;
use crate::engine::{ensure_account, SyncContext};
use crate::error::EngineError;

/// The suffix a `Both` resolution puts on the duplicate's title. One spelling
/// for the UI and the tests; see [`ResolveChoice::Both`].
const CONFLICT_COPY_SUFFIX: &str = " (conflict copy)";

/// One field both sides changed, rendered as the user has to see it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictField {
    /// The sync path: `title`, `notes`, `deleted`, `fields.<id>`, …
    pub path: String,
    /// Human label: the field's own label, or the path's name.
    pub label: String,
    /// The local value. For a sensitive field the caller masks it; the value is
    /// present because the renderer already holds the unlocked vault.
    pub local: String,
    /// The remote value, rendered the same way.
    pub remote: String,
    /// Whether the caller must mask the value before showing it.
    pub sensitive: bool,
}

/// One unresolved item: both values, who wrote the remote copy and when the
/// local copy last changed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictView {
    /// The item both bodies describe.
    pub item_id: String,
    /// The local item's title, so the screen can name the item without a
    /// second read.
    pub title: String,
    /// `Item::updated_at` of the local body.
    pub local_updated_at: i64,
    /// The device with the highest counter in the remote item clock. That is
    /// the device that wrote the copy being offered as "theirs". Counters can
    /// tie after a merge; the local device is then skipped, because the copy
    /// came from somewhere else, and a stable id order breaks any remaining
    /// tie.
    pub remote_device: String,
    /// The conflicting paths, sorted by path.
    pub fields: Vec<ConflictField>,
}

/// What the user decided for one item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveChoice {
    /// Keep the local item; the remote value is dropped.
    Mine,
    /// Take the remote item; the local value is dropped.
    Theirs,
    /// Keep the local item and save the remote item under a new id, with
    /// [`CONFLICT_COPY_SUFFIX`] appended to its title. A remote tombstone has
    /// no body to copy, so this reduces to [`ResolveChoice::Mine`] for a
    /// delete-versus-edit conflict.
    Both,
}

/// Every unresolved conflict for the vault, in item-id order.
///
/// Both bodies were sealed by this engine under the account key, so opening
/// them proves they belong to this account and item; a tampered row is an
/// [`EngineError::Crypto`] error, never a blank view.
pub fn conflict_views(ctx: &SyncContext<'_>) -> Result<Vec<ConflictView>, EngineError> {
    ensure_account(ctx)?;
    let mut views = Vec::new();
    for row in ctx.store.sync_conflicts(&ctx.meta.vault_uuid)? {
        let local = open_body(
            ctx.account_key,
            ctx.account_id,
            &row.item_id,
            &row.local_clock,
            &row.local_body,
        )?;
        let remote = open_body(
            ctx.account_key,
            ctx.account_id,
            &row.item_id,
            &row.remote_clock,
            &row.remote_body,
        )?;
        views.push(build_view(
            &row.item_id,
            &row.remote_clock,
            ctx.device_id,
            &local,
            &remote,
        ));
    }
    Ok(views)
}

/// Resolve one item's conflict and clear the row.
///
/// The chosen value is written as an ordinary local edit whose item clock
/// dominates both stored clocks, so the next [`crate::sync_once`] pushes a
/// version the server has to accept. `state` becomes `idle` when no conflict
/// is left and stays `conflict` otherwise.
pub fn resolve_conflict(
    ctx: &SyncContext<'_>,
    item_id: &str,
    choice: ResolveChoice,
) -> Result<(), EngineError> {
    ensure_account(ctx)?;
    let row = ctx
        .store
        .sync_conflicts(&ctx.meta.vault_uuid)?
        .into_iter()
        .find(|row| row.item_id == item_id)
        .ok_or_else(|| EngineError::NoConflict(item_id.to_string()))?;
    let local = open_body(
        ctx.account_key,
        ctx.account_id,
        item_id,
        &row.local_clock,
        &row.local_body,
    )?;
    let remote = open_body(
        ctx.account_key,
        ctx.account_id,
        item_id,
        &row.remote_clock,
        &row.remote_body,
    )?;

    // The resolution must dominate both inputs, not just the local clock: a
    // bump of the local clock alone can still be concurrent with the remote
    // one and would leave the server-side conflict in place.
    let mut clock = merge_clocks(&row.local_clock, &row.remote_clock);
    bump(&mut clock, ctx.device_id);

    match choice {
        ResolveChoice::Mine => keep_local(ctx, item_id, &local, &clock)?,
        ResolveChoice::Theirs => take_remote(
            ctx,
            item_id,
            &remote,
            &row.remote_body,
            &row.remote_clock,
            &clock,
        )?,
        ResolveChoice::Both => {
            keep_local(ctx, item_id, &local, &clock)?;
            duplicate_remote(ctx, &remote, &clock)?;
        }
    }

    ctx.store
        .sync_conflict_clear(&ctx.meta.vault_uuid, item_id)?;
    let conflicts = u64::from(ctx.store.sync_counts(&ctx.meta.vault_uuid)?.1);
    ctx.store
        .sync_meta_set("state", if conflicts == 0 { "idle" } else { "conflict" })?;
    ctx.store.sync_meta_remove("error")?;
    Ok(())
}

/* ------------------------------------------------------------------ view ---- */

fn build_view(
    item_id: &str,
    remote_clock: &Clock,
    local_device: &str,
    local: &SyncBody,
    remote: &SyncBody,
) -> ConflictView {
    let mut paths: BTreeSet<String> = local.clocks.keys().cloned().collect();
    paths.extend(remote.clocks.keys().cloned());
    paths.extend(field_paths(&local.item));
    paths.extend(field_paths(&remote.item));
    paths.insert(DELETED_PATH.to_string());

    let mut fields = Vec::new();
    for path in paths {
        let local_path_clock = local.clocks.get(&path).cloned().unwrap_or_default();
        let remote_path_clock = remote.clocks.get(&path).cloned().unwrap_or_default();
        let ordering = compare(&local_path_clock, &remote_path_clock);
        let concurrent = ordering == Ordering::Concurrent;
        let equal = ordering == Ordering::Equal;
        let Some(field) = render(&path, local, remote) else {
            continue;
        };
        // The merge records a tombstone conflict whenever the two flags differ;
        // its own path clocks are not the deciding evidence there. Equal clocks
        // with different values are the anomalous same-version pair the service
        // refuses to settle, and the row must still name them.
        let conflicting = if path == DELETED_PATH {
            local.deleted != remote.deleted || concurrent
        } else {
            concurrent || (equal && field.local != field.remote)
        };
        if conflicting {
            fields.push(field);
        }
    }

    ConflictView {
        item_id: item_id.to_string(),
        title: local.item.title.clone(),
        local_updated_at: local.item.updated_at,
        remote_device: highest_device(remote_clock, local_device),
        fields,
    }
}

fn render(path: &str, local: &SyncBody, remote: &SyncBody) -> Option<ConflictField> {
    let field = |label: &str, local: String, remote: String, sensitive: bool| ConflictField {
        path: path.to_string(),
        label: label.to_string(),
        local,
        remote,
        sensitive,
    };
    let rendered = match path {
        DELETED_PATH => field(
            "Deleted",
            deleted_word(local.deleted).to_string(),
            deleted_word(remote.deleted).to_string(),
            false,
        ),
        "title" => field(
            "Title",
            local.item.title.clone(),
            remote.item.title.clone(),
            false,
        ),
        "category" => field(
            "Category",
            local.item.category.as_str().to_string(),
            remote.item.category.as_str().to_string(),
            false,
        ),
        "notes" => field(
            "Notes",
            local.item.notes.clone(),
            remote.item.notes.clone(),
            false,
        ),
        "urls" => field(
            "URLs",
            local.item.urls.join("\n"),
            remote.item.urls.join("\n"),
            false,
        ),
        "tags" => field(
            "Tags",
            local.item.tags.join("\n"),
            remote.item.tags.join("\n"),
            false,
        ),
        "favorite" => field(
            "Favorite",
            local.item.favorite.to_string(),
            remote.item.favorite.to_string(),
            false,
        ),
        "totp_secret" => field(
            "One-time code secret",
            local.item.totp_secret.clone().unwrap_or_default(),
            remote.item.totp_secret.clone().unwrap_or_default(),
            true,
        ),
        other => {
            let field_id = other.strip_prefix("fields.")?;
            let local_field = field_at(local, field_id);
            let remote_field = field_at(remote, field_id);
            if local_field.is_none() && remote_field.is_none() {
                // The path survives only in a clock: both sides removed the
                // field, so there is nothing to show.
                return None;
            }
            let label = local_field
                .map(|field| field.label.clone())
                .or_else(|| remote_field.map(|field| field.label.clone()))
                .unwrap_or_else(|| field_id.to_string());
            let sensitive = local_field.is_some_and(|field| field.sensitive)
                || remote_field.is_some_and(|field| field.sensitive);
            field(
                &label,
                local_field
                    .map(|field| field.value.clone())
                    .unwrap_or_default(),
                remote_field
                    .map(|field| field.value.clone())
                    .unwrap_or_default(),
                sensitive,
            )
        }
    };
    Some(rendered)
}

fn field_at<'a>(body: &'a SyncBody, field_id: &str) -> Option<&'a kestrel_core::model::Field> {
    body.item.fields.iter().find(|field| field.id == field_id)
}

fn deleted_word(deleted: bool) -> &'static str {
    if deleted {
        "deleted"
    } else {
        "live"
    }
}

/// The device that wrote the remote copy.
///
/// The highest counter wins. Counters tie after a merge, so a tie skips the
/// local device (the copy came from somewhere else) and otherwise falls back to
/// the lexicographically greatest id, which keeps the answer stable.
fn highest_device(clock: &Clock, local_device: &str) -> String {
    let Some(highest) = clock.values().copied().max() else {
        return String::new();
    };
    let mut tied: Vec<&String> = clock
        .iter()
        .filter(|(_, counter)| **counter == highest)
        .map(|(device, _)| device)
        .collect();
    tied.sort();
    tied.iter()
        .rev()
        .find(|device| device.as_str() != local_device)
        .or_else(|| tied.last())
        .map(|device| (*device).clone())
        .unwrap_or_default()
}

/* -------------------------------------------------------------- resolving ---- */

fn keep_local(
    ctx: &SyncContext<'_>,
    item_id: &str,
    local: &SyncBody,
    clock: &Clock,
) -> Result<(), EngineError> {
    match ctx.store.get(ctx.master, ctx.meta, item_id) {
        Ok(_) => {}
        // The row is gone; the local body is the only copy left, so put it
        // back rather than resolving to an item that does not exist.
        Err(StoreError::NotFound) if !local.deleted => {
            ctx.store
                .save_item(ctx.master, ctx.meta, local.item.clone())?;
        }
        Err(StoreError::NotFound) => {}
        Err(error) => return Err(error.into()),
    }
    set_trashed(ctx, item_id, local.deleted)?;
    ctx.store
        .sync_upsert(&ctx.meta.vault_uuid, item_id, clock, true)?;
    Ok(())
}

fn take_remote(
    ctx: &SyncContext<'_>,
    item_id: &str,
    remote: &SyncBody,
    remote_sealed: &[u8],
    remote_clock: &Clock,
    clock: &Clock,
) -> Result<(), EngineError> {
    if remote.deleted {
        set_trashed(ctx, item_id, true)?;
    } else {
        ctx.store
            .save_item(ctx.master, ctx.meta, remote.item.clone())?;
        set_trashed(ctx, item_id, false)?;
    }
    ctx.store
        .sync_upsert(&ctx.meta.vault_uuid, item_id, clock, true)?;
    // The adopted body is the baseline the next push diffs against, tombstone
    // included: otherwise every field would look changed on that push.
    // The bytes are sealed at `remote_clock`; recording them under the
    // resolution clock would make the baseline unopenable on the next push.
    ctx.store
        .sync_set_body(&ctx.meta.vault_uuid, item_id, remote_sealed, remote_clock)?;
    Ok(())
}

fn duplicate_remote(
    ctx: &SyncContext<'_>,
    remote: &SyncBody,
    clock: &Clock,
) -> Result<(), EngineError> {
    if remote.deleted {
        // A tombstone has no item to keep as a second copy.
        return Ok(());
    }
    let mut copy = remote.item.clone();
    copy.id = new_item_id();
    copy.title = format!("{}{CONFLICT_COPY_SUFFIX}", remote.item.title);
    let saved = ctx.store.save_item(ctx.master, ctx.meta, copy)?;
    ctx.store
        .sync_upsert(&ctx.meta.vault_uuid, &saved.id, clock, true)?;
    Ok(())
}

/// A fresh opaque item id. The protocol accepts `[A-Za-z0-9_-]{1,128}` and the
/// vault treats the id as an opaque string, so 16 random bytes rendered as hex
/// are a good id and need no `uuid` dependency.
fn new_item_id() -> String {
    codec::encode(&kestrel_core::crypto::random_bytes::<16>())
}

fn set_trashed(ctx: &SyncContext<'_>, item_id: &str, trashed: bool) -> Result<(), EngineError> {
    match ctx.store.set_trashed(ctx.meta, item_id, trashed) {
        Ok(()) | Err(StoreError::NotFound) => Ok(()),
        Err(error) => Err(error.into()),
    }
}
