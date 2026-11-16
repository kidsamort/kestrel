//! Field-level merge of two copies of one item.
//!
//! The merge is logical, never temporal: item-level clocks decide whether one
//! side wholly dominates the other, and only a genuinely concurrent pair is
//! walked field by field. A field both sides changed is never guessed at — it
//! keeps the local value and is named in the conflict list, so the caller can
//! show "mine vs theirs" and ask. Timestamps are cosmetic and never consulted.
//!
//! Deletion is a field path (`"deleted"`) with its own clock, but the design
//! rule is stronger than plain last-writer-wins: a tombstone applies only when
//! it dominates the *item*. Inside the concurrent branch a differing tombstone
//! state is therefore always a conflict, never a silent delete — losing a
//! password to a merge rule is not recoverable.

use super::{bump, compare, merge_clocks, Clock, Ordering};
use crate::model::{Field, Item};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The path in [`SyncBody::clocks`] that carries the tombstone flag.
pub const DELETED_PATH: &str = "deleted";

/// One item as it travels over sync: the item body, its tombstone flag and the
/// clock of the last write that set each field path.
///
/// `item` is the vault's own [`Item`], so a merged body can be sealed (or
/// stored) without a second conversion. `clocks` is keyed by field path:
/// `title`, `category`, `notes`, `urls`, `tags`, `favorite`, `totp_secret`,
/// `deleted`, and `fields.<field.id>` for every field.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncBody {
    /// The item itself, exactly as the vault stores it.
    pub item: Item,
    /// Tombstone marker. A deleted body is kept only for the conflict screen;
    /// it is never offered as a live item.
    pub deleted: bool,
    /// Field path -> clock of the write that last set that path.
    pub clocks: BTreeMap<String, Clock>,
}

/// Structural equality for a sync body: item fields, tombstone flag and clocks.
///
/// [`Item`] and [`Field`] do not derive `PartialEq` in the vault crate, so the
/// comparison is spelled out here. Order inside `fields` is significant because
/// the editor renders fields in that order.
impl PartialEq for SyncBody {
    fn eq(&self, other: &Self) -> bool {
        self.deleted == other.deleted
            && self.clocks == other.clocks
            && same_item(&self.item, &other.item)
    }
}

/// Every field path of an item, without the tombstone path.
///
/// The scalar paths are always present (an empty value is still a value), and
/// every field contributes `fields.<id>`. A field that was removed keeps its
/// clock in [`SyncBody::clocks`] but is no longer listed here; the merge unions
/// both sources so the removal is not forgotten.
pub fn field_paths(item: &Item) -> BTreeSet<String> {
    let mut paths: BTreeSet<String> = [
        "title",
        "category",
        "notes",
        "urls",
        "tags",
        "favorite",
        "totp_secret",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    for field in &item.fields {
        paths.insert(format!("fields.{}", field.id));
    }
    paths
}

/// The outcome of merging two copies of an item.
// `Merged` carries the whole body; this is a one-shot result value, not a
// collection element, and boxing it would force a dereference on every caller.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum Merge {
    /// The local copy dominates (or is identical): nothing to write.
    Local,
    /// The remote copy dominates: adopt it wholesale.
    Remote,
    /// The copies are concurrent and were merged field by field.
    Merged {
        /// The merged body, with per-path clocks.
        body: SyncBody,
        /// The merged item-level clock, bumped for the merging device.
        clock: Clock,
        /// Paths both sides changed concurrently, sorted by path.
        conflicts: Vec<String>,
    },
}

/// Merge `remote` into `local` for the given device.
///
/// `local_clock` and `remote_clock` are the item-level vectors that travelled
/// beside each body. An item-level domination wins outright; otherwise the
/// union of both bodies' clock keys and both items' current field paths is
/// merged path by path. The returned [`Merge::Merged::clock`] always dominates
/// both inputs and carries a fresh counter for `device`, so pushing it settles
/// the server-side conflict.
///
/// Precondition: both bodies describe the same item (`item.id`), which the
/// caller guarantees by loading both sides for one id.
pub fn merge_bodies(
    local: &SyncBody,
    local_clock: &Clock,
    remote: &SyncBody,
    remote_clock: &Clock,
    device: &str,
) -> Merge {
    match compare(local_clock, remote_clock) {
        Ordering::Dominates | Ordering::Equal => Merge::Local,
        Ordering::Dominated => Merge::Remote,
        Ordering::Concurrent => merge_concurrent(local, remote, local_clock, remote_clock, device),
    }
}

fn merge_concurrent(
    local: &SyncBody,
    remote: &SyncBody,
    local_clock: &Clock,
    remote_clock: &Clock,
    device: &str,
) -> Merge {
    let mut body = SyncBody {
        item: local.item.clone(),
        deleted: local.deleted,
        clocks: BTreeMap::new(),
    };
    let mut conflicts = Vec::new();

    // Both bodies' clock keys matter even when the corresponding value is
    // gone: a removal is a clock with no value, and dropping it would let the
    // other side's stale copy come back on the next pull.
    let mut paths = field_paths(&local.item);
    paths.extend(field_paths(&remote.item));
    paths.extend(local.clocks.keys().cloned());
    paths.extend(remote.clocks.keys().cloned());
    paths.insert(DELETED_PATH.to_string());

    let mut field_updates: BTreeMap<String, Option<Field>> = BTreeMap::new();

    for path in &paths {
        let local_path_clock = local.clocks.get(path).cloned().unwrap_or_default();
        let remote_path_clock = remote.clocks.get(path).cloned().unwrap_or_default();
        let ordering = compare(&local_path_clock, &remote_path_clock);
        let mut path_clock = merge_clocks(&local_path_clock, &remote_path_clock);

        if path == DELETED_PATH {
            // A concurrent tombstone/edit is a conflict even if the tombstone's
            // own clock dominates: item-level concurrency means the other side
            // made an edit the deleter never saw. Keep the local flag (the
            // caller surfaces both bodies) and record the path.
            if local.deleted != remote.deleted {
                conflicts.push(path.clone());
            }
        } else if let Some(field_id) = path.strip_prefix("fields.") {
            let local_field = local.item.fields.iter().find(|f| f.id == field_id);
            let remote_field = remote.item.fields.iter().find(|f| f.id == field_id);
            let chosen = match ordering {
                Ordering::Dominates | Ordering::Equal => local_field.cloned(),
                Ordering::Dominated => remote_field.cloned(),
                Ordering::Concurrent => {
                    conflicts.push(path.clone());
                    local_field.cloned()
                }
            };
            if !same_field(local_field, chosen.as_ref()) {
                bump(&mut path_clock, device);
            }
            field_updates.insert(field_id.to_string(), chosen);
        } else {
            let take_remote = matches!(ordering, Ordering::Dominated);
            if matches!(ordering, Ordering::Concurrent) {
                conflicts.push(path.clone());
            }
            let changed = apply_scalar(&mut body.item, &remote.item, path, take_remote)
                && scalar_changed(path, &local.item, &body.item);
            if changed {
                bump(&mut path_clock, device);
            }
        }

        if !path_clock.is_empty() {
            body.clocks.insert(path.clone(), path_clock);
        }
    }

    body.item.fields = merge_fields(&local.item, &remote.item, &field_updates);
    // Cosmetic only: the merge never orders anything by this value. Taking the
    // later of the two keeps the UI's "changed recently" honest.
    body.item.updated_at = local.item.updated_at.max(remote.item.updated_at);

    let mut clock = merge_clocks(local_clock, remote_clock);
    bump(&mut clock, device);
    Merge::Merged {
        body,
        clock,
        conflicts,
    }
}

/// Apply a scalar field from the remote item when the remote path clock won.
/// Returns `false` for an unknown path, which has no value to apply.
fn apply_scalar(merged: &mut Item, remote: &Item, path: &str, take_remote: bool) -> bool {
    match path {
        "title" => {
            if take_remote {
                merged.title = remote.title.clone();
            }
        }
        "category" => {
            if take_remote {
                merged.category = remote.category;
            }
        }
        "notes" => {
            if take_remote {
                merged.notes = remote.notes.clone();
            }
        }
        "urls" => {
            if take_remote {
                merged.urls = remote.urls.clone();
            }
        }
        "tags" => {
            if take_remote {
                merged.tags = remote.tags.clone();
            }
        }
        "favorite" => {
            if take_remote {
                merged.favorite = remote.favorite;
            }
        }
        "totp_secret" => {
            if take_remote {
                merged.totp_secret = remote.totp_secret.clone();
            }
        }
        _ => return false,
    }
    true
}

/// Whether the scalar at `path` differs between the pre-merge local item and
/// the merged item. Only called for paths [`apply_scalar`] recognises.
fn scalar_changed(path: &str, local: &Item, merged: &Item) -> bool {
    match path {
        "title" => local.title != merged.title,
        "category" => local.category != merged.category,
        "notes" => local.notes != merged.notes,
        "urls" => local.urls != merged.urls,
        "tags" => local.tags != merged.tags,
        "favorite" => local.favorite != merged.favorite,
        "totp_secret" => local.totp_secret != merged.totp_secret,
        _ => false,
    }
}

/// Assemble the merged field list: local order first, then fields the remote
/// side introduced. A field whose chosen value is `None` is removed, which is
/// how a dominating removal (or never having seen the field) is represented.
fn merge_fields(
    local: &Item,
    remote: &Item,
    updates: &BTreeMap<String, Option<Field>>,
) -> Vec<Field> {
    let mut fields = Vec::with_capacity(local.fields.len() + remote.fields.len());
    for field in &local.fields {
        if let Some(Some(chosen)) = updates.get(&field.id) {
            fields.push(chosen.clone());
        }
    }
    for field in &remote.fields {
        let known = local.fields.iter().any(|f| f.id == field.id);
        if !known {
            if let Some(Some(chosen)) = updates.get(&field.id) {
                fields.push(chosen.clone());
            }
        }
    }
    fields
}

fn same_item(a: &Item, b: &Item) -> bool {
    a.id == b.id
        && a.title == b.title
        && a.category == b.category
        && a.notes == b.notes
        && a.urls == b.urls
        && a.tags == b.tags
        && a.favorite == b.favorite
        && a.totp_secret == b.totp_secret
        && a.created_at == b.created_at
        && a.updated_at == b.updated_at
        && a.fields.len() == b.fields.len()
        && a.fields
            .iter()
            .zip(&b.fields)
            .all(|(left, right)| same_field(Some(left), Some(right)))
}

fn same_field(a: Option<&Field>, b: Option<&Field>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.id == b.id
                && a.label == b.label
                && a.kind == b.kind
                && a.value == b.value
                && a.sensitive == b.sensitive
        }
        _ => false,
    }
}
