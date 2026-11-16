//! Pure item-sync logic: version vectors, the field-level merge rule and the
//! sealed body format.
//!
//! Nothing here opens a connection, reads a clock from the wall or contacts the
//! service. The store owns the rows ([`crate::store::sync`]); this module owns
//! the arithmetic the store and the sync engine agree on, so the rule can be
//! tested without a database and audited without a network stack.

pub mod body;
pub mod merge;

use std::collections::BTreeMap;

/// A version vector: `{ device id -> logical counter }`.
///
/// Time is never part of it. A device bumps its own counter on every write, so
/// two copies of an item can be ordered without trusting a system clock.
pub type Clock = BTreeMap<String, u64>;

/// How two clocks relate. Only four answers are possible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ordering {
    /// The same state: every counter is equal, including the absent ones.
    Equal,
    /// The left clock has seen everything the right one has, plus more.
    Dominates,
    /// The right clock has seen everything the left one has, plus more.
    Dominated,
    /// Neither side has seen the other's writes.
    Concurrent,
}

/// Compare two clocks, treating a missing device key as counter zero.
///
/// A counter of zero and a missing key are the same statement ("no write from
/// that device"), which is what lets a removed field keep a clock entry without
/// making the entry itself meaningful.
pub fn compare(a: &Clock, b: &Clock) -> Ordering {
    let mut left_newer = false;
    let mut right_newer = false;
    for (device, &left) in a {
        let right = b.get(device).copied().unwrap_or(0);
        left_newer |= left > right;
        right_newer |= right > left;
    }
    for (device, &right) in b {
        let left = a.get(device).copied().unwrap_or(0);
        left_newer |= left > right;
        right_newer |= right > left;
    }
    match (left_newer, right_newer) {
        (false, false) => Ordering::Equal,
        (true, false) => Ordering::Dominates,
        (false, true) => Ordering::Dominated,
        (true, true) => Ordering::Concurrent,
    }
}

/// Pointwise maximum of two clocks, with zero entries dropped.
///
/// Dropping zeros keeps a merge idempotent: `{"a": 0}` means the same as an
/// absent key, so storing it would only make equality checks noisy.
pub fn merge_clocks(a: &Clock, b: &Clock) -> Clock {
    let mut merged = a.clone();
    for (device, &counter) in b {
        let entry = merged.entry(device.clone()).or_insert(0);
        if *entry < counter {
            *entry = counter;
        }
    }
    merged.retain(|_, counter| *counter != 0);
    merged
}

/// Record a write by `device`: its counter becomes one higher than before.
///
/// A device that has never written starts at one; the caller never has to seed
/// the map.
pub fn bump(clock: &mut Clock, device: &str) {
    let entry = clock.entry(device.to_string()).or_insert(0);
    *entry += 1;
}
