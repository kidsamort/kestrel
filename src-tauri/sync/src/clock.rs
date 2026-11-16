//! Vector clocks.
//!
//! A clock is a map from device id to a per-device logical counter. The entire
//! merge policy is [`relation`]: if one clock dominates the other the newer
//! write wins silently, and if neither dominates the two writes are concurrent
//! and must not be merged by the server. No wall clock takes part in this, which
//! is why a wrong system time anywhere cannot roll a password back.

use std::collections::BTreeMap;

/// Device id to logical counter. `BTreeMap` keeps the JSON encoding canonical
/// (sorted keys) so equal clocks are byte-equal in SQLite.
pub type Clock = BTreeMap<String, u64>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// Every counter is equal.
    Equal,
    /// `left` is strictly newer than `right`.
    Dominates,
    /// `right` is strictly newer than `left`.
    Dominated,
    /// Neither dominates: a genuine concurrent write.
    Concurrent,
}

/// Compares two clocks. Zero counters are ignored, because an omitted counter
/// and a zero counter mean the same thing (nothing written yet).
pub fn relation(left: &Clock, right: &Clock) -> Relation {
    let mut left_advanced = false;
    let mut right_advanced = false;

    for (device, left_counter) in left {
        if *left_counter == 0 {
            continue;
        }
        match right.get(device) {
            Some(right_counter) if left_counter > right_counter => left_advanced = true,
            Some(_) => {}
            None => left_advanced = true,
        }
    }

    for (device, right_counter) in right {
        if *right_counter == 0 {
            continue;
        }
        match left.get(device) {
            Some(left_counter) if right_counter > left_counter => right_advanced = true,
            Some(_) => {}
            None => right_advanced = true,
        }
    }

    match (left_advanced, right_advanced) {
        (false, false) => Relation::Equal,
        (true, false) => Relation::Dominates,
        (false, true) => Relation::Dominated,
        (true, true) => Relation::Concurrent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock(entries: &[(&str, u64)]) -> Clock {
        entries
            .iter()
            .map(|(device, counter)| ((*device).to_string(), *counter))
            .collect()
    }

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn equal_clocks_are_equal() {
        assert_eq!(
            relation(&clock(&[(A, 1)]), &clock(&[(A, 1)])),
            Relation::Equal
        );
    }

    #[test]
    fn a_higher_counter_dominates() {
        assert_eq!(
            relation(&clock(&[(A, 2)]), &clock(&[(A, 1)])),
            Relation::Dominates
        );
        assert_eq!(
            relation(&clock(&[(A, 1)]), &clock(&[(A, 2)])),
            Relation::Dominated
        );
    }

    #[test]
    fn adding_a_device_dominates() {
        assert_eq!(
            relation(&clock(&[(A, 1), (B, 1)]), &clock(&[(A, 1)])),
            Relation::Dominates
        );
    }

    #[test]
    fn one_counter_each_way_is_concurrent() {
        assert_eq!(
            relation(&clock(&[(A, 2), (B, 1)]), &clock(&[(A, 1), (B, 2)])),
            Relation::Concurrent
        );
    }

    #[test]
    fn zero_counters_do_not_count() {
        assert_eq!(
            relation(&clock(&[(A, 1), (B, 0)]), &clock(&[(A, 1)])),
            Relation::Equal
        );
    }
}
