//! When the background loop runs, and how long it waits after a failure.
//!
//! The loop itself lives in the desktop shell (`src-tauri/src/sync_scheduler.rs`)
//! because it needs the app handle and the command layer. Everything that can be
//! decided without a thread, a clock or a store is here, so the policy is tested
//! without sleeping.
//!
//! Two rules:
//!
//! * An idle vault syncs on a fixed interval. A failed run backs off — double
//!   the interval once, then ten, fifteen and thirty minutes — so a service that
//!   is down (or a laptop that is offline) costs one request per half hour
//!   instead of one per interval.
//! * A local write asks for a run after a short debounce, so a burst of saves is
//!   one run. The debounce is derived from the interval and never exceeds five
//!   seconds.
//!
//! `interval_secs = 0` means "automatic sync is off" to the loop. For the
//! arithmetic here it is folded to the one-minute default, so no caller has to
//! guard a zero-second wait: a zero delay is a busy loop, not a schedule.

/// The interval a configured zero is folded to. One minute is the smallest
/// interval the settings command accepts.
const DEFAULT_INTERVAL_SECS: u64 = 60;

/// The longest a failing service is left alone between attempts.
const BACKOFF_CAP_SECS: u64 = 1_800;

/// A burst of saves must feel free, so the debounce is short. It is still at
/// least a second: a run per keystroke would be worse than no automatic sync.
const DEBOUNCE_MAX_SECS: u64 = 5;

/// How often an idle vault syncs, and how a failing service backs off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    /// The configured interval, before the zero-is-one-minute fold.
    pub interval_secs: u64,
}

impl Schedule {
    pub fn new(interval_secs: u64) -> Schedule {
        Schedule { interval_secs }
    }

    /// The interval actually used: a configured zero is the one-minute default.
    pub fn interval(&self) -> u64 {
        if self.interval_secs == 0 {
            DEFAULT_INTERVAL_SECS
        } else {
            self.interval_secs
        }
    }

    /// Seconds to wait before the next run, given how many consecutive runs
    /// failed. Never zero.
    pub fn next_delay(&self, consecutive_failures: u32) -> u64 {
        if consecutive_failures == 0 {
            return self.interval();
        }
        // Backing off means "less often", never "more often": with a one-hour
        // interval, a fixed five-minute first retry would poll a failing service
        // twelve times as often as a healthy one. The exponential is capped at
        // the backoff ceiling and then floored at the configured interval.
        //
        // Saturating: the store holds a `u64` and nothing here may overflow on
        // a value written by an older or hand-edited database.
        let doubled = self
            .interval()
            .saturating_mul(1u64 << consecutive_failures.min(6));
        doubled.min(BACKOFF_CAP_SECS).max(self.interval())
    }

    /// The debounce for a write-triggered sync: several saves in a row are one
    /// run. Never zero and never longer than five seconds.
    pub fn write_debounce(&self) -> u64 {
        (self.interval() / 2).min(DEBOUNCE_MAX_SECS).max(1)
    }
}

/// Seconds to wait before the next run, given how many consecutive runs failed.
///
/// 0 failures → `interval_secs`; otherwise `min(interval * 2^failures, 1800)`
/// floored at `interval_secs`, so a failing service is never polled more often
/// than a healthy one. A configured zero is the one-minute default, and the
/// delay is never zero.
pub fn next_delay(interval_secs: u64, consecutive_failures: u32) -> u64 {
    Schedule::new(interval_secs).next_delay(consecutive_failures)
}

/// The debounce for a write-triggered sync: several saves in a row are one run.
/// `min(5, interval/2).max(1)`, with a configured zero folded to one minute.
pub fn write_debounce_secs(interval_secs: u64) -> u64 {
    Schedule::new(interval_secs).write_debounce()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idle_vault_syncs_on_its_interval() {
        assert_eq!(next_delay(60, 0), 60);
        assert_eq!(next_delay(300, 0), 300);
        assert_eq!(next_delay(86_400, 0), 86_400);
    }

    #[test]
    fn failures_double_and_never_retry_sooner_than_the_interval() {
        // Doubling from the configured interval, capped at half an hour.
        assert_eq!(next_delay(60, 1), 120);
        assert_eq!(next_delay(60, 2), 240);
        assert_eq!(next_delay(60, 3), 480);
        assert_eq!(next_delay(60, 4), 960);
        assert_eq!(next_delay(60, 5), 1_800);
        assert_eq!(next_delay(10, 1), 20);

        // A long interval is never shortened by a failure: "every hour" plus one
        // failure is still an hour, not five minutes.
        assert_eq!(next_delay(600, 1), 1_200);
        assert_eq!(next_delay(600, 2), 1_800);
        assert_eq!(next_delay(3_600, 1), 3_600);
        assert_eq!(next_delay(3_600, 9), 3_600);
        assert_eq!(next_delay(300, 3), 1_800);
    }

    #[test]
    fn a_very_long_failure_streak_is_clamped() {
        assert_eq!(next_delay(60, u32::MAX), 1_800);
        assert_eq!(next_delay(3_600, 10_000), 3_600);
        // Doubling a huge interval must not overflow.
        assert_eq!(next_delay(u64::MAX, 1), u64::MAX);
    }

    #[test]
    fn a_zero_interval_is_the_one_minute_default() {
        assert_eq!(Schedule::new(0).interval(), 60);
        assert_eq!(next_delay(0, 0), 60);
        assert_eq!(next_delay(0, 1), 120);
        assert_eq!(next_delay(0, 2), 240);
        assert_eq!(write_debounce_secs(0), 5);
    }

    #[test]
    fn a_delay_is_never_zero() {
        for interval in [0, 1, 2, 60, 3_600, u64::MAX] {
            for failures in 0..8 {
                assert!(
                    next_delay(interval, failures) > 0,
                    "interval {interval}, failures {failures}"
                );
            }
        }
    }

    #[test]
    fn the_write_debounce_is_short_and_never_zero() {
        assert_eq!(write_debounce_secs(0), 5);
        assert_eq!(write_debounce_secs(1), 1);
        assert_eq!(write_debounce_secs(2), 1);
        assert_eq!(write_debounce_secs(8), 4);
        assert_eq!(write_debounce_secs(10), 5);
        assert_eq!(write_debounce_secs(60), 5);
        assert_eq!(write_debounce_secs(86_400), 5);
        // The table and the struct must stay one policy, not two.
        for interval in [0, 1, 2, 8, 60, 86_400] {
            let schedule = Schedule::new(interval);
            assert_eq!(schedule.write_debounce(), write_debounce_secs(interval));
            assert_eq!(schedule.next_delay(1), next_delay(interval, 1));
        }
    }
}
