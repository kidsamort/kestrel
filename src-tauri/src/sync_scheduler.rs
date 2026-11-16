//! The background sync loop: a timer with backoff, and a debounced sync after a
//! write.
//!
//! One thread per process, started once from `setup`. The thread knows nothing
//! about what a sync does; it asks [`crate::commands_sync::run_sync`] to do one
//! and turns the result into the next deadline. The timing policy — the interval,
//! the backoff table, the write debounce — is [`kestrel_engine::Schedule`], and
//! the decisions the loop makes are a plain state machine ([`SchedulerCore`]),
//! so the thread itself has almost nothing to get wrong.
//!
//! # What the loop guarantees
//!
//! * **One run at a time.** [`SchedulerCore`]'s `running` flag is the whole
//!   guard: a run starts only from `poll`, and `poll` refuses while it is set.
//!   A request that lands during a run is kept as the next debounce, so a write
//!   made while a sync was on the wire gets a follow-up run instead of being
//!   folded into a push that may already have read the dirty set.
//! * **No session or store lock is held by this module.** The thread keeps no
//!   store guard and no session guard; `run_sync` takes the vault lock for the
//!   length of one call and drops it before returning. The scheduler lock is
//!   dropped before the run starts, so `request` and `stop` stay callable while
//!   a sync is on the wire.
//! * **A locked vault is not a failure.** The run never reached the network, so
//!   the failure streak is untouched: a locked vault never moves further up the
//!   backoff table, and one with no failures stays on its interval. The loop
//!   keeps trying: one attempt per scheduled tick, each a cheap check of a flag.
//! * **`stop` does not wait out the sleep.** The worker blocks in
//!   [`Condvar::wait_timeout`], never in `thread::sleep`, and the stop flag is
//!   set under the same mutex the waiter holds, so the join returns as soon as
//!   the wait wakes.
//! * **No panic path of its own.** No `unwrap`/`expect`, no indexing, no
//!   `Instant + Duration` (which panics on overflow), and a poisoned scheduler
//!   mutex is recovered instead of propagated.
//!
//! The interval is read from the store on every pass, so the Settings toggle
//! takes effect on the next wake rather than at restart. `sync_set_auto` calls
//! [`request_sync`] after writing the new value.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use kestrel_core::session::VaultState;
use kestrel_engine::Schedule;
use tauri::{AppHandle, Manager};

use crate::commands_sync::{run_sync, KEY_AUTO_INTERVAL};

/// The thread name, so a stack dump says which background loop it is.
const THREAD_NAME: &str = "kestrel-sync-scheduler";

/// A single wait is capped at a day. `Condvar::wait_timeout` is only as portable
/// as the platform's timeout type; a capped wait costs nothing because the armed
/// deadline is unchanged, so the next poll simply sleeps the rest.
const MAX_WAIT: Duration = Duration::from_secs(86_400);

/// The one scheduler in the process. `start` fills it; [`request_sync`] reads it
/// without ever forcing it to exist.
static INSTANCE: OnceLock<Arc<SyncScheduler>> = OnceLock::new();

/// The process-wide sync loop.
pub struct SyncScheduler {
    shared: Arc<Shared>,
    /// `Some` while the worker can still be joined. Taken by `stop`, so a
    /// second stop is a no-op instead of a second join.
    thread: Mutex<Option<JoinHandle<()>>>,
}

/// The state the worker and the callers share.
struct Shared {
    inner: Mutex<Inner>,
    /// Signalled by `request` and `stop`; the worker waits on it with the next
    /// deadline as its timeout.
    wake: Condvar,
}

struct Inner {
    core: SchedulerCore,
    /// Set by `stop` under `inner`. The worker checks it before every wait and
    /// again after every run, so a stop cannot be lost to a wake-up race.
    stop: bool,
}

impl SyncScheduler {
    /// Start the loop and return the process-wide handle.
    ///
    /// Idempotent: the first call spawns the thread, every later call returns
    /// the same handle and ignores its argument. The guarantee is
    /// [`OnceLock::get_or_init`]: the initializer runs at most once, even when
    /// two callers race, so a second window (or a test) can never start a
    /// second worker.
    pub fn start(app: AppHandle) -> &'static SyncScheduler {
        let scheduler = INSTANCE.get_or_init(|| Arc::new(SyncScheduler::spawn(app)));
        scheduler.as_ref()
    }

    /// Ask for a run after the write debounce. Safe from any thread, and a
    /// no-op once the scheduler is stopped.
    pub fn request(&self) {
        let mut inner = lock(&self.shared.inner);
        if inner.stop {
            return;
        }
        inner.core.request(Instant::now());
        // Drop the lock before the notify: the worker only needs the wake, and
        // a request must never wait for a run that is about to start.
        drop(inner);
        self.shared.wake.notify_one();
    }

    /// Stop and join the worker. Idempotent.
    ///
    /// If a run is in flight the join waits for it: the network call cannot be
    /// cancelled and the vault lock belongs to `run_sync` for the length of the
    /// call. Must not be called from the worker thread itself.
    pub fn stop(&self) {
        {
            let mut inner = lock(&self.shared.inner);
            inner.stop = true;
            // Under the lock the waiter already holds, so the flag cannot be
            // set between its predicate check and its wait.
            self.shared.wake.notify_all();
        }
        let handle = lock(&self.thread).take();
        if let Some(handle) = handle {
            // A panic would already have been reported by the thread itself;
            // shutdown is not the place to propagate it.
            if handle.join().is_err() {
                eprintln!("kestrel: the sync scheduler thread panicked");
            }
        }
    }

    fn spawn(app: AppHandle) -> SyncScheduler {
        let shared = Arc::new(Shared {
            inner: Mutex::new(Inner {
                core: SchedulerCore::new(),
                stop: false,
            }),
            wake: Condvar::new(),
        });
        let worker = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name(THREAD_NAME.to_string())
            .spawn(move || run_loop(&app, &worker));
        let thread = match thread {
            Ok(handle) => Some(handle),
            Err(_) => {
                // A thread we cannot start is a scheduling failure, not a
                // reason to take the app down: "Sync now" and the command
                // surface still work, they just do not run on a timer.
                eprintln!("kestrel: the sync scheduler thread could not be started");
                None
            }
        };
        SyncScheduler {
            shared,
            thread: Mutex::new(thread),
        }
    }
}

/// Ask for a debounced run. A no-op when the scheduler was never started, so
/// every write path can call it unconditionally.
pub fn request_sync() {
    if let Some(scheduler) = INSTANCE.get() {
        scheduler.request();
    }
}

/// Stop the background loop at shutdown: the thread is joined and this returns
/// after it has stopped.
///
/// A no-op when the scheduler was never started, and a no-op after a stop:
/// [`SyncScheduler::stop`] takes the join handle out of its mutex, so the
/// thread is joined at most once.
pub fn stop_sync() {
    if let Some(scheduler) = INSTANCE.get() {
        scheduler.stop();
    }
}

/// The worker: poll the state machine, sleep until its deadline or the next
/// wake-up, and run one sync when it says so.
fn run_loop(app: &AppHandle, shared: &Shared) {
    let mut failures: u32 = 0;
    loop {
        // The interval is read **under** the scheduler lock. Reading it first
        // left a window where `sync_set_auto` could write the setting and notify
        // while this thread was between the read and the lock: the notify found
        // no waiter, `poll` saw the stale `0` and dropped the request, and the
        // switch read "on" with nothing running. The store read is a short
        // keyless query, so holding the lock across it costs nothing.
        let mut inner = lock(&shared.inner);
        if inner.stop {
            return;
        }
        let interval = read_interval(app);
        match inner.core.poll(Instant::now(), interval, failures) {
            Action::Idle => {
                // Automatic sync is off. Every wake — a stop, or the settings
                // command's request — is one more pass through `poll`.
                drop(wait(&shared.wake, inner));
            }
            Action::Sleep(delay) => {
                drop(wait_timeout(&shared.wake, inner, delay.min(MAX_WAIT)));
            }
            Action::Run => {
                // The scheduler lock is released before the run: `request` and
                // `stop` must stay callable while a sync is on the wire, and the
                // session lock must belong to `run_sync` alone.
                drop(inner);
                let outcome = match app.try_state::<VaultState>() {
                    Some(state) => run_sync(state.inner()),
                    // `setup` manages the state before it starts this loop, so
                    // this is unreachable in the app. A missing state is a
                    // failure to back off from, never a panic.
                    None => Err("the vault state is not managed".to_string()),
                };
                failures = fold_failure_streak(failures, &outcome);
                // Re-read the interval: a run takes as long as the network
                // does, and the setting may have changed meanwhile.
                let mut inner = lock(&shared.inner);
                if inner.stop {
                    return;
                }
                let interval = read_interval(app);
                inner.core.finish(Instant::now(), interval, failures);
            }
        }
    }
}

/// The configured interval in seconds.
///
/// Absent, `0` or unparsable means automatic sync is off, and so does a store
/// that cannot be read: the next wake reads it again, and running with an
/// interval nobody can state would be a guess.
fn read_interval(app: &AppHandle) -> u64 {
    let Some(state) = app.try_state::<VaultState>() else {
        return 0;
    };
    match state.sync_meta(KEY_AUTO_INTERVAL) {
        Ok(Some(text)) => text.trim().parse::<u64>().unwrap_or(0),
        Ok(None) | Err(_) => 0,
    }
}

/// Fold one run's outcome into the failure streak.
///
/// A locked vault is `Ok` — `run_sync` reports "nothing to do", not a failure —
/// so it clears the streak like any other successful tick. That is deliberate:
/// the streak exists to slow down a *broken service*, and a vault that was
/// simply locked says nothing about the service. Matching on the error text was
/// worse: a `SQLITE_BUSY` ("database is locked") would have been misread as a
/// locked vault and never backed off.
fn fold_failure_streak(current: u32, outcome: &Result<(), String>) -> u32 {
    match outcome {
        Ok(()) => 0,
        Err(_) => current.saturating_add(1),
    }
}

/// What the loop should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Start one run now. The state machine is in `running`; `finish` must be
    /// called when the run returns.
    Run,
    /// Wait this long (or until woken), then poll again.
    Sleep(Duration),
    /// Nothing is scheduled. Wait for a notification.
    Idle,
}

/// The scheduler's state machine, with the clock passed in.
///
/// `idle | pending(deadline) | running` is spelled as four fields because a
/// write-triggered run and the periodic timer are separate deadlines and the
/// earlier one wins:
///
/// * `running` — a run is in flight. `poll` never returns `Run` again until
///   [`SchedulerCore::finish`] clears it. One flag is the entire concurrency
///   guard because only the single worker thread calls `poll`.
/// * `request_at` — a write asked for a run. Its debounce is measured from the
///   latest request, so a burst of saves is one run after the last save.
/// * `deadline` — the periodic run. `armed_interval` remembers which interval
///   produced it, so a new setting re-arms from now instead of waiting out the
///   old interval.
/// * Everything `None` and not running is idle.
#[derive(Debug, Default)]
pub struct SchedulerCore {
    request_at: Option<Instant>,
    deadline: Option<Instant>,
    armed_interval: Option<u64>,
    running: bool,
}

impl SchedulerCore {
    pub fn new() -> SchedulerCore {
        SchedulerCore::default()
    }

    /// A write asked for a sync. The latest request wins, so the debounce is
    /// trailing-edge: the run happens after the burst ends.
    pub fn request(&mut self, now: Instant) {
        self.request_at = Some(now);
    }

    /// Decide what to do at `now`.
    ///
    /// `interval` is the raw setting: `0` means automatic sync is off and is
    /// checked before [`Schedule`] folds a zero to its one-minute default.
    /// `failures` is the current streak, used only when a deadline has to be
    /// armed.
    pub fn poll(&mut self, now: Instant, interval: u64, failures: u32) -> Action {
        if self.running {
            return Action::Idle;
        }
        if interval == 0 {
            // Disabled. A request is dropped, not banked: nothing may sync
            // while the user has automatic sync off, and enabling it later
            // starts from a fresh interval.
            self.request_at = None;
            self.deadline = None;
            self.armed_interval = None;
            return Action::Idle;
        }
        let schedule = Schedule::new(interval);
        if self.armed_interval != Some(interval) {
            self.armed_interval = Some(interval);
            self.deadline = due_at(now, schedule.next_delay(failures));
        }
        let request_due = self
            .request_at
            .and_then(|at| due_at(at, schedule.write_debounce()));
        let next = match (request_due, self.deadline) {
            (Some(request), Some(deadline)) => Some(request.min(deadline)),
            (Some(request), None) => Some(request),
            (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        };
        match next {
            // At or past the earliest deadline: this run also covers every
            // pending request, so both are cleared.
            Some(at) if at <= now => {
                self.request_at = None;
                self.deadline = None;
                self.running = true;
                Action::Run
            }
            Some(at) => Action::Sleep(at.saturating_duration_since(now)),
            // Only reachable if `Instant` could not represent the deadline; see
            // `due_at`. `Idle` waits for a wake instead of spinning.
            None => Action::Idle,
        }
    }

    /// A run finished at `now`. The next automatic run is one interval — or one
    /// backoff — later. A request that arrived during the run keeps its own
    /// arrival time, so if its debounce already passed while the run was on the
    /// wire it runs at the next poll.
    pub fn finish(&mut self, now: Instant, interval: u64, failures: u32) {
        self.running = false;
        if interval == 0 {
            self.deadline = None;
            self.armed_interval = None;
            return;
        }
        self.armed_interval = Some(interval);
        self.deadline = due_at(now, Schedule::new(interval).next_delay(failures));
    }
}

/// `Instant + Duration` panics on overflow. A deadline beyond what an `Instant`
/// can hold (about 584 years) is treated as "never" instead; the loop must have
/// no panic path.
fn due_at(now: Instant, secs: u64) -> Option<Instant> {
    now.checked_add(Duration::from_secs(secs))
}

/// Lock, recovering a poisoned mutex.
///
/// The only values under these locks are a small state machine and a bool; a
/// panic elsewhere cannot leave either half-written. Turning a poisoned lock
/// into a second panic would take the whole background loop down.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn wait<'a, T>(condvar: &Condvar, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
    match condvar.wait(guard) {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn wait_timeout<'a, T>(
    condvar: &Condvar,
    guard: MutexGuard<'a, T>,
    timeout: Duration,
) -> MutexGuard<'a, T> {
    match condvar.wait_timeout(guard, timeout) {
        Ok((guard, _)) => guard,
        Err(poisoned) => poisoned.into_inner().0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERVAL: u64 = 60;

    fn start() -> Instant {
        Instant::now()
    }

    #[test]
    fn a_request_runs_once_after_the_debounce() {
        let mut core = SchedulerCore::new();
        let start = start();
        core.request(start);
        // Nothing runs before the debounce has passed: a burst of saves is one
        // run, not one per save.
        assert_eq!(
            core.poll(start, INTERVAL, 0),
            Action::Sleep(Duration::from_secs(5))
        );
        assert_eq!(
            core.poll(start + Duration::from_secs(5), INTERVAL, 0),
            Action::Run
        );
    }

    #[test]
    fn only_the_latest_request_in_a_burst_matters() {
        let mut core = SchedulerCore::new();
        let start = start();
        core.request(start);
        core.request(start + Duration::from_secs(3));
        // The debounce is measured from the last save, not the first.
        assert_eq!(
            core.poll(start + Duration::from_secs(5), INTERVAL, 0),
            Action::Sleep(Duration::from_secs(3))
        );
        assert_eq!(
            core.poll(start + Duration::from_secs(8), INTERVAL, 0),
            Action::Run
        );
    }

    #[test]
    fn a_request_during_a_run_does_not_start_a_second_run() {
        let mut core = SchedulerCore::new();
        let start = start();
        core.request(start);
        assert_eq!(
            core.poll(start + Duration::from_secs(5), INTERVAL, 0),
            Action::Run
        );
        // A write lands while the first run is in flight: no second run may
        // start, and no matter how often the loop polls.
        core.request(start + Duration::from_secs(6));
        assert_eq!(
            core.poll(start + Duration::from_secs(6), INTERVAL, 0),
            Action::Idle
        );
        assert_eq!(
            core.poll(start + Duration::from_secs(7), INTERVAL, 0),
            Action::Idle
        );
    }

    #[test]
    fn a_write_during_a_run_runs_after_the_run_finishes() {
        let mut core = SchedulerCore::new();
        let start = start();
        core.request(start);
        assert_eq!(
            core.poll(start + Duration::from_secs(5), INTERVAL, 0),
            Action::Run
        );
        core.request(start + Duration::from_secs(6));
        // The first run took longer than the debounce.
        core.finish(start + Duration::from_secs(20), INTERVAL, 0);
        // Still one at a time: the second run starts only now, after the first
        // returned.
        assert_eq!(
            core.poll(start + Duration::from_secs(20), INTERVAL, 0),
            Action::Run
        );
    }

    #[test]
    fn an_idle_loop_sleeps_one_interval_then_runs() {
        let mut core = SchedulerCore::new();
        let start = start();
        assert_eq!(
            core.poll(start, INTERVAL, 0),
            Action::Sleep(Duration::from_secs(60))
        );
        assert_eq!(
            core.poll(start + Duration::from_secs(59), INTERVAL, 0),
            Action::Sleep(Duration::from_secs(1))
        );
        assert_eq!(
            core.poll(start + Duration::from_secs(60), INTERVAL, 0),
            Action::Run
        );
        // While the run is in flight there is nothing to schedule.
        assert_eq!(
            core.poll(start + Duration::from_secs(61), INTERVAL, 0),
            Action::Idle
        );
    }

    #[test]
    fn a_failure_backs_off() {
        let mut core = SchedulerCore::new();
        let start = start();
        core.finish(start, INTERVAL, 1);
        assert_eq!(
            core.poll(start, INTERVAL, 1),
            Action::Sleep(Duration::from_secs(120))
        );
        assert_eq!(
            core.poll(start + Duration::from_secs(119), INTERVAL, 1),
            Action::Sleep(Duration::from_secs(1))
        );
        assert_eq!(
            core.poll(start + Duration::from_secs(120), INTERVAL, 1),
            Action::Run
        );
    }

    #[test]
    fn a_locked_vault_keeps_its_interval() {
        let mut core = SchedulerCore::new();
        let start = start();
        // `run_sync` reports a locked vault as `Ok` (nothing to do), so the
        // streak clears and the next run is on the interval, not a backoff.
        let failures = fold_failure_streak(3, &Ok(()));
        assert_eq!(failures, 0);
        core.finish(start, INTERVAL, failures);
        assert_eq!(
            core.poll(start, INTERVAL, failures),
            Action::Sleep(Duration::from_secs(60))
        );
    }

    #[test]
    fn a_transient_failure_increments_the_streak() {
        let mut core = SchedulerCore::new();
        let start = start();
        let failures = fold_failure_streak(2, &Err("connection refused".to_string()));
        assert_eq!(failures, 3);
        core.finish(start, INTERVAL, failures);
        // Three failures from a one-minute interval: 60 * 2^3, still under the
        // half-hour ceiling.
        assert_eq!(
            core.poll(start, INTERVAL, failures),
            Action::Sleep(Duration::from_secs(480))
        );
    }

    #[test]
    fn a_success_clears_the_streak() {
        assert_eq!(fold_failure_streak(4, &Ok(())), 0);
    }

    #[test]
    fn a_disabled_schedule_does_nothing() {
        let mut core = SchedulerCore::new();
        let start = start();
        core.request(start);
        assert_eq!(
            core.poll(start + Duration::from_secs(5), 0, 0),
            Action::Idle
        );
        // The request is not banked: nothing syncs while automatic sync is off.
        assert_eq!(
            core.poll(start + Duration::from_secs(6), 0, 0),
            Action::Idle
        );
    }

    #[test]
    fn a_new_interval_rearms_from_now() {
        let mut core = SchedulerCore::new();
        let start = start();
        assert_eq!(
            core.poll(start, 60, 0),
            Action::Sleep(Duration::from_secs(60))
        );
        // The settings command wrote a new interval; the loop learns it on its
        // next pass and must not sit out the old one.
        assert_eq!(
            core.poll(start + Duration::from_secs(60), 120, 0),
            Action::Sleep(Duration::from_secs(120))
        );
    }
}
