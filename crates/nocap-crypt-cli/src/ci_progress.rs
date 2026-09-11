//! `--ci` mode's replacement for `LiveProgress`: periodic single-line
//! progress reports instead of an in-place-redrawing `indicatif` bar —
//! a CI log viewer that doesn't interpret `\r` cursor movement shows
//! every redraw tick as its own line, which is exactly what `--ci`
//! output must avoid.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use nocap_crypt_ui::{Event, Reporter};

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const IDLE_FALLBACK: Duration = Duration::from_secs(30);

/// Poll `counter` and emit an `Event::Progress` line via `reporter`
/// every time a 25% threshold is crossed, plus a time-based fallback
/// so a slow operation with uneven progress doesn't go silent for
/// long stretches. Blocks until `is_finished()` returns true — call
/// this from the same thread that's waiting on a
/// `std::thread::scope`-spawned worker (see `cmd::image::run_encrypt`
/// for the pattern), not from a detached background thread, so it
/// never needs the `Reporter` to be `'static`/shared via `Arc`.
///
/// `is_finished()` is checked *after* sampling the counter each
/// iteration, not before: a worker that finishes before this thread's
/// very first poll (routine for any small/fast operation — thread
/// spawn and scheduling can easily outlast a tiny synchronous
/// encrypt) must still get its final state reported, or `--ci` mode
/// emits zero `Event::Progress` lines — not even the closing 100%
/// one — for that run.
pub fn run(
    reporter: &dyn Reporter,
    counter: &AtomicU64,
    total_bytes: u64,
    is_finished: impl Fn() -> bool,
) {
    if total_bytes == 0 {
        return;
    }

    let start = Instant::now();
    let mut last_threshold = 0u64;
    let mut last_report = Instant::now();

    loop {
        let finished = is_finished();
        let done = counter.load(Ordering::Relaxed).min(total_bytes);
        let percent = (done as f64 / total_bytes as f64) * 100.0;
        let threshold = ((percent / 25.0) as u64) * 25;
        let idle_too_long = last_report.elapsed() >= IDLE_FALLBACK;

        if finished || threshold > last_threshold || (idle_too_long && done > 0) {
            let elapsed = start.elapsed().as_secs_f64();
            let bytes_per_sec = if elapsed > 0.0 {
                Some(done as f64 / elapsed / (1024.0 * 1024.0))
            } else {
                None
            };
            reporter.report(Event::Progress {
                percent,
                bytes_per_sec,
                elapsed_secs: elapsed,
            });
            last_threshold = last_threshold.max(threshold);
            last_report = Instant::now();
        }

        if finished {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::Mutex;

    struct RecordingReporter {
        events: Mutex<Vec<Event>>,
    }

    impl Reporter for RecordingReporter {
        fn report(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[test]
    fn zero_total_bytes_reports_nothing_and_returns_immediately() {
        let reporter = RecordingReporter {
            events: Mutex::new(Vec::new()),
        };
        let counter = AtomicU64::new(0);
        run(&reporter, &counter, 0, || true);
        assert!(reporter.events.lock().unwrap().is_empty());
    }

    #[test]
    fn reports_at_least_once_for_a_completed_operation() {
        let reporter = RecordingReporter {
            events: Mutex::new(Vec::new()),
        };
        let counter = AtomicU64::new(1000);
        // is_finished() is false on the first check (so the loop body
        // runs and observes the counter's already-complete state at
        // least once), true afterward.
        let first_check = Cell::new(true);
        run(&reporter, &counter, 1000, || {
            if first_check.get() {
                first_check.set(false);
                false
            } else {
                true
            }
        });
        // The first poll should have recorded a Progress event, since
        // threshold (100%) > last_threshold (0).
        let events = reporter.events.lock().unwrap();
        assert!(!events.is_empty());
        assert!(matches!(events[0], Event::Progress { .. }));
    }

    /// Regression test for a real bug: `is_finished()` used to be
    /// checked before the counter was ever sampled, so a worker that
    /// was already finished on the very first poll (the common case
    /// for any fast operation) produced zero `Event::Progress` lines.
    #[test]
    fn already_finished_on_first_check_still_reports_final_state() {
        let reporter = RecordingReporter {
            events: Mutex::new(Vec::new()),
        };
        let counter = AtomicU64::new(1000);
        run(&reporter, &counter, 1000, || true);
        let events = reporter.events.lock().unwrap();
        assert_eq!(
            events.len(),
            1,
            "must report exactly once, even when already finished on entry"
        );
        assert!(matches!(events[0], Event::Progress { percent, .. } if percent == 100.0));
    }
}
