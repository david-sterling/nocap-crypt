//! Concurrency mode selection, modeled directly on dm-crypt's own
//! design rather than invented from scratch (see Rust Architecture
//! Plan §4):
//!
//! - **Default is `GlobalPool`**: dm-crypt's default is an *unbound
//!   kernel workqueue* that auto-balances across whichever CPUs are
//!   free, not a static pre-picked count. Rayon's global pool
//!   (work-stealing, no per-operation static commitment) is the direct
//!   analogue — so the default is to dispatch onto *one* pool used for
//!   every operation, not a hand-rolled per-operation cores/disk sizing
//!   heuristic. Unlike a kernel workqueue, though, an unconfigured
//!   rayon pool doesn't know about a container's cgroup CPU quota on
//!   its own — `nocap-crypt-cli::run()` closes that gap by building
//!   the global pool once, at startup, sized to
//!   `heuristic::effective_core_count()`, so this dispatch code stays a
//!   plain, unmodified `par_iter()` while the pool it runs on is still
//!   quota-aware.
//! - **`Synchronous` is the small-file/pin-to-submission-thread
//!   bypass**: dm-crypt has had `no_read_workqueue`/`no_write_workqueue`
//!   since kernel 5.9 to skip workqueue dispatch entirely on fast
//!   devices, where dispatch overhead can exceed the crypto cost —
//!   real kernel precedent for skipping the pool below
//!   `--small-file-threshold`, and for `--pin-to-submission-thread`
//!   (mirrors dm-crypt's `samecpucrypt`), which forces this path
//!   unconditionally for reproducible single-threaded benchmarking.
//! - **`Fixed(n)` is the explicit `--max-workers` override**: dm-crypt
//!   treats its own tunables as opt-in deviations from the
//!   auto-balanced default, not the normal path.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Concurrency {
    /// No rayon pool at all — process every range on the calling
    /// thread. Small-file bypass or `--pin-to-submission-thread`.
    Synchronous,
    /// Rayon's ambient global pool, unmodified. The default.
    GlobalPool,
    /// A scoped pool pinned to exactly `usize` threads. Explicit
    /// `--max-workers` override.
    Fixed(usize),
}

/// Default small-file bypass threshold: below this, thread-pool
/// spin-up cost plausibly outweighs the parallelism benefit for the
/// image sizes actually in scope for this tool (~150MB) once hardware
/// AES is engaged — confirm with `bench` rather than trusting the
/// assumption, but default to the conservative bypass until proven
/// otherwise.
pub const DEFAULT_SMALL_FILE_THRESHOLD_BYTES: u64 = 256 * 1024 * 1024;

/// Resolve which concurrency mode applies. `path` is accepted for
/// signature symmetry with the rest of this crate's disk-aware
/// functions but isn't consulted here — disk type no longer feeds the
/// worker-count decision (see module docs); it remains available via
/// `heuristic::compute` for reporting.
pub fn resolve(
    file_size: u64,
    _path: &Path,
    small_file_threshold: u64,
    pin_to_submission_thread: bool,
    max_workers_override: Option<usize>,
) -> Concurrency {
    if pin_to_submission_thread || file_size < small_file_threshold {
        return Concurrency::Synchronous;
    }
    match max_workers_override {
        Some(n) => Concurrency::Fixed(n.max(1)),
        None => Concurrency::GlobalPool,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dummy_path() -> PathBuf {
        std::env::temp_dir()
    }

    #[test]
    fn small_file_is_synchronous_even_with_override() {
        let mode = resolve(
            1024,
            &dummy_path(),
            DEFAULT_SMALL_FILE_THRESHOLD_BYTES,
            false,
            Some(8),
        );
        assert_eq!(mode, Concurrency::Synchronous);
    }

    #[test]
    fn pin_to_submission_thread_forces_synchronous_on_large_file() {
        let mode = resolve(
            DEFAULT_SMALL_FILE_THRESHOLD_BYTES * 10,
            &dummy_path(),
            DEFAULT_SMALL_FILE_THRESHOLD_BYTES,
            true,
            None,
        );
        assert_eq!(mode, Concurrency::Synchronous);
    }

    #[test]
    fn large_file_no_override_uses_global_pool() {
        let mode = resolve(
            DEFAULT_SMALL_FILE_THRESHOLD_BYTES * 10,
            &dummy_path(),
            DEFAULT_SMALL_FILE_THRESHOLD_BYTES,
            false,
            None,
        );
        assert_eq!(mode, Concurrency::GlobalPool);
    }

    #[test]
    fn large_file_with_override_uses_fixed() {
        let mode = resolve(
            DEFAULT_SMALL_FILE_THRESHOLD_BYTES * 10,
            &dummy_path(),
            DEFAULT_SMALL_FILE_THRESHOLD_BYTES,
            false,
            Some(6),
        );
        assert_eq!(mode, Concurrency::Fixed(6));
    }

    #[test]
    fn zero_override_is_clamped_to_one() {
        let mode = resolve(
            DEFAULT_SMALL_FILE_THRESHOLD_BYTES * 10,
            &dummy_path(),
            DEFAULT_SMALL_FILE_THRESHOLD_BYTES,
            false,
            Some(0),
        );
        assert_eq!(mode, Concurrency::Fixed(1));
    }
}
