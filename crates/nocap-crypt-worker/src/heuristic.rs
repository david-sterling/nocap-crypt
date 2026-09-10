//! System introspection: cores (cgroup-aware), disk type, and the
//! fixed chunk-dispatch size. `DispatchInfo`/`compute()` are purely
//! informational (verbose/didactic output, explicit-override/
//! small-file-bypass decisions callers make themselves) — as of the
//! dm-crypt-modeled concurrency redesign (see `concurrency.rs`), they
//! no longer pick a worker count. `effective_core_count()` on its own
//! is the exception: `nocap-crypt-cli`'s `run()` calls it once at
//! startup to size rayon's global pool (see that call site), so the
//! `Concurrency::GlobalPool` default actually binds to the cgroup CPU
//! quota rather than the host's raw core count.

use std::path::Path;

use crate::cgroup::effective_quota_cores;
use crate::diskinfo::{disk_type_for_path, DiskType};

/// I/O/chunk-dispatch size in bytes — a throughput choice, deliberately
/// a separate constant from the 512-byte `plain64` IV sector size
/// (`nocap_crypt_core::SECTOR_SIZE`) even though both are powers of two.
/// Never derive one from the other. Settled, no further tuning needed
/// on this axis. Private: callers only ever need the derived
/// `DispatchInfo::chunk_sectors`, never this raw byte count.
const CHUNK_DISPATCH_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchInfo {
    pub effective_cores: usize,
    pub disk_type: DiskType,
    pub chunk_sectors: u64,
}

/// Effective logical core count: cgroup quota if resolvable, else the
/// process's own view of available parallelism. Plain
/// `available_parallelism()` reports the *node's* cores, not a
/// container's CPU limit — badly over-provisioning inside Kubernetes —
/// so cgroup quota takes priority when readable.
pub fn effective_core_count() -> usize {
    effective_quota_cores().unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    })
}

/// Gather system info relevant to `path`'s storage. An "auto" decision
/// that can't be inspected isn't trustworthy in a CI pipeline, so
/// verbose/didactic output should print all of this, even though (per
/// the concurrency redesign) it no longer drives the default worker
/// count.
pub fn compute(path: &Path) -> DispatchInfo {
    DispatchInfo {
        effective_cores: effective_core_count(),
        disk_type: disk_type_for_path(path),
        chunk_sectors: (CHUNK_DISPATCH_BYTES / nocap_crypt_core::SECTOR_SIZE) as u64,
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
    fn chunk_sectors_matches_fixed_4096_byte_dispatch() {
        let info = compute(&dummy_path());
        assert_eq!(info.chunk_sectors, 8); // 4096 / 512
    }

    #[test]
    fn effective_core_count_is_at_least_one() {
        assert!(effective_core_count() >= 1);
    }
}
