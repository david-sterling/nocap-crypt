//! Sector-range dispatch: dm-crypt-modeled concurrency (see
//! `concurrency.rs`), cgroup/core/disk system introspection for
//! reporting, and the `rayon`-backed dispatch that turns the serial
//! `nocap-crypt-core` engine into concurrent sector-range encryption.

pub mod cgroup;
pub mod concurrency;
pub mod diskinfo;
pub mod dispatch;
pub mod heuristic;

pub use concurrency::{
    resolve as resolve_concurrency, Concurrency, DEFAULT_SMALL_FILE_THRESHOLD_BYTES,
};
pub use diskinfo::{disk_type_for_path, DiskType};
pub use dispatch::{chunk_ranges, process_ranges, SectorRange};
pub use heuristic::{compute as compute_system_info, effective_core_count, DispatchInfo};
