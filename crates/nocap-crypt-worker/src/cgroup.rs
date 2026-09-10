//! Effective CPU core count under a cgroup CPU quota.
//!
//! `runtime`-level core counts (`std::thread::available_parallelism`)
//! report the *node's* cores, not the pod's CPU limit — inside
//! Kubernetes that badly over-provisions workers. Reading `cpu.max`
//! (cgroup v2) or `cpu.cfs_quota_us`/`cpu.cfs_period_us` (cgroup v1) and
//! computing the effective core count from that is a real correctness
//! concern for exactly the environment this tool runs in.

const CGROUP_V2_CPU_MAX: &str = "/sys/fs/cgroup/cpu.max";
const CGROUP_V1_QUOTA: &str = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us";
const CGROUP_V1_PERIOD: &str = "/sys/fs/cgroup/cpu/cpu.cfs_period_us";

/// Effective core count from cgroup CPU quota, or `None` if no quota
/// is set (`"max"` in v2, `-1` in v1) or neither cgroup interface is
/// readable (not in a container, or a v1/v2 layout this doesn't probe).
/// `pub(crate)`: only `heuristic::effective_core_count` calls this —
/// callers outside the crate should go through that (it adds the
/// non-cgroup fallback), not this raw quota probe directly.
pub(crate) fn effective_quota_cores() -> Option<usize> {
    cgroup_v2_cores().or_else(cgroup_v1_cores)
}

fn cgroup_v2_cores() -> Option<usize> {
    let content = std::fs::read_to_string(CGROUP_V2_CPU_MAX).ok()?;
    parse_cgroup_v2_max(&content)
}

fn cgroup_v1_cores() -> Option<usize> {
    let quota = std::fs::read_to_string(CGROUP_V1_QUOTA).ok()?;
    let period = std::fs::read_to_string(CGROUP_V1_PERIOD).ok()?;
    parse_cgroup_v1(quota.trim(), period.trim())
}

/// Parse `cpu.max` content, e.g. `"200000 100000"` (2.0 effective
/// cores) or `"max 100000"` (no quota, unlimited).
fn parse_cgroup_v2_max(content: &str) -> Option<usize> {
    let mut parts = content.split_whitespace();
    let quota_str = parts.next()?;
    let period: f64 = parts.next()?.parse().ok()?;
    if quota_str == "max" || period <= 0.0 {
        return None;
    }
    let quota: f64 = quota_str.parse().ok()?;
    if quota <= 0.0 {
        return None;
    }
    Some((quota / period).ceil().max(1.0) as usize)
}

/// Parse cgroup v1 `cpu.cfs_quota_us` (`-1` = unlimited) and
/// `cpu.cfs_period_us`.
fn parse_cgroup_v1(quota_str: &str, period_str: &str) -> Option<usize> {
    let quota: i64 = quota_str.parse().ok()?;
    let period: i64 = period_str.parse().ok()?;
    if quota <= 0 || period <= 0 {
        return None;
    }
    Some(((quota as f64 / period as f64).ceil().max(1.0)) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_two_cores() {
        assert_eq!(parse_cgroup_v2_max("200000 100000\n"), Some(2));
    }

    #[test]
    fn v2_unlimited_is_none() {
        assert_eq!(parse_cgroup_v2_max("max 100000\n"), None);
    }

    #[test]
    fn v2_fractional_rounds_up() {
        // 1.5 effective cores -> ceil to 2, matching a "don't
        // under-provision" bias for a fractional quota.
        assert_eq!(parse_cgroup_v2_max("150000 100000\n"), Some(2));
    }

    #[test]
    fn v1_two_cores() {
        assert_eq!(parse_cgroup_v1("200000", "100000"), Some(2));
    }

    #[test]
    fn v1_unlimited_quota_is_none() {
        assert_eq!(parse_cgroup_v1("-1", "100000"), None);
    }

    #[test]
    fn v1_malformed_is_none() {
        assert_eq!(parse_cgroup_v1("not-a-number", "100000"), None);
    }
}
