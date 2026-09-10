//! Disk rotational-flag lookup, used by the worker heuristic to cap
//! parallelism on spinning disks (parallel random-offset writes cause
//! seek thrashing) vs let it run wide on SSD/NVMe.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskType {
    /// `/sys/block/<dev>/queue/rotational` == 0
    Ssd,
    /// `/sys/block/<dev>/queue/rotational` == 1
    Rotational,
    /// Not resolvable — overlay/tmpfs/network volume in a container is
    /// the common case here; callers should fall back to a
    /// core-count-only default and say so explicitly rather than
    /// pretending confidence this doesn't have.
    Unknown,
}

pub fn disk_type_for_path(path: &Path) -> DiskType {
    platform::disk_type_for_path(path)
}

/// `sda1` -> `sda`, `nvme0n1p3` -> `nvme0n1`, `mmcblk0p2` -> `mmcblk0`,
/// `sda` -> `sda` (already a whole-disk name).
///
/// Only reachable from the Linux `platform::resolve_block_device` path;
/// `#[allow(dead_code)]` because non-Linux release builds otherwise
/// never call it (tests exercise it directly on every platform).
#[allow(dead_code)]
fn base_device_name(name: &str) -> String {
    if let Some(pos) = name.rfind('p') {
        let (head, tail) = (&name[..pos], &name[pos + 1..]);
        if head.ends_with(|c: char| c.is_ascii_digit())
            && !tail.is_empty()
            && tail.chars().all(|c| c.is_ascii_digit())
        {
            return head.to_string();
        }
    }
    // NVMe/mmc/loop whole-disk names end in a digit even with no
    // partition (e.g. `nvme0n1`) — only SATA/virtio-style names
    // (`sda1`) append the partition digit directly with no separator,
    // so trailing-digit stripping must not apply to the former.
    if name.starts_with("nvme") || name.starts_with("mmcblk") || name.starts_with("loop") {
        return name.to_string();
    }
    name.trim_end_matches(|c: char| c.is_ascii_digit()).to_string()
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{base_device_name, DiskType};
    use std::fs;
    use std::path::Path;

    pub fn disk_type_for_path(path: &Path) -> DiskType {
        resolve_block_device(path)
            .and_then(|dev| read_rotational(&dev))
            .unwrap_or(DiskType::Unknown)
    }

    fn resolve_block_device(path: &Path) -> Option<String> {
        let canonical = fs::canonicalize(path).ok()?;
        let canonical = canonical.to_str()?;
        let mounts = fs::read_to_string("/proc/mounts").ok()?;

        let mut best: Option<(usize, String)> = None;
        for line in mounts.lines() {
            let mut parts = line.split_whitespace();
            let device = parts.next()?;
            let mount_point = parts.next()?;
            if canonical.starts_with(mount_point)
                && best.as_ref().is_none_or(|(len, _)| mount_point.len() > *len)
            {
                best = Some((mount_point.len(), device.to_string()));
            }
        }

        let (_, device) = best?;
        let name = device.strip_prefix("/dev/")?;
        Some(base_device_name(name))
    }

    fn read_rotational(dev_name: &str) -> Option<DiskType> {
        let content = fs::read_to_string(format!("/sys/block/{dev_name}/queue/rotational")).ok()?;
        match content.trim() {
            "0" => Some(DiskType::Ssd),
            "1" => Some(DiskType::Rotational),
            _ => None,
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::DiskType;
    use std::path::Path;

    pub fn disk_type_for_path(_path: &Path) -> DiskType {
        DiskType::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_device_name_strips_sata_partition() {
        assert_eq!(base_device_name("sda1"), "sda");
        assert_eq!(base_device_name("sda"), "sda");
    }

    #[test]
    fn base_device_name_strips_nvme_partition() {
        assert_eq!(base_device_name("nvme0n1p3"), "nvme0n1");
        assert_eq!(base_device_name("nvme0n1"), "nvme0n1");
    }

    #[test]
    fn base_device_name_strips_mmc_partition() {
        assert_eq!(base_device_name("mmcblk0p2"), "mmcblk0");
    }

    #[test]
    fn unresolvable_path_is_unknown_on_this_platform_or_gracefully_handled() {
        // On non-Linux this is always Unknown; on Linux, a bogus path
        // won't resolve to a real mount either.
        let ty = disk_type_for_path(Path::new("/definitely/not/a/real/path/xyz"));
        assert_eq!(ty, DiskType::Unknown);
    }
}
