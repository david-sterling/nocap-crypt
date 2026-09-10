//! LUKS1/2 header detection.
//!
//! Full header parsing is intentionally out of scope for the initial
//! implementation — see Rust Architecture Plan §9 open item 3: the
//! actual target volumes for this tool are headerless `plain64` (key
//! supplied out-of-band at mount time), not LUKS1/2. This module only
//! detects *presence* of a LUKS header, which is enough for
//! `validate`/`inspect` to branch between "parse the header" (future
//! work, currently reported as unsupported) and "structural plain
//! validation" (`structural.rs`, fully implemented).

const LUKS_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LuksVersion {
    V1,
    V2,
}

/// Inspect the first bytes of a volume for the LUKS magic + version
/// field. Returns `None` for a headerless (plain dm-crypt) volume.
pub fn detect_luks_header(data: &[u8]) -> Option<LuksVersion> {
    if data.len() < 8 || &data[..6] != LUKS_MAGIC {
        return None;
    }
    match u16::from_be_bytes([data[6], data[7]]) {
        1 => Some(LuksVersion::V1),
        2 => Some(LuksVersion::V2),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_magic_is_headerless() {
        assert_eq!(detect_luks_header(&[0u8; 32]), None);
    }

    #[test]
    fn too_short_is_headerless() {
        assert_eq!(detect_luks_header(b"LUKS"), None);
    }

    #[test]
    fn detects_luks1_magic() {
        let mut data = vec![0u8; 32];
        data[..6].copy_from_slice(LUKS_MAGIC);
        data[6..8].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(detect_luks_header(&data), Some(LuksVersion::V1));
    }

    #[test]
    fn detects_luks2_magic() {
        let mut data = vec![0u8; 32];
        data[..6].copy_from_slice(LUKS_MAGIC);
        data[6..8].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(detect_luks_header(&data), Some(LuksVersion::V2));
    }
}
