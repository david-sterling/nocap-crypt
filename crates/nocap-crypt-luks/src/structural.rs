//! Structural validation for headerless *plain* dm-crypt volumes — the
//! primary target here (per the architecture plan's open item on LUKS
//! scope: build artifacts in this pipeline are plain64 with no on-disk
//! header, key supplied out-of-band at mount time).

use nocap_crypt_core::{CipherSpec, CipherSpecError, SECTOR_SIZE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralReport {
    pub file_size: u64,
    pub sector_size: u64,
    pub size_is_sector_multiple: bool,
    pub cipher_spec_round_trips: bool,
}

impl StructuralReport {
    pub fn passes(&self) -> bool {
        self.size_is_sector_multiple && self.cipher_spec_round_trips
    }
}

/// Validate that `file_size` and `cipher_spec_str` are consistent with
/// a plain dm-crypt volume: size is a whole number of sectors, and the
/// cipher spec string round-trips through the same parser used
/// elsewhere in this tool (mirroring what `cryptsetup` itself expects).
pub fn validate_plain_structural(file_size: u64, cipher_spec_str: &str) -> StructuralReport {
    let sector_size = SECTOR_SIZE as u64;
    let round_trips = match CipherSpec::parse(cipher_spec_str) {
        Ok(spec) => spec.as_str() == cipher_spec_str,
        Err(_) => false,
    };
    StructuralReport {
        file_size,
        sector_size,
        size_is_sector_multiple: file_size.is_multiple_of(sector_size),
        cipher_spec_round_trips: round_trips,
    }
}

pub fn parse_cipher_spec(spec: &str) -> Result<CipherSpec, CipherSpecError> {
    CipherSpec::parse(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sector_aligned_size_with_known_spec_passes() {
        let report = validate_plain_structural(512 * 10, "aes-xts-plain64");
        assert!(report.passes());
    }

    #[test]
    fn non_sector_aligned_size_fails() {
        let report = validate_plain_structural(513, "aes-xts-plain64");
        assert!(!report.size_is_sector_multiple);
        assert!(!report.passes());
    }

    #[test]
    fn unknown_cipher_spec_fails_round_trip() {
        let report = validate_plain_structural(4096, "aes-gcm-random");
        assert!(!report.cipher_spec_round_trips);
        assert!(!report.passes());
    }
}
