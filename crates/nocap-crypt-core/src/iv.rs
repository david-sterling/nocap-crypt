//! `plain64` IV derivation.
//!
//! dm-crypt's `plain64` IV mode sets the IV to the (512-byte-granular)
//! sector number, encoded as a little-endian u64, zero-padded to the
//! cipher block size (16 bytes for AES). This is the single highest-risk
//! correctness point in the whole project: any deviation here produces
//! ciphertext that looks plausible but silently fails to mount under
//! real dm-crypt.

/// IV sector granularity for `plain64`, fixed at 512 bytes regardless of
/// the underlying block/alignment size used for file sizing.
pub const IV_SECTOR_SIZE: u64 = 512;

/// Derive the 16-byte AES-block IV for `plain64` given a 512-byte sector
/// index (i.e. `byte_offset / 512`, not a 4096-byte block index).
pub fn plain64_iv(sector_512: u64) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&sector_512.to_le_bytes());
    iv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sector_zero_is_all_zero_iv() {
        assert_eq!(plain64_iv(0), [0u8; 16]);
    }

    #[test]
    fn sector_one_is_little_endian_one() {
        let mut expected = [0u8; 16];
        expected[0] = 1;
        assert_eq!(plain64_iv(1), expected);
    }

    #[test]
    fn sector_4096_matches_known_answer() {
        // sector 4096 = 0x1000 -> LE bytes: byte[1] = 0x10, all others 0.
        let iv = plain64_iv(4096);
        let mut expected = [0u8; 16];
        expected[..8].copy_from_slice(&4096u64.to_le_bytes());
        assert_eq!(iv, expected);
        assert_eq!(iv[1], 0x10);
    }

    #[test]
    fn high_sector_number_does_not_overflow_into_upper_half() {
        // u64::MAX sector: all first 8 bytes 0xff, upper 8 bytes must stay zero.
        let iv = plain64_iv(u64::MAX);
        assert_eq!(&iv[..8], &[0xff; 8]);
        assert_eq!(&iv[8..], &[0u8; 8]);
    }

}
