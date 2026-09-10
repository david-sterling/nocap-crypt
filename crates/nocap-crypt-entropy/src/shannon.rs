//! Shannon entropy (bits/byte, range 0.0-8.0) over a byte slice.

/// Shannon entropy in bits per byte. Empty input is defined as 0.0
/// (there is no information to measure).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// The highest value [`shannon_entropy`] can possibly return for a
/// `len`-byte sample, regardless of how random the source is. With
/// only `len` draws, the empirical byte-value histogram can occupy at
/// most `min(len, 256)` distinct bins, and entropy over a histogram is
/// bounded by `log2` of the bin count — so this is a hard ceiling from
/// sample size alone, not a randomness-quality bound.
///
/// This matters most at key-material lengths (32/64 bytes): a real
/// CSPRNG-generated 64-byte key typically scores ~5.5-6.0 bits/byte
/// under [`shannon_entropy`], nowhere near the 8.0 maximum, purely
/// because 64 draws can't fill out 256 possible byte values. That is
/// not evidence of a weak RNG — [`crate::is_uniform`] (chi-square) is
/// the test that actually accounts for sample size and should be
/// trusted over a raw bits/byte number at this length.
pub fn shannon_entropy_ceiling(len: usize) -> f64 {
    if len == 0 {
        0.0
    } else {
        (len.min(256) as f64).log2()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn all_same_byte_is_zero_entropy() {
        let data = vec![0x42u8; 1024];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn uniform_256_byte_alphabet_is_max_entropy() {
        let data: Vec<u8> = (0..=255u8).collect();
        let entropy = shannon_entropy(&data);
        assert!((entropy - 8.0).abs() < 1e-9);
    }

    #[test]
    fn two_symbols_equal_frequency_is_one_bit() {
        let mut data = vec![0u8; 500];
        data.extend(vec![1u8; 500]);
        let entropy = shannon_entropy(&data);
        assert!((entropy - 1.0).abs() < 1e-9);
    }

    #[test]
    fn ceiling_is_zero_for_empty_input() {
        assert_eq!(shannon_entropy_ceiling(0), 0.0);
    }

    #[test]
    fn ceiling_matches_log2_of_sample_length_below_256() {
        // 64-byte key: capped at log2(64) = 6.0, not 8.0.
        assert!((shannon_entropy_ceiling(64) - 6.0).abs() < 1e-9);
        // 32-byte key: capped at log2(32) = 5.0.
        assert!((shannon_entropy_ceiling(32) - 5.0).abs() < 1e-9);
    }

    #[test]
    fn ceiling_saturates_at_8_bits_once_sample_reaches_256_bytes() {
        assert_eq!(shannon_entropy_ceiling(256), 8.0);
        assert_eq!(shannon_entropy_ceiling(4096), 8.0);
    }

    #[test]
    fn no_real_sample_can_exceed_its_own_ceiling() {
        // Best case for entropy: every byte value distinct. Even then,
        // shannon_entropy must not exceed the ceiling for that length.
        let data: Vec<u8> = (0..64u16).map(|i| (i % 256) as u8).collect();
        assert!(shannon_entropy(&data) <= shannon_entropy_ceiling(data.len()) + 1e-9);
    }
}
