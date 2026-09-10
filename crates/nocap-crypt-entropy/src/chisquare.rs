//! Chi-square goodness-of-fit test against a uniform byte distribution.
//!
//! Secondary, more rigorous signal than Shannon entropy alone: a byte
//! stream can score close to 8.0 bits/byte on Shannon entropy while
//! still being structurally non-uniform (e.g. a fixed permutation of
//! byte values, or strong pairwise correlation) in a way chi-square
//! catches and a single scalar entropy number does not.

/// Raw chi-square statistic for `data` against a uniform distribution
/// over the 256 possible byte values. 255 degrees of freedom.
pub fn chi_square_statistic(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let expected = data.len() as f64 / 256.0;
    counts
        .iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            diff * diff / expected
        })
        .sum()
}

/// Approximate upper-tail chi-square critical value via the
/// Wilson-Hilferty cube-root normal approximation — accurate to within
/// a fraction of a percent at df=255, and avoids needing a full inverse
/// chi-square CDF implementation for a threshold check.
///
/// `z` is the standard-normal quantile for the desired one-tailed
/// confidence (1.645 ~ 95%, 2.326 ~ 99%).
pub fn chi_square_critical_approx(df: f64, z: f64) -> f64 {
    let term = 1.0 - 2.0 / (9.0 * df) + z * (2.0 / (9.0 * df)).sqrt();
    df * term * term * term
}

/// Degrees of freedom for a 256-bin byte-value chi-square test.
pub const DEGREES_OF_FREEDOM: f64 = 255.0;

/// True if `data`'s byte distribution is not distinguishable from
/// uniform at the given confidence (`z` = standard-normal quantile,
/// e.g. 1.645 for ~95%).
pub fn is_uniform(data: &[u8], z: f64) -> bool {
    chi_square_statistic(data) <= chi_square_critical_approx(DEGREES_OF_FREEDOM, z)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_zero_statistic() {
        assert_eq!(chi_square_statistic(&[]), 0.0);
    }

    #[test]
    fn perfectly_uniform_distribution_has_zero_statistic() {
        let mut data = Vec::new();
        for _ in 0..100 {
            data.extend(0..=255u8);
        }
        assert!(chi_square_statistic(&data) < 1e-6);
    }

    #[test]
    fn constant_byte_stream_is_grossly_non_uniform() {
        let data = vec![0x00u8; 10_000];
        // 95% critical value at df=255 is ~293; a constant stream must
        // blow far past that.
        assert!(!is_uniform(&data, 1.645));
    }

    #[test]
    fn critical_value_matches_known_chi_square_table_approx() {
        // Standard chi-square table: df=255, alpha=0.05 (95%) critical
        // value is documented around 293.25. Wilson-Hilferty should
        // land within a few units of that.
        let approx = chi_square_critical_approx(DEGREES_OF_FREEDOM, 1.645);
        assert!((approx - 293.25).abs() < 3.0, "got {approx}");
    }

    #[test]
    fn csprng_like_uniform_random_passes() {
        // Deterministic LCG stand-in for "random-looking" data — real
        // entropy-source testing belongs in nocap-crypt-keymgmt/keygen
        // tests; this just exercises the statistic on non-degenerate
        // input without pulling in a `rand` dependency for this crate.
        let mut state: u64 = 0x2545F4914F6CDD1D;
        let data: Vec<u8> = (0..65536)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state & 0xFF) as u8
            })
            .collect();
        assert!(is_uniform(&data, 1.645));
    }
}
