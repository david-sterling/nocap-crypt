//! Key length/weakness validation: the checks a cryptanalyst would
//! actually want before trusting a key file.

use nocap_crypt_core::CipherSpec;
use nocap_crypt_entropy::{is_uniform, shannon_entropy};
use thiserror::Error;

/// Conservative floor for key-material Shannon entropy. This is
/// deliberately a low bar, not "near 8.0 bits/byte": naive per-byte
/// Shannon entropy on a 32/64-byte key sample is capped well below 8.0
/// by sample size alone, regardless of randomness quality (see
/// `nocap_crypt_entropy::shannon_entropy_ceiling` — ~5.0/~6.0
/// bits/byte respectively), so real CSPRNG-generated keys typically
/// land around there, not near the maximum. This threshold exists to
/// catch gross mistakes (e.g. an ASCII passphrase copy-pasted in as if
/// it were a raw key), not to certify cryptographic quality —
/// chi-square (`KeyValidationReport::chi_square_uniform_95`) is the
/// more rigorous secondary signal for that, since it actually accounts
/// for sample size.
pub const MIN_KEY_ENTROPY_BITS_PER_BYTE: f64 = 3.0;

#[derive(Debug, Error, PartialEq)]
pub enum KeyValidationError {
    #[error("key length mismatch: cipher {cipher} requires {expected} bytes, got {actual}")]
    LengthMismatch {
        cipher: String,
        expected: usize,
        actual: usize,
    },
    #[error("key is all-zero bytes")]
    AllZero,
    #[error("key entropy too low: {bits_per_byte:.2} bits/byte (minimum {minimum:.2})")]
    LowEntropy { bits_per_byte: f64, minimum: f64 },
    #[error("key bytes repeat with period {period} — looks like a repeating pattern, not random key material")]
    RepeatingPattern { period: usize },
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyValidationReport {
    pub required_bytes: usize,
    pub actual_bytes: usize,
    pub shannon_bits_per_byte: f64,
    pub chi_square_uniform_95: bool,
}

/// Validate `key` against everything `spec` requires: exact length,
/// not all-zero, above the entropy floor, and not a short repeating
/// pattern. Returns the first failure found, in the order a
/// cryptanalyst would want to know about them (structural before
/// statistical).
pub fn validate_key(
    spec: &CipherSpec,
    key: &[u8],
) -> Result<KeyValidationReport, KeyValidationError> {
    let expected = spec.required_key_bytes();
    if key.len() != expected {
        return Err(KeyValidationError::LengthMismatch {
            cipher: spec.as_str(),
            expected,
            actual: key.len(),
        });
    }

    if key.iter().all(|&b| b == 0) {
        return Err(KeyValidationError::AllZero);
    }

    if let Some(period) = detect_repeating_pattern(key) {
        return Err(KeyValidationError::RepeatingPattern { period });
    }

    let bits_per_byte = shannon_entropy(key);
    if bits_per_byte < MIN_KEY_ENTROPY_BITS_PER_BYTE {
        return Err(KeyValidationError::LowEntropy {
            bits_per_byte,
            minimum: MIN_KEY_ENTROPY_BITS_PER_BYTE,
        });
    }

    Ok(KeyValidationReport {
        required_bytes: expected,
        actual_bytes: key.len(),
        shannon_bits_per_byte: bits_per_byte,
        chi_square_uniform_95: is_uniform(key, 1.645),
    })
}

/// Smallest period `p < key.len()` (with `key.len() % p == 0`) such
/// that `key` is exactly `key[..p]` repeated — catches keys built by
/// naively repeating a short pattern to pad length.
fn detect_repeating_pattern(key: &[u8]) -> Option<usize> {
    let n = key.len();
    (1..n)
        .find(|&period| n.is_multiple_of(period) && key.chunks(period).all(|c| c == &key[..period]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nocap_crypt_core::CipherSpec;

    fn xts_spec() -> CipherSpec {
        CipherSpec::parse("aes-xts-plain64").unwrap()
    }

    fn good_key(len: usize) -> Vec<u8> {
        let mut state: u64 = 0x243F6A8885A308D3;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state & 0xFF) as u8
            })
            .collect()
    }

    #[test]
    fn accepts_well_formed_key() {
        let key = good_key(64);
        let report = validate_key(&xts_spec(), &key).unwrap();
        assert_eq!(report.required_bytes, 64);
        assert_eq!(report.actual_bytes, 64);
    }

    #[test]
    fn rejects_wrong_length() {
        let err = validate_key(&xts_spec(), &good_key(32)).unwrap_err();
        assert_eq!(
            err,
            KeyValidationError::LengthMismatch {
                cipher: "aes-xts-plain64".to_string(),
                expected: 64,
                actual: 32
            }
        );
    }

    #[test]
    fn rejects_all_zero_key() {
        let err = validate_key(&xts_spec(), &[0u8; 64]).unwrap_err();
        assert_eq!(err, KeyValidationError::AllZero);
    }

    #[test]
    fn rejects_repeating_pattern_key() {
        let mut key = Vec::new();
        for _ in 0..16 {
            key.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        }
        let err = validate_key(&xts_spec(), &key).unwrap_err();
        assert_eq!(err, KeyValidationError::RepeatingPattern { period: 4 });
    }

    #[test]
    fn rejects_low_entropy_key() {
        // Mostly one byte value with a couple of exceptions — not a
        // clean repeating pattern, but well under the entropy floor.
        let mut key = vec![0x11u8; 64];
        key[0] = 0x22;
        let err = validate_key(&xts_spec(), &key).unwrap_err();
        assert!(matches!(err, KeyValidationError::LowEntropy { .. }));
    }
}
