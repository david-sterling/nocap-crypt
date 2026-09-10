//! Key representation for logging: grouped hex, and a non-reversible
//! fingerprint so two runs can be confirmed to use the "same key"
//! without ever logging the key itself. Full key material is only ever
//! surfaced by an explicit, separate `--reveal` call site — nothing in
//! this module prints unredacted key bytes by default.

use sha2::{Digest, Sha256};

/// Hex-encode `key`, grouped into 4-byte (8 hex char) blocks separated
/// by spaces, for human-readable `--reveal` output.
pub fn hex_grouped(key: &[u8]) -> String {
    key.chunks(4)
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Non-reversible fingerprint: first 8 hex chars (4 bytes) of
/// SHA-256(key). Safe to log by default — cannot be inverted back to
/// the key, but two runs using the same key produce the same
/// fingerprint.
pub fn fingerprint(key: &[u8]) -> String {
    let digest = Sha256::digest(key);
    hex::encode(&digest[..4])
}

/// The default, safe-to-log representation: length + fingerprint, never
/// the key bytes themselves.
pub fn redacted(key: &[u8]) -> String {
    format!("<{} bytes, fingerprint {}>", key.len(), fingerprint(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_grouped_groups_by_four_bytes() {
        let key = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(hex_grouped(&key), "00112233 4455");
    }

    #[test]
    fn fingerprint_is_eight_hex_chars() {
        let fp = fingerprint(b"some key material");
        assert_eq!(fp.len(), 8);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let key = vec![0x42u8; 32];
        assert_eq!(fingerprint(&key), fingerprint(&key));
    }

    #[test]
    fn fingerprint_differs_for_different_keys() {
        assert_ne!(fingerprint(&[0u8; 32]), fingerprint(&[1u8; 32]));
    }

    #[test]
    fn redacted_never_contains_raw_key_hex() {
        let key = vec![0xABu8; 32];
        let redacted = redacted(&key);
        assert!(!redacted.contains(&hex_grouped(&key)));
    }
}
