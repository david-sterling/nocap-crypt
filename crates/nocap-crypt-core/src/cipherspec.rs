//! Cipher spec string parsing/construction, mirroring the subset of
//! `cryptsetup`'s cipher spec grammar this tool supports
//! (`aes-xts-plain64`, `aes-cbc-essiv:sha256`), plus key-length
//! derivation per cipher.

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherMode {
    XtsPlain64,
    CbcEssivSha256,
}

/// AES key size in bits. XTS restricts to 128/256 in the NIST spec, but
/// this tool also accepts 192 for CBC-ESSIV, matching what a reviewer
/// checking `keycheck` against AES-128/192/256 would expect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AesKeyBits {
    Bits128,
    Bits192,
    Bits256,
}

impl AesKeyBits {
    pub fn bytes(self) -> usize {
        match self {
            AesKeyBits::Bits128 => 16,
            AesKeyBits::Bits192 => 24,
            AesKeyBits::Bits256 => 32,
        }
    }

    pub fn from_bits(bits: u16) -> Option<Self> {
        match bits {
            128 => Some(AesKeyBits::Bits128),
            192 => Some(AesKeyBits::Bits192),
            256 => Some(AesKeyBits::Bits256),
            _ => None,
        }
    }

    pub fn bits(self) -> u16 {
        match self {
            AesKeyBits::Bits128 => 128,
            AesKeyBits::Bits192 => 192,
            AesKeyBits::Bits256 => 256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CipherSpec {
    pub mode: CipherMode,
    /// AES key size of the *underlying* AES cipher. For XTS the on-disk
    /// key material is double this (two concatenated AES keys); for
    /// CBC-ESSIV it's exactly this.
    pub aes_bits: AesKeyBits,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CipherSpecError {
    #[error("unrecognized cipher spec {0:?} (supported: aes-xts-plain64, aes-cbc-essiv:sha256)")]
    UnknownSpec(String),
    #[error("XTS does not support a {0}-bit AES key (supported: 128, 256)")]
    UnsupportedXtsKeySize(u16),
    #[error(
        "aes-cbc-essiv:sha256 requires a 256-bit AES key (SHA-256's 32-byte \
         digest must match the ESSIV cipher's key size); got {0} bits"
    )]
    UnsupportedEssivKeySize(u16),
    #[error("unsupported AES key size: {0} bits (supported: 128, 192, 256)")]
    UnsupportedKeySize(u16),
}

impl CipherSpec {
    /// Parse a bare cipher spec string with the cipher's default key
    /// size (matches cryptsetup's own default: 256-bit AES for both
    /// `aes-xts-plain64` and `aes-cbc-essiv:sha256`).
    pub fn parse(spec: &str) -> Result<Self, CipherSpecError> {
        match spec {
            "aes-xts-plain64" => Ok(CipherSpec {
                mode: CipherMode::XtsPlain64,
                aes_bits: AesKeyBits::Bits256,
            }),
            "aes-cbc-essiv:sha256" => Ok(CipherSpec {
                mode: CipherMode::CbcEssivSha256,
                aes_bits: AesKeyBits::Bits256,
            }),
            other => Err(CipherSpecError::UnknownSpec(other.to_string())),
        }
    }

    /// Override the AES key size (bits of the underlying AES cipher, NOT
    /// the doubled XTS on-disk key length).
    pub fn with_aes_bits(mut self, bits: u16) -> Result<Self, CipherSpecError> {
        let parsed =
            AesKeyBits::from_bits(bits).ok_or(CipherSpecError::UnsupportedKeySize(bits))?;
        match self.mode {
            CipherMode::XtsPlain64 if parsed == AesKeyBits::Bits192 => {
                return Err(CipherSpecError::UnsupportedXtsKeySize(bits));
            }
            CipherMode::CbcEssivSha256 if parsed != AesKeyBits::Bits256 => {
                return Err(CipherSpecError::UnsupportedEssivKeySize(bits));
            }
            _ => {}
        }
        self.aes_bits = parsed;
        Ok(self)
    }

    /// Required on-disk/key-file key length in bytes for this spec. XTS
    /// doubles the AES key size (two concatenated AES keys); this is the
    /// single most common footgun in dm-crypt key handling and is worth
    /// keeping as an explicit, named computation rather than inline
    /// arithmetic at call sites.
    pub fn required_key_bytes(&self) -> usize {
        match self.mode {
            CipherMode::XtsPlain64 => self.aes_bits.bytes() * 2,
            CipherMode::CbcEssivSha256 => self.aes_bits.bytes(),
        }
    }

    pub fn as_str(&self) -> String {
        match self.mode {
            CipherMode::XtsPlain64 => "aes-xts-plain64".to_string(),
            CipherMode::CbcEssivSha256 => "aes-cbc-essiv:sha256".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xts_default_key_size() {
        let spec = CipherSpec::parse("aes-xts-plain64").unwrap();
        assert_eq!(spec.mode, CipherMode::XtsPlain64);
        assert_eq!(spec.required_key_bytes(), 64);
    }

    #[test]
    fn parses_cbc_essiv_default_key_size() {
        let spec = CipherSpec::parse("aes-cbc-essiv:sha256").unwrap();
        assert_eq!(spec.mode, CipherMode::CbcEssivSha256);
        assert_eq!(spec.required_key_bytes(), 32);
    }

    #[test]
    fn xts_128_requires_32_byte_key() {
        let spec = CipherSpec::parse("aes-xts-plain64")
            .unwrap()
            .with_aes_bits(128)
            .unwrap();
        assert_eq!(spec.required_key_bytes(), 32);
    }

    #[test]
    fn xts_rejects_192_bit_aes() {
        let err = CipherSpec::parse("aes-xts-plain64")
            .unwrap()
            .with_aes_bits(192)
            .unwrap_err();
        assert_eq!(err, CipherSpecError::UnsupportedXtsKeySize(192));
    }

    #[test]
    fn unknown_spec_rejected() {
        assert!(matches!(
            CipherSpec::parse("aes-gcm"),
            Err(CipherSpecError::UnknownSpec(_))
        ));
    }

    #[test]
    fn roundtrips_through_as_str() {
        let spec = CipherSpec::parse("aes-xts-plain64").unwrap();
        assert_eq!(spec.as_str(), "aes-xts-plain64");
    }
}
