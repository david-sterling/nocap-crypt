//! Key material format detection/parsing: raw binary, hex, or base64.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    Raw,
    Hex,
    Base64,
}

#[derive(Debug, Error)]
pub enum KeyParseError {
    #[error("key material is not valid UTF-8 text, required to decode as {0:?}")]
    NotUtf8(KeyFormat),
    #[error("invalid hex key material: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("invalid base64 key material: {0}")]
    InvalidBase64(#[from] base64::DecodeError),
}

/// Decode `data` according to `format`. For `Hex`/`Base64`, `data` is
/// expected to be the ASCII/UTF-8 text encoding (leading/trailing
/// whitespace is trimmed); for `Raw` it is used verbatim.
pub fn parse_key(data: &[u8], format: KeyFormat) -> Result<Vec<u8>, KeyParseError> {
    match format {
        KeyFormat::Raw => Ok(data.to_vec()),
        KeyFormat::Hex => {
            let text = std::str::from_utf8(data).map_err(|_| KeyParseError::NotUtf8(format))?;
            Ok(hex::decode(text.trim())?)
        }
        KeyFormat::Base64 => {
            let text = std::str::from_utf8(data).map_err(|_| KeyParseError::NotUtf8(format))?;
            Ok(BASE64.decode(text.trim())?)
        }
    }
}

/// Best-effort format auto-detection, used when `--key-format` isn't
/// given explicitly. Not infallible by nature (a raw binary key can
/// coincidentally look like hex/base64 text) — `--key-format` always
/// overrides this.
pub fn detect_format(data: &[u8]) -> KeyFormat {
    if let Ok(text) = std::str::from_utf8(data) {
        let trimmed = text.trim();
        if !trimmed.is_empty()
            && trimmed.len() % 2 == 0
            && trimmed.chars().all(|c| c.is_ascii_hexdigit())
        {
            return KeyFormat::Hex;
        }
        if !trimmed.is_empty() && BASE64.decode(trimmed).is_ok() {
            return KeyFormat::Base64;
        }
    }
    KeyFormat::Raw
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex() {
        let key = parse_key(b"00ff10aa", KeyFormat::Hex).unwrap();
        assert_eq!(key, vec![0x00, 0xff, 0x10, 0xaa]);
    }

    #[test]
    fn parses_hex_with_whitespace() {
        let key = parse_key(b"  00ff10aa\n", KeyFormat::Hex).unwrap();
        assert_eq!(key, vec![0x00, 0xff, 0x10, 0xaa]);
    }

    #[test]
    fn parses_base64() {
        let key = parse_key(b"AP8Qqg==", KeyFormat::Base64).unwrap();
        assert_eq!(key, vec![0x00, 0xff, 0x10, 0xaa]);
    }

    #[test]
    fn parses_raw_verbatim() {
        let bytes = vec![0x00, 0x01, 0xfe, 0xff];
        let key = parse_key(&bytes, KeyFormat::Raw).unwrap();
        assert_eq!(key, bytes);
    }

    #[test]
    fn rejects_invalid_hex() {
        assert!(parse_key(b"not-hex!!", KeyFormat::Hex).is_err());
    }

    #[test]
    fn detects_hex() {
        assert_eq!(detect_format(b"00ff10aa"), KeyFormat::Hex);
    }

    #[test]
    fn detects_raw_for_binary_data() {
        let bytes: Vec<u8> = (0..64u8).collect();
        assert_eq!(detect_format(&bytes), KeyFormat::Raw);
    }
}
