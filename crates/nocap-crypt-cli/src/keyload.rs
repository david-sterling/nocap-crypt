//! Shared key-file loading + cipher-spec resolution, used by every
//! subcommand that touches key material.

use std::path::Path;

use clap::ValueEnum;
use nocap_crypt_core::{CipherSpec, CipherSpecError};
use nocap_crypt_keymgmt::{detect_format, parse_key, KeyFormat, KeyParseError};

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum KeyFormatArg {
    Auto,
    Raw,
    Hex,
    Base64,
}

/// The exact two cipher spec strings `nocap_crypt_core::CipherSpec::parse`
/// accepts — surfaced as a `ValueEnum` purely for shell tab-completion
/// (see `specs/bash-autocompletion-plan.md` §3.2). No loss of
/// correctness versus the old bare `String`: this was already the
/// complete accepted set at runtime, just invisible to the shell.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherArg {
    #[value(name = "aes-xts-plain64")]
    AesXtsPlain64,
    #[value(name = "aes-cbc-essiv:sha256")]
    AesCbcEssivSha256,
}

impl CipherArg {
    pub fn as_str(self) -> &'static str {
        match self {
            CipherArg::AesXtsPlain64 => "aes-xts-plain64",
            CipherArg::AesCbcEssivSha256 => "aes-cbc-essiv:sha256",
        }
    }
}

impl KeyFormatArg {
    fn resolve(self, data: &[u8]) -> KeyFormat {
        match self {
            KeyFormatArg::Auto => detect_format(data),
            KeyFormatArg::Raw => KeyFormat::Raw,
            KeyFormatArg::Hex => KeyFormat::Hex,
            KeyFormatArg::Base64 => KeyFormat::Base64,
        }
    }
}

#[derive(Debug)]
pub enum KeyLoadError {
    Io(std::io::Error),
    Parse(KeyParseError),
}

impl std::fmt::Display for KeyLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyLoadError::Io(e) => write!(f, "reading key file: {e}"),
            KeyLoadError::Parse(e) => write!(f, "parsing key material: {e}"),
        }
    }
}

pub fn load_key_file(path: &Path, format: KeyFormatArg) -> Result<Vec<u8>, KeyLoadError> {
    let raw = std::fs::read(path).map_err(KeyLoadError::Io)?;
    let fmt = format.resolve(&raw);
    parse_key(&raw, fmt).map_err(KeyLoadError::Parse)
}

/// Resolve `cipher` and, if `key_size_bits` is given, override the AES
/// key size (XTS doubles this for the on-disk key length — see
/// `nocap_crypt_core::CipherSpec::required_key_bytes`). `CipherSpec::parse`
/// can't actually fail here (the `ValueEnum` already restricts `cipher`
/// to a string it accepts) but stays in the call path unchanged rather
/// than being bypassed, so this is still the single place cipher-spec
/// string parsing happens.
pub fn resolve_cipher_spec(
    cipher: CipherArg,
    key_size_bits: Option<u16>,
) -> Result<CipherSpec, CipherSpecError> {
    let spec = CipherSpec::parse(cipher.as_str())?;
    match key_size_bits {
        Some(bits) => spec.with_aes_bits(bits),
        None => Ok(spec),
    }
}
