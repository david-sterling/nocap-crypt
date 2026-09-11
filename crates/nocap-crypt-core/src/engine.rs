//! Sector-by-sector `plain64`-compatible encryption engine.
//!
//! Operates on in-memory buffers keyed to an absolute 512-byte sector
//! index (`nocap-crypt-blockio` owns the actual file I/O and hands buffers
//! here). Any sector range can be encrypted/decrypted independently since
//! `plain64` has no chaining between sectors, which is what makes
//! sector-range parallelism in `nocap-crypt-worker` safe.

use aes::{Aes128, Aes192, Aes256};
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use sha2::{Digest, Sha256};
use xts_mode::Xts128;

use crate::cipher::KeyError;
use crate::cipherspec::{AesKeyBits, CipherMode, CipherSpec};
use crate::iv::{plain64_iv, IV_SECTOR_SIZE};

/// IV/tweak granularity, fixed by the `plain64` convention. Deliberately
/// a distinct constant from any I/O chunk-dispatch size used upstream
/// (worker/blockio) — the two must never be derived from each other even
/// though both happen to be powers of two.
pub const SECTOR_SIZE: usize = IV_SECTOR_SIZE as usize;

// Boxing the largest variant would save ~250 bytes on a struct built
// once per encrypt/decrypt invocation, not per-sector or in a hot
// loop — not worth the match-site indirection it'd add throughout
// this file.
#[allow(clippy::large_enum_variant)]
pub enum XtsVariant {
    Aes128(Xts128<Aes128>),
    Aes192(Xts128<Aes192>),
    Aes256(Xts128<Aes256>),
}

// Only AES-256 is reachable: `CipherSpec::with_aes_bits` rejects any
// other size for `CbcEssivSha256` because the SHA-256 digest used to key
// the ESSIV salt cipher is fixed at 32 bytes (see cipherspec.rs).
pub enum CbcEssivVariant {
    Aes256 { main: Aes256, essiv: Aes256 },
}

/// A keyed, ready-to-use cipher for one of the supported dm-crypt cipher
/// specs. Construction validates key length; every method thereafter is
/// infallible given a sector-size-aligned buffer.
pub enum SectorEngine {
    Xts(XtsVariant),
    CbcEssiv(CbcEssivVariant),
}

fn tweak_fn(sector_index: u128) -> [u8; 16] {
    plain64_iv(sector_index as u64)
}

impl SectorEngine {
    pub fn new(spec: CipherSpec, key: &[u8]) -> Result<Self, KeyError> {
        let expected = spec.required_key_bytes();
        if key.len() != expected {
            return Err(KeyError::WrongLength {
                expected,
                actual: key.len(),
            });
        }

        match spec.mode {
            CipherMode::XtsPlain64 => {
                let half = key.len() / 2;
                let (k1, k2) = key.split_at(half);
                let variant = match spec.aes_bits {
                    AesKeyBits::Bits128 => XtsVariant::Aes128(Xts128::new(
                        Aes128::new(k1.into()),
                        Aes128::new(k2.into()),
                    )),
                    AesKeyBits::Bits192 => XtsVariant::Aes192(Xts128::new(
                        Aes192::new(k1.into()),
                        Aes192::new(k2.into()),
                    )),
                    AesKeyBits::Bits256 => XtsVariant::Aes256(Xts128::new(
                        Aes256::new(k1.into()),
                        Aes256::new(k2.into()),
                    )),
                };
                Ok(SectorEngine::Xts(variant))
            }
            CipherMode::CbcEssivSha256 => {
                // ESSIV salt cipher is keyed with SHA-256(main_key); this
                // spec is only offered at 256-bit AES (see
                // CipherSpecError::UnsupportedEssivKeySize) precisely
                // because the 32-byte digest must equal the salt
                // cipher's key length.
                let digest = Sha256::digest(key);
                let variant = match spec.aes_bits {
                    AesKeyBits::Bits256 => CbcEssivVariant::Aes256 {
                        main: Aes256::new(key.into()),
                        essiv: Aes256::new((&digest[..]).into()),
                    },
                    AesKeyBits::Bits192 | AesKeyBits::Bits128 => unreachable!(
                        "CipherSpec::with_aes_bits rejects non-256-bit keys for CbcEssivSha256"
                    ),
                };
                Ok(SectorEngine::CbcEssiv(variant))
            }
        }
    }

    /// Encrypt `buf` in place. `first_sector` is the absolute 512-byte
    /// sector index of `buf[0]`; `buf.len()` must be a multiple of
    /// [`SECTOR_SIZE`].
    pub fn encrypt_range(&self, first_sector: u64, buf: &mut [u8]) {
        assert_eq!(buf.len() % SECTOR_SIZE, 0, "buffer must be sector-aligned");
        match self {
            SectorEngine::Xts(variant) => match variant {
                XtsVariant::Aes128(xts) => {
                    xts.encrypt_area(buf, SECTOR_SIZE, first_sector as u128, tweak_fn)
                }
                XtsVariant::Aes192(xts) => {
                    xts.encrypt_area(buf, SECTOR_SIZE, first_sector as u128, tweak_fn)
                }
                XtsVariant::Aes256(xts) => {
                    xts.encrypt_area(buf, SECTOR_SIZE, first_sector as u128, tweak_fn)
                }
            },
            SectorEngine::CbcEssiv(variant) => {
                cbc_essiv_crypt_range(variant, first_sector, buf, true)
            }
        }
    }

    /// Decrypt `buf` in place; same alignment contract as
    /// [`encrypt_range`](Self::encrypt_range).
    pub fn decrypt_range(&self, first_sector: u64, buf: &mut [u8]) {
        assert_eq!(buf.len() % SECTOR_SIZE, 0, "buffer must be sector-aligned");
        match self {
            SectorEngine::Xts(variant) => match variant {
                XtsVariant::Aes128(xts) => {
                    xts.decrypt_area(buf, SECTOR_SIZE, first_sector as u128, tweak_fn)
                }
                XtsVariant::Aes192(xts) => {
                    xts.decrypt_area(buf, SECTOR_SIZE, first_sector as u128, tweak_fn)
                }
                XtsVariant::Aes256(xts) => {
                    xts.decrypt_area(buf, SECTOR_SIZE, first_sector as u128, tweak_fn)
                }
            },
            SectorEngine::CbcEssiv(variant) => {
                cbc_essiv_crypt_range(variant, first_sector, buf, false)
            }
        }
    }
}

/// Manual per-sector CBC-ESSIV: IV resets every [`SECTOR_SIZE`] bytes to
/// `E_essiv(plain64_iv(sector))`, then standard CBC chaining applies
/// across the 16-byte AES blocks within that one sector only.
fn cbc_essiv_crypt_range(
    variant: &CbcEssivVariant,
    first_sector: u64,
    buf: &mut [u8],
    encrypt: bool,
) {
    let sectors = buf.len() / SECTOR_SIZE;
    for s in 0..sectors {
        let sector_index = first_sector + s as u64;
        let sector_buf = &mut buf[s * SECTOR_SIZE..(s + 1) * SECTOR_SIZE];

        macro_rules! run {
            ($main:expr, $essiv:expr) => {{
                let mut iv = plain64_iv(sector_index);
                $essiv.encrypt_block((&mut iv).into());
                if encrypt {
                    cbc_encrypt_blocks($main, &iv, sector_buf);
                } else {
                    cbc_decrypt_blocks($main, &iv, sector_buf);
                }
            }};
        }

        match variant {
            CbcEssivVariant::Aes256 { main, essiv } => run!(main, essiv),
        }
    }
}

fn cbc_encrypt_blocks<C: BlockEncrypt>(cipher: &C, iv: &[u8; 16], buf: &mut [u8]) {
    let mut prev = *iv;
    let (blocks, _) = buf.as_chunks_mut::<16>();
    for block in blocks {
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        cipher.encrypt_block((&mut block[..]).into());
        prev.copy_from_slice(&block[..]);
    }
}

fn cbc_decrypt_blocks<C: BlockDecrypt>(cipher: &C, iv: &[u8; 16], buf: &mut [u8]) {
    let mut prev = *iv;
    let (blocks, _) = buf.as_chunks_mut::<16>();
    for block in blocks {
        let ciphertext: [u8; 16] = *block;
        cipher.decrypt_block((&mut block[..]).into());
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        prev = ciphertext;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xts_key(aes_bits: AesKeyBits) -> Vec<u8> {
        let spec = CipherSpec::parse("aes-xts-plain64")
            .unwrap()
            .with_aes_bits(aes_bits.bits())
            .unwrap();
        (0..spec.required_key_bytes()).map(|i| i as u8).collect()
    }

    #[test]
    fn xts_round_trip_single_sector() {
        let key = xts_key(AesKeyBits::Bits256);
        let spec = CipherSpec::parse("aes-xts-plain64").unwrap();
        let engine = SectorEngine::new(spec, &key).unwrap();

        let plaintext: Vec<u8> = (0..SECTOR_SIZE as u32).map(|i| (i % 256) as u8).collect();
        let mut buf = plaintext.clone();
        engine.encrypt_range(0, &mut buf);
        assert_ne!(buf, plaintext, "ciphertext must differ from plaintext");
        engine.decrypt_range(0, &mut buf);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn xts_round_trip_multi_sector_nonzero_offset() {
        let key = xts_key(AesKeyBits::Bits256);
        let spec = CipherSpec::parse("aes-xts-plain64").unwrap();
        let engine = SectorEngine::new(spec, &key).unwrap();

        let plaintext: Vec<u8> = (0..(SECTOR_SIZE * 5) as u32)
            .map(|i| (i % 256) as u8)
            .collect();
        let mut buf = plaintext.clone();
        engine.encrypt_range(4096, &mut buf);
        engine.decrypt_range(4096, &mut buf);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn xts_same_plaintext_different_sectors_differ() {
        let key = xts_key(AesKeyBits::Bits256);
        let spec = CipherSpec::parse("aes-xts-plain64").unwrap();
        let engine = SectorEngine::new(spec, &key).unwrap();

        let plaintext = vec![0x42u8; SECTOR_SIZE];
        let mut a = plaintext.clone();
        let mut b = plaintext.clone();
        engine.encrypt_range(0, &mut a);
        engine.encrypt_range(1, &mut b);
        assert_ne!(
            a, b,
            "identical plaintext at different sectors must produce different ciphertext"
        );
    }

    #[test]
    fn xts_128_round_trip() {
        let key = xts_key(AesKeyBits::Bits128);
        let spec = CipherSpec::parse("aes-xts-plain64")
            .unwrap()
            .with_aes_bits(128)
            .unwrap();
        let engine = SectorEngine::new(spec, &key).unwrap();

        let plaintext = vec![0xABu8; SECTOR_SIZE * 2];
        let mut buf = plaintext.clone();
        engine.encrypt_range(10, &mut buf);
        engine.decrypt_range(10, &mut buf);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn cbc_essiv_round_trip() {
        let spec = CipherSpec::parse("aes-cbc-essiv:sha256").unwrap();
        let key: Vec<u8> = (0..32).map(|i| i as u8).collect();
        let engine = SectorEngine::new(spec, &key).unwrap();

        let plaintext: Vec<u8> = (0..(SECTOR_SIZE * 3) as u32)
            .map(|i| (i % 256) as u8)
            .collect();
        let mut buf = plaintext.clone();
        engine.encrypt_range(7, &mut buf);
        assert_ne!(buf, plaintext);
        engine.decrypt_range(7, &mut buf);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn wrong_key_length_rejected() {
        let spec = CipherSpec::parse("aes-xts-plain64").unwrap();
        let result = SectorEngine::new(spec, &[0u8; 10]);
        assert!(matches!(
            result,
            Err(KeyError::WrongLength {
                expected: 64,
                actual: 10
            })
        ));
    }
}
