//! Known-answer tests against real NIST ACVP `ACVP-AES-XTS-1.0` vectors.
//!
//! `tests/vectors/acvp-aes-xts-1.0.json` is extracted verbatim (key/pt/ct/
//! tweak fields only, no reformatting) from `internalProjection.json` in
//! NIST's own `usnistgov/ACVP-Server` repository — its shipped, precomputed
//! result of running that repository's own local `gen-val` tooling against
//! the `ACVP-AES-XTS-1.0` sample registration. This same local/offline
//! `gen-val` toolchain (Orleans server + `GenValAppRunner`, no NIST account
//! or network dependency) was independently built and run to confirm the
//! local-generation path itself works; see `specs/fips_check.md` Tier 2.
//!
//! This exercises `xts_mode::Xts128<AesNNN>` (the exact crate/version
//! `nocap_crypt_core::engine::SectorEngine` composes) directly with each
//! vector's arbitrary 16-byte tweak, bypassing `SectorEngine`'s
//! sector-index-derived tweak (`plain64_iv`) since ACVP vectors use
//! arbitrary tweak values, not restricted to plain64's sector-number
//! convention. `plain64_iv` itself is exercised separately by
//! `engine.rs`'s own unit tests and is trivial by inspection (a
//! little-endian `u64` zero-padded to 16 bytes) — this test instead
//! validates the AES-XTS primitive underneath it against NIST's reference
//! implementation.
//!
//! The fixture holds 260 of the sample registration's 400 vectors: NIST's
//! `ACVP-AES-XTS-1.0` conformance suite includes `payloadLen` values that
//! aren't a multiple of 8 bits (sub-byte plaintext lengths), which is a
//! FIPS 1619 generality real block-device encryption never exercises —
//! disk sectors are byte-granular — and which `xts_mode` (byte-buffer
//! ciphertext stealing only) shares as an out-of-scope corner with every
//! byte-oriented AES-XTS implementation. The 140 excluded vectors are the
//! entire sub-byte-`payloadLen` subset; every byte-aligned vector is
//! included.

use aes::{Aes128, Aes256};
use cipher::KeyInit;
use serde::Deserialize;
use xts_mode::Xts128;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawVector {
    tc_id: u32,
    direction: String,
    key_len: u32,
    key: String,
    pt: String,
    ct: String,
    tweak: String,
}

fn run_case(v: &RawVector) {
    let key = hex::decode(&v.key).unwrap();
    let pt = hex::decode(&v.pt).unwrap();
    let ct = hex::decode(&v.ct).unwrap();
    let tweak_bytes = hex::decode(&v.tweak).unwrap();
    assert_eq!(
        tweak_bytes.len(),
        16,
        "tc {}: tweak must be 16 bytes",
        v.tc_id
    );
    let mut tweak = [0u8; 16];
    tweak.copy_from_slice(&tweak_bytes);

    let half = key.len() / 2;
    let (k1, k2) = key.split_at(half);

    match v.key_len {
        128 => {
            let xts = Xts128::new(
                Aes128::new(k1.try_into().expect("AES-128 half-key is 16 bytes")),
                Aes128::new(k2.try_into().expect("AES-128 half-key is 16 bytes")),
            );
            let mut buf = if v.direction == "encrypt" {
                pt.clone()
            } else {
                ct.clone()
            };
            if v.direction == "encrypt" {
                xts.encrypt_sector(&mut buf, tweak.into());
                assert_eq!(buf, ct, "tc {} (AES-128, encrypt) mismatch", v.tc_id);
            } else {
                xts.decrypt_sector(&mut buf, tweak.into());
                assert_eq!(buf, pt, "tc {} (AES-128, decrypt) mismatch", v.tc_id);
            }
        }
        256 => {
            let xts = Xts128::new(
                Aes256::new(k1.try_into().expect("AES-256 half-key is 32 bytes")),
                Aes256::new(k2.try_into().expect("AES-256 half-key is 32 bytes")),
            );
            let mut buf = if v.direction == "encrypt" {
                pt.clone()
            } else {
                ct.clone()
            };
            if v.direction == "encrypt" {
                xts.encrypt_sector(&mut buf, tweak.into());
                assert_eq!(buf, ct, "tc {} (AES-256, encrypt) mismatch", v.tc_id);
            } else {
                xts.decrypt_sector(&mut buf, tweak.into());
                assert_eq!(buf, pt, "tc {} (AES-256, decrypt) mismatch", v.tc_id);
            }
        }
        other => panic!("tc {}: unexpected keyLen {}", v.tc_id, other),
    }
}

#[test]
fn acvp_aes_xts_1_0_known_answer_vectors() {
    let raw = include_str!("vectors/acvp-aes-xts-1.0.json");
    let vectors: Vec<RawVector> = serde_json::from_str(raw).expect("fixture must parse");
    assert_eq!(
        vectors.len(),
        260,
        "expected all 260 byte-aligned ACVP-AES-XTS-1.0 sample vectors"
    );

    for v in &vectors {
        run_case(v);
    }
}
