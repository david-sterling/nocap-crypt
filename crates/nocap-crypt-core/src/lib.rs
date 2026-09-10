//! `nocap-crypt-core`: `plain64`-compatible sector encryption engine.
//!
//! This crate is the correctness-critical core of `nocap-crypt` — it is
//! responsible for producing ciphertext that is bit-identical to real
//! `dm-crypt`/`cryptsetup` output for the cipher specs it supports. See
//! `iv.rs` for the single highest-risk function in the whole project.

pub mod cipher;
pub mod cipherspec;
pub mod engine;
pub mod iv;

pub use cipher::KeyError;
pub use cipherspec::{AesKeyBits, CipherMode, CipherSpec, CipherSpecError};
pub use engine::{SectorEngine, SECTOR_SIZE};
pub use iv::{plain64_iv, IV_SECTOR_SIZE};
