//! Hardware acceleration and build/backend reporting, backing
//! `nocap-crypt info` and the self-describing context every `bench`
//! result carries.

pub mod backend;
pub mod hwaccel;

pub use backend::{build_info, crypto_backend_info, BuildInfo, CryptoBackendInfo};
pub use hwaccel::{detect_hw_accel, HwAccelReport};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    pub hw_accel: HwAccelReport,
    pub build: BuildInfo,
    pub crypto_backend: CryptoBackendInfo,
}

pub fn collect() -> SystemInfo {
    SystemInfo {
        hw_accel: detect_hw_accel(),
        build: build_info(),
        crypto_backend: crypto_backend_info(),
    }
}
