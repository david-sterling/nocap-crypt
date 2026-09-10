//! Hardware AES acceleration detection/reporting.
//!
//! Go's/Rust's respective standard crypto stacks dispatch to hardware
//! AES automatically when available — `nocap-crypt info` exists to report
//! *which path is active*, since that's what a reviewer/cryptanalyst
//! wants to confirm, not change.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct HwAccelReport {
    pub target_arch: String,
    /// Whether the CPU itself exposes AES hardware extensions
    /// (AES-NI on x86_64, ARMv8 Crypto Extensions on aarch64) —
    /// independent of whether this binary's crypto backend actually
    /// uses them.
    pub cpu_supports_aes_extensions: bool,
    /// x86_64 only: VAES (vectorized AES-NI) support.
    pub cpu_supports_vaes: Option<bool>,
    /// Whether the compiled-in crypto backend (RustCrypto `aes` crate)
    /// actually takes the hardware path on this build.
    pub crypto_backend_uses_hardware: bool,
    pub active_path_description: String,
}

pub fn detect_hw_accel() -> HwAccelReport {
    detect_platform()
}

#[cfg(target_arch = "x86_64")]
fn detect_platform() -> HwAccelReport {
    // RustCrypto's `aes` crate does runtime AES-NI/VAES detection
    // automatically on stable, no build-time flags needed — the
    // hardware path is active whenever the CPU supports it.
    let aes = is_x86_feature_detected!("aes");
    let vaes = is_x86_feature_detected!("vaes");
    let path = match (aes, vaes) {
        (true, true) => "AES-NI + VAES (hardware)".to_string(),
        (true, false) => "AES-NI (hardware)".to_string(),
        (false, _) => "software (constant-time bitsliced fallback)".to_string(),
    };
    HwAccelReport {
        target_arch: "x86_64".to_string(),
        cpu_supports_aes_extensions: aes,
        cpu_supports_vaes: Some(vaes),
        crypto_backend_uses_hardware: aes,
        active_path_description: path,
    }
}

#[cfg(target_arch = "aarch64")]
fn detect_platform() -> HwAccelReport {
    let aes = std::arch::is_aarch64_feature_detected!("aes");
    // Stable-first decision (see Rust Architecture Plan §6): the
    // RustCrypto `aes` crate's `armv8` feature currently requires a
    // nightly compiler, so this build never takes the ARMv8 Crypto
    // Extension hardware path even when the CPU supports it — reported
    // honestly rather than implying hardware accel is active.
    let path = if aes {
        "software (fixslicing) — CPU supports ARMv8 Crypto Extensions, but this build's crypto backend requires nightly to use them (stable-first policy)".to_string()
    } else {
        "software (fixslicing) — hardware AES unavailable on this CPU".to_string()
    };
    HwAccelReport {
        target_arch: "aarch64".to_string(),
        cpu_supports_aes_extensions: aes,
        cpu_supports_vaes: None,
        crypto_backend_uses_hardware: false,
        active_path_description: path,
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn detect_platform() -> HwAccelReport {
    HwAccelReport {
        target_arch: std::env::consts::ARCH.to_string(),
        cpu_supports_aes_extensions: false,
        cpu_supports_vaes: None,
        crypto_backend_uses_hardware: false,
        active_path_description: "software (constant-time fallback) — no hardware AES detection implemented for this architecture".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_has_nonempty_description() {
        let report = detect_hw_accel();
        assert!(!report.active_path_description.is_empty());
        assert!(!report.target_arch.is_empty());
    }

    #[test]
    fn crypto_backend_hardware_use_implies_cpu_support() {
        let report = detect_hw_accel();
        if report.crypto_backend_uses_hardware {
            assert!(report.cpu_supports_aes_extensions);
        }
    }
}
