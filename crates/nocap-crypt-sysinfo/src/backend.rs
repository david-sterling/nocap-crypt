//! Build provenance and crypto-backend reporting.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct BuildInfo {
    pub package_version: String,
    pub target_arch: String,
    pub target_os: String,
    /// Short git SHA the binary was built from, with a `-dirty` suffix
    /// if the working tree had uncommitted changes at build time.
    /// `"unknown"` if `build.rs` couldn't run `git` (e.g. building
    /// from a source tarball with no `.git`).
    pub git_sha: String,
}

pub fn build_info() -> BuildInfo {
    BuildInfo {
        package_version: env!("CARGO_PKG_VERSION").to_string(),
        target_arch: std::env::consts::ARCH.to_string(),
        target_os: std::env::consts::OS.to_string(),
        git_sha: env!("NOCAP_CRYPT_GIT_SHA").to_string(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CryptoBackendInfo {
    pub backend: String,
    pub cipher_specs_compiled_in: Vec<String>,
}

pub fn crypto_backend_info() -> CryptoBackendInfo {
    CryptoBackendInfo {
        backend: "RustCrypto aes/xts-mode/cbc/sha2 (pure Rust, no OpenSSL/libcrypto/ring linkage)"
            .to_string(),
        cipher_specs_compiled_in: vec![
            "aes-xts-plain64".to_string(),
            "aes-cbc-essiv:sha256".to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_info_reports_nonempty_version() {
        assert!(!build_info().package_version.is_empty());
    }

    #[test]
    fn build_info_reports_nonempty_git_sha() {
        assert!(!build_info().git_sha.is_empty());
    }

    #[test]
    fn crypto_backend_lists_both_cipher_specs() {
        let info = crypto_backend_info();
        assert!(info
            .cipher_specs_compiled_in
            .contains(&"aes-xts-plain64".to_string()));
        assert!(info
            .cipher_specs_compiled_in
            .contains(&"aes-cbc-essiv:sha256".to_string()));
    }
}
