//! CSPRNG-backed key generation for `nocap-crypt keygen`.
//!
//! Deliberately a separate code path from any seeded/deterministic RNG
//! used elsewhere (e.g. `nocap-crypt-bench`'s reproducible benchmark data
//! generator) — there is no shared function with an "insecure" flag, so
//! there's no way to accidentally wire real key material to a seedable
//! generator.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use nocap_crypt_core::CipherSpec;
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;

/// Generate a cryptographically random key of the length `spec`
/// requires, sourced from the OS CSPRNG (`getrandom`/`CryptGenRandom`
/// via `rand::rngs::OsRng`) — never a seedable PRNG.
pub fn generate_key(spec: &CipherSpec) -> Vec<u8> {
    let mut key = vec![0u8; spec.required_key_bytes()];
    OsRng.fill_bytes(&mut key);
    key
}

#[derive(Debug, Error)]
pub enum KeyFileWriteError {
    #[error("key file already exists at {path} (pass --force to overwrite)")]
    AlreadyExists { path: String },
    #[error("io error writing key file: {0}")]
    Io(#[from] std::io::Error),
}

/// Write `key` to `path`. Refuses to overwrite an existing file unless
/// `force` is set. On Unix, the file is created with `0600` permissions
/// (owner read/write only) so a freshly generated key file isn't
/// world-readable by default.
pub fn write_key_file(path: &Path, key: &[u8], force: bool) -> Result<(), KeyFileWriteError> {
    if path.exists() && !force {
        return Err(KeyFileWriteError::AlreadyExists {
            path: path.display().to_string(),
        });
    }

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    apply_restrictive_mode(&mut opts);

    let mut file = opts.open(path)?;
    file.write_all(key)?;
    Ok(())
}

#[cfg(unix)]
fn apply_restrictive_mode(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(0o600);
}

#[cfg(not(unix))]
fn apply_restrictive_mode(_opts: &mut OpenOptions) {
    // No POSIX mode bits on this platform; ACL-based restriction would
    // be a separate, platform-specific mechanism and is out of scope
    // for the initial implementation.
}

#[cfg(test)]
mod tests {
    use super::*;
    use nocap_crypt_core::CipherSpec;

    #[test]
    fn generates_key_of_required_length() {
        let spec = CipherSpec::parse("aes-xts-plain64").unwrap();
        let key = generate_key(&spec);
        assert_eq!(key.len(), spec.required_key_bytes());
    }

    #[test]
    fn generated_keys_are_not_identical() {
        let spec = CipherSpec::parse("aes-xts-plain64").unwrap();
        let a = generate_key(&spec);
        let b = generate_key(&spec);
        assert_ne!(a, b, "two independent CSPRNG draws collided — broken RNG wiring");
    }

    #[test]
    fn generated_key_is_not_all_zero() {
        let spec = CipherSpec::parse("aes-xts-plain64").unwrap();
        let key = generate_key(&spec);
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn refuses_to_overwrite_without_force() {
        let dir = std::env::temp_dir().join(format!("nocap-crypt-keygen-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key.bin");
        write_key_file(&path, &[1, 2, 3, 4], false).unwrap();

        let err = write_key_file(&path, &[5, 6, 7, 8], false).unwrap_err();
        assert!(matches!(err, KeyFileWriteError::AlreadyExists { .. }));

        write_key_file(&path, &[5, 6, 7, 8], true).unwrap();
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, vec![5, 6, 7, 8]);

        std::fs::remove_dir_all(&dir).ok();
    }
}
