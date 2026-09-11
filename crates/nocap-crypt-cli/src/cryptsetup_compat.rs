//! `--dry-run-cryptsetup-compat`: shell out to a real, locally
//! installed `cryptsetup` to encrypt a small fixture through an actual
//! `--type plain` dm-crypt mapping, then diff the resulting ciphertext
//! against [`SectorEngine`]'s own output for the same fixture/key/cipher.
//!
//! This is the live counterpart to the static vectors in
//! `nocap-crypt-core/tests/kat_cryptsetup.rs` (`specs/fips_check.md`
//! Tier 1) — useful for re-checking against whatever `cryptsetup`/kernel
//! happens to be on the machine this runs on, without regenerating and
//! committing new vectors every time. It needs a real Linux kernel with
//! dm-crypt and loop-device support, plus root/`CAP_SYS_ADMIN` for
//! `losetup`/`cryptsetup open` — the same privileged-runner requirement
//! `specs/fips_check.md` §2 documents for Tier 4. So: failure to even
//! run the check (missing binary, no privilege, no loop devices) is
//! reported and skipped, not treated as a cryptographic failure — only
//! an actual ciphertext mismatch is.

use nocap_crypt_core::CipherSpec;

/// How much fixture plaintext to push through the real mapping, and at
/// what sector offset. Nonzero `FIXTURE_SKIP_SECTORS` means the check
/// also exercises `plain64`'s sector-index tweak derivation, not just
/// the trivial sector-0 case.
const FIXTURE_SECTORS: u64 = 4;
const FIXTURE_SKIP_SECTORS: u64 = 17;

// Most variants besides `UnsupportedPlatform` are only ever constructed
// by the `#[cfg(target_os = "linux")]` platform module (or by this
// module's own tests) — on a non-Linux `cargo build`, that makes them
// look dead even though they're real, reachable states on the platform
// this feature actually targets.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// `cryptsetup` isn't on `PATH` — check skipped, not failed.
    CryptsetupNotFound,
    /// This platform can't run the check at all (needs Linux + dm-crypt
    /// + loop devices).
    UnsupportedPlatform,
    /// A step failed for an operational reason (no root, no losetup,
    /// no `/dev/mapper`, etc.) rather than a cryptographic one.
    OperationalError(String),
    /// Ciphertext matched byte-for-byte.
    Match,
    /// Ciphertext differed from real `cryptsetup` output — a real
    /// compatibility bug, unlike every other variant here.
    Mismatch,
}

impl Outcome {
    /// Only an actual ciphertext mismatch should fail the invocation —
    /// every other variant means the check didn't get to run at all,
    /// which `specs/fips_check.md` §2 already expects on most
    /// unprivileged machines/CI runners (Tier 4 is "privileged runner
    /// only").
    pub fn is_failure(&self) -> bool {
        matches!(self, Outcome::Mismatch)
    }

    pub fn message(&self) -> String {
        match self {
            Outcome::CryptsetupNotFound => {
                "--dry-run-cryptsetup-compat: cryptsetup not found on PATH, skipping".to_string()
            }
            Outcome::UnsupportedPlatform => {
                "--dry-run-cryptsetup-compat: needs Linux + dm-crypt + loop devices, skipping on this platform"
                    .to_string()
            }
            Outcome::OperationalError(detail) => format!(
                "--dry-run-cryptsetup-compat: could not complete (likely needs root/CAP_SYS_ADMIN \
                 — see specs/fips_check.md Tier 4): {detail}"
            ),
            Outcome::Match => format!(
                "--dry-run-cryptsetup-compat: MATCH ({FIXTURE_SECTORS} sectors at sector \
                 {FIXTURE_SKIP_SECTORS}, bit-for-bit identical to real cryptsetup output)"
            ),
            Outcome::Mismatch => {
                "--dry-run-cryptsetup-compat: MISMATCH — ciphertext differs from real cryptsetup output"
                    .to_string()
            }
        }
    }
}

pub fn run(spec: CipherSpec, key: &[u8]) -> Outcome {
    platform::run(spec, key)
}

#[cfg(target_os = "linux")]
mod platform {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::Command;

    use nocap_crypt_core::{CipherSpec, SectorEngine, SECTOR_SIZE};

    use super::{Outcome, FIXTURE_SECTORS, FIXTURE_SKIP_SECTORS};

    /// Best-effort teardown of whatever got set up before an error —
    /// `Drop` rather than manual cleanup calls at every early return, so
    /// a step failing partway through (e.g. `cryptsetup open` succeeds
    /// but the mapped-device write fails) can't leak a loop device or
    /// dm-crypt mapping.
    struct Guard {
        map_name: Option<String>,
        loop_dev: Option<String>,
        backing_path: PathBuf,
        key_path: PathBuf,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(name) = &self.map_name {
                let _ = Command::new("cryptsetup").args(["close", name]).status();
            }
            if let Some(dev) = &self.loop_dev {
                let _ = Command::new("losetup").args(["-d", dev]).status();
            }
            let _ = std::fs::remove_file(&self.backing_path);
            let _ = std::fs::remove_file(&self.key_path);
        }
    }

    pub fn run(spec: CipherSpec, key: &[u8]) -> Outcome {
        if Command::new("cryptsetup")
            .arg("--version")
            .output()
            .is_err()
        {
            return Outcome::CryptsetupNotFound;
        }

        match run_inner(spec, key) {
            Ok(matched) => {
                if matched {
                    Outcome::Match
                } else {
                    Outcome::Mismatch
                }
            }
            Err(detail) => Outcome::OperationalError(detail),
        }
    }

    fn run_inner(spec: CipherSpec, key: &[u8]) -> Result<bool, String> {
        let fixture_len = FIXTURE_SECTORS as usize * SECTOR_SIZE;
        let plaintext: Vec<u8> = (0..fixture_len).map(|i| (i % 256) as u8).collect();

        let engine = SectorEngine::new(spec, key).map_err(|e| format!("building engine: {e}"))?;
        let mut ours = plaintext.clone();
        engine.encrypt_range(FIXTURE_SKIP_SECTORS, &mut ours);

        let pid = std::process::id();
        let dir = std::env::temp_dir();
        let backing_path = dir.join(format!("nocap-crypt-compat-{pid}.img"));
        let key_path = dir.join(format!("nocap-crypt-compat-{pid}.key"));
        let map_name = format!("nocap-crypt-compat-{pid}");

        let mut guard = Guard {
            map_name: None,
            loop_dev: None,
            backing_path: backing_path.clone(),
            key_path: key_path.clone(),
        };

        // Backing file only needs to hold the fixture itself — `--skip`
        // (below) shifts which IV/tweak sector number `cryptsetup`
        // uses, not where the write lands on the backing device. A
        // write to the start of the mapped device always lands at
        // backing-file offset 0 unless `--offset` is also given, which
        // it isn't here. The ciphertext must always be read back from
        // backing-file offset 0, never from a skip-shifted offset —
        // getting this wrong makes every run report a false MISMATCH.
        let total_len = FIXTURE_SECTORS * SECTOR_SIZE as u64;
        std::fs::File::create(&backing_path)
            .and_then(|f| f.set_len(total_len))
            .map_err(|e| format!("creating backing file: {e}"))?;
        std::fs::write(&key_path, key).map_err(|e| format!("writing key file: {e}"))?;

        let losetup_out = Command::new("losetup")
            .args(["--find", "--show"])
            .arg(&backing_path)
            .output()
            .map_err(|e| format!("running losetup: {e}"))?;
        if !losetup_out.status.success() {
            return Err(format!(
                "losetup failed: {}",
                String::from_utf8_lossy(&losetup_out.stderr).trim()
            ));
        }
        let loop_dev = String::from_utf8_lossy(&losetup_out.stdout)
            .trim()
            .to_string();
        guard.loop_dev = Some(loop_dev.clone());

        let key_file_str = key_path
            .to_str()
            .ok_or("temp key path is not valid UTF-8")?
            .to_string();
        let open_args: Vec<String> = vec![
            "open".into(),
            "--type".into(),
            "plain".into(),
            "--cipher".into(),
            spec.as_str(),
            "--key-size".into(),
            (spec.required_key_bytes() * 8).to_string(),
            "--key-file".into(),
            key_file_str,
            // No `--keyfile-size`: the key file we just wrote is
            // exactly `key.len()` bytes on disk (never padded/truncated
            // elsewhere), which is already what `cryptsetup` reads by
            // default from `--key-size` alone — passing it explicitly
            // only produces a harmless-but-noisy "option is being
            // ignored" warning on stderr.
            "--skip".into(),
            FIXTURE_SKIP_SECTORS.to_string(),
            loop_dev.clone(),
            map_name.clone(),
        ];
        let open_status = Command::new("cryptsetup")
            .args(&open_args)
            .status()
            .map_err(|e| format!("running cryptsetup open: {e}"))?;
        if !open_status.success() {
            return Err(format!("cryptsetup open exited with {open_status}"));
        }
        guard.map_name = Some(map_name.clone());

        let map_path = format!("/dev/mapper/{map_name}");
        OpenOptions::new()
            .write(true)
            .open(&map_path)
            .and_then(|mut f| f.write_all(&plaintext))
            .map_err(|e| format!("writing through dm-crypt mapping: {e}"))?;

        // Real dm-crypt output lands at the start of the backing file —
        // `--skip` only changed the IV, not the write location (see the
        // comment above `total_len`).
        let backing_bytes =
            std::fs::read(&backing_path).map_err(|e| format!("reading backing file: {e}"))?;
        if backing_bytes.len() < fixture_len {
            return Err("backing file shorter than expected after write".to_string());
        }
        let real_ciphertext = &backing_bytes[..fixture_len];

        drop(guard);
        Ok(real_ciphertext == ours.as_slice())
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use nocap_crypt_core::CipherSpec;

    use super::Outcome;

    pub fn run(_spec: CipherSpec, _key: &[u8]) -> Outcome {
        Outcome::UnsupportedPlatform
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_mismatch_is_a_failure() {
        assert!(!Outcome::CryptsetupNotFound.is_failure());
        assert!(!Outcome::UnsupportedPlatform.is_failure());
        assert!(!Outcome::OperationalError("x".into()).is_failure());
        assert!(!Outcome::Match.is_failure());
        assert!(Outcome::Mismatch.is_failure());
    }

    #[test]
    fn every_outcome_has_a_nonempty_message() {
        for outcome in [
            Outcome::CryptsetupNotFound,
            Outcome::UnsupportedPlatform,
            Outcome::OperationalError("detail".to_string()),
            Outcome::Match,
            Outcome::Mismatch,
        ] {
            assert!(!outcome.message().is_empty());
        }
    }

    #[test]
    fn match_message_names_the_fixture_shape() {
        let msg = Outcome::Match.message();
        assert!(msg.contains(&FIXTURE_SECTORS.to_string()));
        assert!(msg.contains(&FIXTURE_SKIP_SECTORS.to_string()));
    }

    #[test]
    fn operational_error_message_includes_the_detail() {
        let msg = Outcome::OperationalError("permission denied".to_string()).message();
        assert!(msg.contains("permission denied"));
    }

    /// Smoke test for whichever `platform::run` this OS compiles in.
    /// This crate's dev/CI matrix includes a non-Linux (Windows)
    /// machine, so the non-Linux stub path needs its own real coverage,
    /// not just a mention in a doc comment.
    #[test]
    fn run_on_this_platform_does_not_panic() {
        let spec = CipherSpec::parse("aes-xts-plain64").unwrap();
        let key = vec![0u8; spec.required_key_bytes()];
        let outcome = run(spec, &key);
        if cfg!(not(target_os = "linux")) {
            assert_eq!(outcome, Outcome::UnsupportedPlatform);
        }
    }
}
