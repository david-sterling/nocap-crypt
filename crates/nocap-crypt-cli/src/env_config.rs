//! Environment-variable parameter sourcing for standalone `nocap-crypt
//! --ci` invocation (no subcommand given at all) — reads `NOCAP_CRYPT_*`
//! variables so a pipeline step can run as just `nocap-crypt --ci`,
//! with the file to cipher/key/options coming from env instead of
//! process args that show up in shell history and process listings.
//!
//! Scoped to `encrypt`/`decrypt` for now — the two operations this
//! project's own origin (replacing a bash CI pipeline step) actually
//! needs; other `NOCAP_CRYPT_OPERATION` values return a clear
//! "not yet supported for env-only invocation" error rather than
//! silently doing nothing or guessing.

use std::path::PathBuf;
use std::str::FromStr;

use clap::ValueEnum;

use crate::cmd::image::{DecryptArgs, EncryptArgs};
use crate::keyload::{CipherArg, KeyFormatArg};
use nocap_crypt_worker::DEFAULT_SMALL_FILE_THRESHOLD_BYTES;

#[derive(Debug)]
pub enum Operation {
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
}

/// Build the operation to run entirely from `NOCAP_CRYPT_*`
/// environment variables. Fails fast with a single, specific message
/// naming exactly which variable is missing or malformed — before
/// touching any file — so a misconfigured pipeline fails immediately
/// with an actionable message instead of a confusing downstream I/O
/// error.
pub fn resolve_from_env() -> Result<Operation, String> {
    let operation = require("NOCAP_CRYPT_OPERATION")?;
    match operation.as_str() {
        "encrypt" => Ok(Operation::Encrypt(encrypt_args_from_env()?)),
        "decrypt" => Ok(Operation::Decrypt(decrypt_args_from_env()?)),
        other => Err(format!(
            "NOCAP_CRYPT_OPERATION={other:?} is not yet supported for standalone `--ci` \
             invocation (supported: encrypt, decrypt) — run with an explicit subcommand \
             instead, e.g. `nocap-crypt --ci {other} ...`"
        )),
    }
}

fn encrypt_args_from_env() -> Result<EncryptArgs, String> {
    Ok(EncryptArgs {
        input: require_path("NOCAP_CRYPT_INPUT")?,
        output: require_path("NOCAP_CRYPT_OUTPUT")?,
        key_file: require_path("NOCAP_CRYPT_KEY_FILE")?,
        key_format: optional_key_format()?,
        cipher: optional_cipher()?,
        key_size: optional_parsed("NOCAP_CRYPT_KEY_SIZE")?,
        align_block_size: optional_parsed("NOCAP_CRYPT_ALIGN_BLOCK_SIZE")?.unwrap_or(4096),
        align_extra_block: optional_parsed("NOCAP_CRYPT_ALIGN_EXTRA_BLOCK")?.unwrap_or(1),
        max_workers: optional_parsed("NOCAP_CRYPT_MAX_WORKERS")?,
        small_file_threshold: optional_parsed("NOCAP_CRYPT_SMALL_FILE_THRESHOLD")?
            .unwrap_or(DEFAULT_SMALL_FILE_THRESHOLD_BYTES),
        pin_to_submission_thread: optional_bool("NOCAP_CRYPT_PIN_TO_SUBMISSION_THREAD")?.unwrap_or(false),
        dry_run_cryptsetup_compat: false,
    })
}

fn decrypt_args_from_env() -> Result<DecryptArgs, String> {
    Ok(DecryptArgs {
        input: require_path("NOCAP_CRYPT_INPUT")?,
        output: require_path("NOCAP_CRYPT_OUTPUT")?,
        key_file: require_path("NOCAP_CRYPT_KEY_FILE")?,
        key_format: optional_key_format()?,
        cipher: optional_cipher()?,
        key_size: optional_parsed("NOCAP_CRYPT_KEY_SIZE")?,
        max_workers: optional_parsed("NOCAP_CRYPT_MAX_WORKERS")?,
        small_file_threshold: optional_parsed("NOCAP_CRYPT_SMALL_FILE_THRESHOLD")?
            .unwrap_or(DEFAULT_SMALL_FILE_THRESHOLD_BYTES),
        pin_to_submission_thread: optional_bool("NOCAP_CRYPT_PIN_TO_SUBMISSION_THREAD")?.unwrap_or(false),
    })
}

fn optional(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

fn require(name: &str) -> Result<String, String> {
    optional(name).ok_or_else(|| format!("{name} is required (and must be non-empty) for standalone `--ci` invocation"))
}

fn require_path(name: &str) -> Result<PathBuf, String> {
    require(name).map(PathBuf::from)
}

fn optional_parsed<T: FromStr>(name: &str) -> Result<Option<T>, String>
where
    T::Err: std::fmt::Display,
{
    match optional(name) {
        Some(s) => s.parse::<T>().map(Some).map_err(|e| format!("{name}={s:?} is not valid: {e}")),
        None => Ok(None),
    }
}

fn optional_bool(name: &str) -> Result<Option<bool>, String> {
    match optional(name) {
        Some(s) => match s.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" => Ok(Some(true)),
            "0" | "false" | "no" => Ok(Some(false)),
            _ => Err(format!("{name}={s:?} is not a valid boolean (use 1/0, true/false, yes/no)")),
        },
        None => Ok(None),
    }
}

fn optional_key_format() -> Result<KeyFormatArg, String> {
    match optional("NOCAP_CRYPT_KEY_FORMAT") {
        Some(s) => KeyFormatArg::from_str(&s, true).map_err(|e| format!("NOCAP_CRYPT_KEY_FORMAT={s:?} is not valid: {e}")),
        None => Ok(KeyFormatArg::Auto),
    }
}

fn optional_cipher() -> Result<CipherArg, String> {
    match optional("NOCAP_CRYPT_CIPHER") {
        Some(s) => CipherArg::from_str(&s, true).map_err(|e| format!("NOCAP_CRYPT_CIPHER={s:?} is not valid: {e}")),
        None => Ok(CipherArg::AesXtsPlain64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // std::env::var is process-global state; serialize these tests so
    // they don't stomp on each other when run in parallel (the default
    // for `cargo test`).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap();
        for (k, v) in vars {
            std::env::set_var(k, v);
        }
        f();
        for (k, _) in vars {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn missing_operation_is_a_clear_error() {
        with_env(&[], || {
            let err = resolve_from_env().unwrap_err();
            assert!(err.contains("NOCAP_CRYPT_OPERATION"));
        });
    }

    #[test]
    fn unsupported_operation_names_itself_in_the_error() {
        with_env(&[("NOCAP_CRYPT_OPERATION", "bench")], || {
            let err = resolve_from_env().unwrap_err();
            assert!(err.contains("bench"));
        });
    }

    #[test]
    fn encrypt_requires_input_output_key_file() {
        with_env(&[("NOCAP_CRYPT_OPERATION", "encrypt")], || {
            let err = resolve_from_env().unwrap_err();
            assert!(err.contains("NOCAP_CRYPT_INPUT"));
        });
    }

    #[test]
    fn encrypt_resolves_with_all_required_vars_and_sane_defaults() {
        with_env(
            &[
                ("NOCAP_CRYPT_OPERATION", "encrypt"),
                ("NOCAP_CRYPT_INPUT", "/tmp/in.img"),
                ("NOCAP_CRYPT_OUTPUT", "/tmp/out.enc"),
                ("NOCAP_CRYPT_KEY_FILE", "/tmp/key.bin"),
            ],
            || {
                let op = resolve_from_env().unwrap();
                match op {
                    Operation::Encrypt(args) => {
                        assert_eq!(args.input, PathBuf::from("/tmp/in.img"));
                        assert_eq!(args.output, PathBuf::from("/tmp/out.enc"));
                        assert_eq!(args.key_file, PathBuf::from("/tmp/key.bin"));
                        assert_eq!(args.cipher, CipherArg::AesXtsPlain64);
                        assert_eq!(args.align_block_size, 4096);
                        assert_eq!(args.align_extra_block, 1);
                        assert!(!args.pin_to_submission_thread);
                    }
                    Operation::Decrypt(_) => panic!("expected Encrypt"),
                }
            },
        );
    }

    #[test]
    fn decrypt_resolves_with_all_required_vars() {
        with_env(
            &[
                ("NOCAP_CRYPT_OPERATION", "decrypt"),
                ("NOCAP_CRYPT_INPUT", "/tmp/in.enc"),
                ("NOCAP_CRYPT_OUTPUT", "/tmp/out.img"),
                ("NOCAP_CRYPT_KEY_FILE", "/tmp/key.bin"),
            ],
            || {
                let op = resolve_from_env().unwrap();
                assert!(matches!(op, Operation::Decrypt(_)));
            },
        );
    }

    #[test]
    fn malformed_numeric_var_names_itself_in_the_error() {
        with_env(
            &[
                ("NOCAP_CRYPT_OPERATION", "encrypt"),
                ("NOCAP_CRYPT_INPUT", "/tmp/in.img"),
                ("NOCAP_CRYPT_OUTPUT", "/tmp/out.enc"),
                ("NOCAP_CRYPT_KEY_FILE", "/tmp/key.bin"),
                ("NOCAP_CRYPT_KEY_SIZE", "not-a-number"),
            ],
            || {
                let err = resolve_from_env().unwrap_err();
                assert!(err.contains("NOCAP_CRYPT_KEY_SIZE"));
            },
        );
    }

    #[test]
    fn pin_to_submission_thread_accepts_common_boolean_spellings() {
        with_env(
            &[
                ("NOCAP_CRYPT_OPERATION", "encrypt"),
                ("NOCAP_CRYPT_INPUT", "/tmp/in.img"),
                ("NOCAP_CRYPT_OUTPUT", "/tmp/out.enc"),
                ("NOCAP_CRYPT_KEY_FILE", "/tmp/key.bin"),
                ("NOCAP_CRYPT_PIN_TO_SUBMISSION_THREAD", "true"),
            ],
            || {
                let op = resolve_from_env().unwrap();
                match op {
                    Operation::Encrypt(args) => assert!(args.pin_to_submission_thread),
                    Operation::Decrypt(_) => panic!("expected Encrypt"),
                }
            },
        );
    }
}
