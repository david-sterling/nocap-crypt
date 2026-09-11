//! `nocap-crypt keycheck`.

use std::path::PathBuf;

use clap::{Args, ValueHint};
use nocap_crypt_ui::{Event, Reporter};

use crate::exitcode::ExitCode;
use crate::keyload::{load_key_file, resolve_cipher_spec, CipherArg, KeyFormatArg};

#[derive(Args, Debug)]
pub struct KeycheckArgs {
    #[arg(long, value_hint = ValueHint::FilePath)]
    pub key_file: PathBuf,
    #[arg(long, value_enum, default_value = "auto")]
    pub key_format: KeyFormatArg,
    #[arg(long, value_enum, default_value = "aes-xts-plain64")]
    pub cipher: CipherArg,
    #[arg(long)]
    pub key_size: Option<u16>,
    /// Print the raw key material (hex, grouped). Never shown by
    /// default, even in didactic mode.
    #[arg(long, default_value_t = false)]
    pub reveal: bool,
}

pub fn run(args: &KeycheckArgs, reporter: &dyn Reporter) -> ExitCode {
    let spec = match resolve_cipher_spec(args.cipher, args.key_size) {
        Ok(s) => s,
        Err(e) => {
            reporter.report(Event::Error {
                text: e.to_string(),
            });
            return ExitCode::UnsupportedCipher;
        }
    };

    let key = match load_key_file(&args.key_file, args.key_format) {
        Ok(k) => k,
        Err(e) => {
            reporter.report(Event::Error {
                text: e.to_string(),
            });
            return ExitCode::Io;
        }
    };

    let report = match nocap_crypt_keymgmt::validate_key(&spec, &key) {
        Ok(r) => r,
        Err(e) => {
            reporter.report(Event::Error {
                text: e.to_string(),
            });
            return ExitCode::KeyValidation;
        }
    };

    reporter.report(Event::CipherSelected {
        cipher: spec.as_str(),
        key_bits: spec.aes_bits.bits(),
    });
    reporter.report(Event::EntropyScore {
        bits_per_byte: report.shannon_bits_per_byte,
        chi_square_uniform_95: report.chi_square_uniform_95,
    });
    // Always shown, not just under --didactic: a raw "5.7 bits/byte"
    // reads as a failing score next to the 8.0 maximum, but for a
    // 32/64-byte key it's the *expected* value — naive per-byte
    // Shannon entropy is capped by sample size alone (see
    // `nocap_crypt_entropy::shannon_entropy_ceiling`), not by
    // randomness quality. Without this line the number is actively
    // misleading, not just terse.
    let ceiling = nocap_crypt_entropy::shannon_entropy_ceiling(report.actual_bytes);
    reporter.report(Event::Message {
        text: format!(
            "entropy note: {:.4} bits/byte is expected here, not low — a {}-byte sample can't \
             exceed ~{:.2} bits/byte on this metric no matter how random the source is (too few \
             bytes to occupy all 256 possible values). Chi-square uniform@95% ({}) is the signal \
             that actually accounts for sample size.",
            report.shannon_bits_per_byte,
            report.actual_bytes,
            ceiling,
            report.chi_square_uniform_95
        ),
    });
    if reporter.narrates() {
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_keycheck_length().to_string(),
        });
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_entropy_result_key(
                report.shannon_bits_per_byte,
                report.actual_bytes,
            ),
        });
    }
    reporter.report(Event::Message {
        text: format!(
            "key OK: {} bytes (required {}), {}",
            report.actual_bytes,
            report.required_bytes,
            nocap_crypt_keymgmt::redacted(&key)
        ),
    });

    if args.reveal {
        reporter.report(Event::Message {
            text: format!("key material: {}", nocap_crypt_keymgmt::hex_grouped(&key)),
        });
    }

    ExitCode::Success
}
