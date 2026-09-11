//! `nocap-crypt keygen`.

use std::path::PathBuf;

use clap::{Args, ValueHint};
use nocap_crypt_core::CipherMode;
use nocap_crypt_ui::{Event, Reporter};

use crate::exitcode::ExitCode;
use crate::keyload::{resolve_cipher_spec, CipherArg};

#[derive(Args, Debug)]
pub struct KeygenArgs {
    #[arg(long, value_enum, default_value = "aes-xts-plain64")]
    pub cipher: CipherArg,
    #[arg(long)]
    pub key_size: Option<u16>,
    #[arg(long, value_hint = ValueHint::AnyPath)]
    pub output: PathBuf,
    #[arg(long, default_value_t = false)]
    pub force: bool,
}

pub fn run(args: &KeygenArgs, reporter: &dyn Reporter) -> ExitCode {
    let spec = match resolve_cipher_spec(args.cipher, args.key_size) {
        Ok(s) => s,
        Err(e) => {
            reporter.report(Event::Error {
                text: e.to_string(),
            });
            return ExitCode::UnsupportedCipher;
        }
    };

    let key = nocap_crypt_keymgmt::generate_key(&spec);

    if let Err(e) = nocap_crypt_keymgmt::write_key_file(&args.output, &key, args.force) {
        reporter.report(Event::Error {
            text: e.to_string(),
        });
        return ExitCode::Io;
    }

    reporter.report(Event::CipherSelected {
        cipher: spec.as_str(),
        key_bits: spec.aes_bits.bits(),
    });
    if reporter.narrates() {
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_key_generation(
                key.len(),
                spec.mode == CipherMode::XtsPlain64,
            ),
        });
    }
    reporter.report(Event::Message {
        text: format!(
            "wrote {}-byte key to {} ({})",
            key.len(),
            args.output.display(),
            nocap_crypt_keymgmt::redacted(&key)
        ),
    });
    if reporter.narrates() {
        let entropy = nocap_crypt_entropy::shannon_entropy(&key);
        reporter.report(Event::EntropyScore {
            bits_per_byte: entropy,
            chi_square_uniform_95: nocap_crypt_entropy::is_uniform(&key, 1.645),
        });
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_entropy_result_key(entropy, key.len()),
        });
    }

    ExitCode::Success
}
