//! `nocap-crypt inspect` — CI-oriented, read-only ciphertext content
//! check. No key required.

use std::path::PathBuf;

use clap::{Args, ValueHint};
use nocap_crypt_ui::{Event, Reporter};

use crate::exitcode::ExitCode;

#[derive(Args, Debug)]
pub struct InspectArgs {
    #[arg(value_hint = ValueHint::FilePath)]
    pub input: PathBuf,
    #[arg(long, default_value_t = 4096)]
    pub window_size: usize,
    #[arg(long, default_value_t = 512)]
    pub sector_size: u64,
}

pub fn run(args: &InspectArgs, reporter: &dyn Reporter, json: bool) -> ExitCode {
    if reporter.narrates() {
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_headerless_plain(),
        });
    }

    let file = match std::fs::File::open(&args.input) {
        Ok(f) => f,
        Err(e) => {
            reporter.report(Event::Error {
                text: format!("opening {}: {e}", args.input.display()),
            });
            return ExitCode::Io;
        }
    };

    let file_size = match file.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            reporter.report(Event::Error {
                text: e.to_string(),
            });
            return ExitCode::Io;
        }
    };

    let entropy = match nocap_crypt_entropy::analyze_stream(file, args.window_size) {
        Ok(r) => r,
        Err(e) => {
            reporter.report(Event::Error {
                text: e.to_string(),
            });
            return ExitCode::Io;
        }
    };

    let luks = {
        let head = std::fs::read(&args.input)
            .map(|d| d.into_iter().take(8).collect::<Vec<_>>())
            .unwrap_or_default();
        nocap_crypt_luks::detect_luks_header(&head)
    };

    if json {
        let payload = serde_json::json!({
            "file_size": file_size,
            "sector_size": args.sector_size,
            "sector_size_divisible": file_size % args.sector_size == 0,
            "overall_shannon_bits_per_byte": entropy.overall_shannon_bits_per_byte,
            "min_chunk_entropy": entropy.min_window_entropy(),
            "window_count": entropy.windows.len(),
            "luks_header": luks.map(|v| format!("{v:?}")),
        });
        if let Ok(text) = serde_json::to_string_pretty(&payload) {
            reporter.report(Event::Message { text });
        }
        return ExitCode::Success;
    }

    reporter.report(Event::Message {
        text: format!(
            "{}: {} bytes, sector-divisible: {}, luks header: {}",
            args.input.display(),
            file_size,
            file_size % args.sector_size == 0,
            luks.map(|v| format!("{v:?}"))
                .unwrap_or_else(|| "none (headerless/plain)".to_string()),
        ),
    });
    reporter.report(Event::EntropyScore {
        bits_per_byte: entropy.overall_shannon_bits_per_byte,
        chi_square_uniform_95: false,
    });
    if reporter.narrates() {
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_entropy_result_ciphertext(
                entropy.overall_shannon_bits_per_byte,
            ),
        });
    }
    reporter.report(Event::Message {
        text: format!(
            "min chunk entropy: {:.4} bits/byte across {} windows",
            entropy.min_window_entropy().unwrap_or(0.0),
            entropy.windows.len()
        ),
    });

    ExitCode::Success
}
