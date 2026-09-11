//! `nocap-crypt entropy` — works on a file or stdin, so it composes:
//! `nocap-crypt image encrypt ... | nocap-crypt entropy -q --threshold 7.9`.

use std::path::PathBuf;

use clap::{Args, ValueHint};
use nocap_crypt_ui::{Event, Reporter};

use crate::exitcode::ExitCode;

#[derive(Args, Debug)]
pub struct EntropyArgs {
    /// File to analyze; omit (or pass `-`) to read stdin.
    #[arg(value_hint = ValueHint::FilePath)]
    pub input: Option<PathBuf>,
    #[arg(long, default_value_t = 4096)]
    pub window_size: usize,
    /// Minimum acceptable Shannon entropy (bits/byte) across every
    /// window, for CI gating. Exit code 4 on failure.
    #[arg(long)]
    pub threshold: Option<f64>,
}

pub fn run(args: &EntropyArgs, reporter: &dyn Reporter) -> ExitCode {
    let report = match &args.input {
        Some(path) if path.as_os_str() != "-" => match std::fs::File::open(path) {
            Ok(f) => nocap_crypt_entropy::analyze_stream(f, args.window_size),
            Err(e) => {
                reporter.report(Event::Error {
                    text: format!("opening {}: {e}", path.display()),
                });
                return ExitCode::Io;
            }
        },
        _ => nocap_crypt_entropy::analyze_stream(std::io::stdin().lock(), args.window_size),
    };

    let report = match report {
        Ok(r) => r,
        Err(e) => {
            reporter.report(Event::Error {
                text: e.to_string(),
            });
            return ExitCode::Io;
        }
    };

    reporter.report(Event::EntropyScore {
        bits_per_byte: report.overall_shannon_bits_per_byte,
        chi_square_uniform_95: false,
    });
    if reporter.narrates() {
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_entropy_result_generic(
                report.overall_shannon_bits_per_byte,
            ),
        });
    }
    reporter.report(Event::Message {
        text: format!(
            "overall: {:.4} bits/byte, min window: {:.4} bits/byte, {} windows, {} bytes",
            report.overall_shannon_bits_per_byte,
            report.min_window_entropy().unwrap_or(0.0),
            report.windows.len(),
            report.total_bytes,
        ),
    });

    if let Some(threshold) = args.threshold {
        let min = report.min_window_entropy().unwrap_or(0.0);
        if min < threshold {
            reporter.report(Event::Error {
                text: format!("min window entropy {min:.4} below threshold {threshold:.4}"),
            });
            return ExitCode::EntropyFailed;
        }
    }

    ExitCode::Success
}
