//! `nocap-crypt bench` — throughput sweep over worker count, using
//! deterministic synthetic data by default so results are
//! reproducible across CI runs.

use clap::Args;
use nocap_crypt_bench::{build_report, render_human_table, run, BenchParams};
use nocap_crypt_ui::{Event, Reporter};

use crate::exitcode::ExitCode;
use crate::keyload::{resolve_cipher_spec, CipherArg};
use crate::progress::LiveProgress;

#[derive(Args, Debug)]
pub struct BenchArgs {
    #[arg(long, value_enum, default_value = "aes-xts-plain64")]
    pub cipher: CipherArg,
    #[arg(long)]
    pub key_size: Option<u16>,
    #[arg(long, default_value_t = 32)]
    pub data_len_mb: u64,
    /// Comma-separated worker counts to sweep, e.g. "1,2,4,8".
    #[arg(long, default_value = "1,2,4")]
    pub workers: String,
    #[arg(long, default_value_t = 8)]
    pub chunk_sectors: u64,
    #[arg(long, default_value_t = 42)]
    pub seed: u64,
}

pub fn run_bench(
    args: &BenchArgs,
    reporter: &dyn Reporter,
    json: bool,
    show_progress: bool,
    no_color: bool,
) -> ExitCode {
    if let Some(banner) = reporter.boot_banner() {
        reporter.report(Event::Banner {
            text: banner.to_string(),
        });
    }

    let spec = match resolve_cipher_spec(args.cipher, args.key_size) {
        Ok(s) => s,
        Err(e) => {
            reporter.report(Event::Error {
                text: e.to_string(),
            });
            return ExitCode::UnsupportedCipher;
        }
    };

    if reporter.narrates() {
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_bench_methodology().to_string(),
        });
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_bench_data_source(args.seed),
        });
    }

    let key = nocap_crypt_keymgmt::generate_key(&spec);
    let data_len_bytes = args.data_len_mb * 1024 * 1024;

    let worker_counts: Vec<usize> = args
        .workers
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    if worker_counts.is_empty() {
        reporter.report(Event::Error {
            text: format!(
                "--workers {:?} contains no valid worker counts",
                args.workers
            ),
        });
        return ExitCode::InvalidArgs;
    }

    let mut results = Vec::new();
    for &worker_count in &worker_counts {
        let params = BenchParams {
            cipher: spec,
            key: key.clone(),
            data_len_bytes,
            worker_count,
            chunk_sectors: args.chunk_sectors,
            seed: args.seed,
        };
        // `--ci` never uses `indicatif` (no in-place redraw in a CI
        // log); bench doesn't have per-sweep-iteration CI progress
        // lines yet (see docs/ci-mode-plan.md open question #4), so it
        // just skips live progress entirely under CI and relies on the
        // PhaseTiming line reported per worker count below.
        let progress = LiveProgress::start(
            data_len_bytes,
            format!("bench(workers={worker_count}) / {}", spec.as_str()),
            show_progress && !reporter.ci_mode(),
            reporter.progress_flavor(),
            no_color,
        );
        let progress_counter = progress.as_ref().map(|p| p.counter().as_ref());
        let result = run(&params, progress_counter);
        if let Some(p) = progress {
            p.finish();
        }
        match result {
            Ok(result) => {
                reporter.report(Event::PhaseTiming {
                    phase: format!("bench(workers={worker_count})"),
                    duration_ms: result.duration_ms as u64,
                    throughput_mb_s: Some(result.throughput_mb_s),
                });
                if reporter.narrates() {
                    reporter.report(Event::Narration {
                        text: nocap_crypt_ui::explain_bench_worker_count(worker_count),
                    });
                }
                results.push(result);
            }
            Err(e) => {
                reporter.report(Event::Error {
                    text: e.to_string(),
                });
                return ExitCode::Io;
            }
        }
    }

    let report = build_report(results);
    if json {
        if let Ok(text) = serde_json::to_string_pretty(&report) {
            reporter.report(Event::Message { text });
        }
    } else {
        reporter.report(Event::Message {
            text: render_human_table(&report),
        });
    }

    ExitCode::Success
}
