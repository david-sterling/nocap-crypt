//! `nocap-crypt-cli`'s CLI surface, as a library — `main.rs` is a thin
//! wrapper calling [`run`]. The split was originally meant to let
//! `build.rs` share this same [`Cli`] tree for build-time shell
//! completions, which turned out to be impossible (a crate can't list
//! itself as a build-dependency — a genuine Cargo cycle, not a
//! restructuring problem), so that's deferred. The lib/bin split
//! stays anyway: it's the right structure on its own merits
//! (testability).

mod ci_progress;
mod cmd;
mod cryptsetup_compat;
mod env_config;
mod exitcode;
mod keyload;
mod progress;
mod redpill;
mod reporter_setup;

use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use cmd::align::{AlignCheckArgs, AlignFixArgs};
use cmd::bench::BenchArgs;
use cmd::entropy::EntropyArgs;
use cmd::image::{DecryptArgs, EncryptArgs};
use cmd::inspect::InspectArgs;
use cmd::keycheck::KeycheckArgs;
use cmd::keygen::KeygenArgs;
use cmd::validate::ValidateArgs;
use exitcode::ExitCode;
use nocap_crypt_ui::{Event, Reporter};

/// Userspace, unprivileged, dm-crypt (plain64) compatible sector-by-sector
/// encryption tool.
#[derive(Parser, Debug)]
#[command(name = "nocap-crypt", version, about)]
pub struct Cli {
    /// Silent mode: no stdout/stderr, communicate only via exit code.
    /// Wins over every other flag below.
    #[arg(short = 'q', long, global = true)]
    quiet: bool,
    #[arg(short = 'v', long, global = true)]
    verbose: bool,
    /// Implies verbose; adds narration/explanations.
    #[arg(long, global = true)]
    didactic: bool,
    /// The Boss Key: sterile enterprise-log output, no MUGA/4chan UI,
    /// no hardware flexing, no ASCII art. Wins over --redpill,
    /// --didactic, and -v (but not -q or --ci).
    #[arg(long, global = true)]
    governance: bool,
    /// CI/CD mode: line-by-line timestamped logs (no interactive
    /// redraw), a colored pass/fail banner at the end, and — when no
    /// subcommand is given — parameters sourced from NOCAP_CRYPT_*
    /// environment variables. Wins over --governance, --redpill, and
    /// --didactic (but not -q).
    #[arg(long, global = true)]
    ci: bool,
    #[arg(long, value_enum, default_value = "text", global = true)]
    log_format: LogFormatArg,
    #[arg(long, global = true)]
    no_color: bool,

    /// Wake up, Neo.
    #[arg(long, global = true, hide = true)]
    redpill: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum LogFormatArg {
    Text,
    Json,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Encrypt/decrypt a raw image/device, sector-by-sector, plain64.
    Image {
        #[command(subcommand)]
        action: ImageAction,
    },
    /// Generate a CSPRNG-backed key of the correct length for a cipher.
    Keygen(KeygenArgs),
    /// Validate a key: length, format, entropy, cipher fit.
    Keycheck(KeycheckArgs),
    /// Read-only content check of a ciphertext (CI use).
    Inspect(InspectArgs),
    /// Full validation: will this mount as LUKS/plain dm-crypt?
    Validate(ValidateArgs),
    /// Entropy verification on a file or stdin stream.
    Entropy(EntropyArgs),
    /// I/O buffer / block-device alignment.
    Align {
        #[command(subcommand)]
        action: AlignAction,
    },
    /// Performance benchmark with synthetic data.
    Bench(BenchArgs),
    /// Hardware accel, backend, build info. No data touched.
    Info,
    /// Generate a shell completion script (bash/zsh/fish/PowerShell/Elvish).
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Subcommand, Debug)]
enum ImageAction {
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
}

#[derive(Subcommand, Debug)]
enum AlignAction {
    Check(AlignCheckArgs),
    Fix(AlignFixArgs),
}

pub fn run() {
    // `Concurrency::GlobalPool` (the default) dispatches onto rayon's
    // own ambient global pool unmodified, modeled on dm-crypt's own
    // unbound-workqueue default (see `nocap-crypt-worker::concurrency`
    // module docs) — but unlike a kernel workqueue, an unconfigured
    // rayon pool sizes itself via `std::thread::available_parallelism()`,
    // which reports the *host's* cores, not a container's cgroup CPU
    // quota. `effective_core_count()` already resolves that quota (used
    // elsewhere purely for reporting); pre-building the global pool to
    // that size here, once, at startup, is what actually makes it bind
    // in a CPU-limited Kubernetes pod — the exact environment this tool
    // exists for — while keeping `GlobalPool`'s "one auto-balanced pool,
    // no per-operation static cap" design intact. `build_global()` can
    // only succeed once per process; a `cargo test` binary running many
    // tests never reaches this (only the real `run()` entry point does),
    // so there's nothing to guard against here — a second call from
    // elsewhere would just be a no-op via the ignored `Result`.
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(nocap_crypt_worker::effective_core_count())
        .build_global();

    let cli = Cli::parse();

    // The boss key and CI mode both win over the easter egg: neither
    // wants the meme UI slipping into a screenshot or a build log.
    if cli.redpill && !cli.governance && !cli.ci {
        std::process::exit(redpill::run(cli.quiet).code());
    }

    let json = matches!(cli.log_format, LogFormatArg::Json);
    let reporter = reporter_setup::build_reporter(cli.quiet, cli.ci, cli.governance, cli.verbose, cli.didactic, json, cli.no_color);
    // Progress bars are a text-mode-only affordance: mixing an
    // indicatif render into --log-format json would corrupt the
    // structured stdout stream a CI step is trying to parse.
    let show_progress = !cli.quiet && !json;

    // Single call site for every subcommand, rather than repeating
    // this at the top of each `cmd::*::run_*` — orients a --didactic
    // reader before any technical output, regardless of which
    // subcommand ends up running.
    if let Some(primer) = reporter.didactic_primer() {
        reporter.report(Event::Narration { text: primer.to_string() });
    }

    let start = Instant::now();
    let exit = run_command(&cli, reporter.as_ref(), json, show_progress);

    if reporter.ci_mode() {
        reporter.report(Event::Outcome {
            success: exit == ExitCode::Success,
            error_code: exit.error_code(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            label: exit.outcome_label().to_string(),
        });
    }

    std::process::exit(exit.code());
}

fn run_command(cli: &Cli, reporter: &dyn Reporter, json: bool, show_progress: bool) -> ExitCode {
    let Some(command) = &cli.command else {
        if !cli.ci {
            reporter.report(Event::Error {
                text: "a subcommand is required (or pass --ci with NOCAP_CRYPT_OPERATION set for \
                       standalone env-var-driven invocation)"
                    .to_string(),
            });
            return ExitCode::InvalidArgs;
        }
        return run_from_env(reporter, show_progress, cli.no_color);
    };

    match command {
        Command::Image { action } => match action {
            ImageAction::Encrypt(args) => cmd::image::run_encrypt(args, reporter, show_progress, cli.no_color),
            ImageAction::Decrypt(args) => cmd::image::run_decrypt(args, reporter, show_progress, cli.no_color),
        },
        Command::Keygen(args) => cmd::keygen::run(args, reporter),
        Command::Keycheck(args) => cmd::keycheck::run(args, reporter),
        Command::Inspect(args) => cmd::inspect::run(args, reporter, json),
        Command::Validate(args) => cmd::validate::run(args, reporter),
        Command::Entropy(args) => cmd::entropy::run(args, reporter),
        Command::Align { action } => match action {
            AlignAction::Check(args) => cmd::align::run_check(args, reporter),
            AlignAction::Fix(args) => cmd::align::run_fix(args, reporter),
        },
        Command::Bench(args) => cmd::bench::run_bench(args, reporter, json, show_progress, cli.no_color),
        Command::Info => cmd::info::run(reporter, json),
        Command::Completions { shell } => {
            let mut command = <Cli as clap::CommandFactory>::command();
            match cmd::completions::generate(*shell, &mut command, "nocap-crypt", &mut std::io::stdout()) {
                Ok(()) => ExitCode::Success,
                Err(e) => {
                    reporter.report(Event::Error {
                        text: format!("writing completion script: {e}"),
                    });
                    ExitCode::Io
                }
            }
        }
    }
}

/// Standalone `nocap-crypt --ci` (no subcommand): build the operation
/// entirely from `NOCAP_CRYPT_*` environment variables — see
/// `env_config` for the variable reference and scope (encrypt/decrypt
/// only for now).
fn run_from_env(reporter: &dyn Reporter, show_progress: bool, no_color: bool) -> ExitCode {
    match env_config::resolve_from_env() {
        Ok(env_config::Operation::Encrypt(args)) => cmd::image::run_encrypt(&args, reporter, show_progress, no_color),
        Ok(env_config::Operation::Decrypt(args)) => cmd::image::run_decrypt(&args, reporter, show_progress, no_color),
        Err(text) => {
            reporter.report(Event::Error { text });
            ExitCode::InvalidArgs
        }
    }
}
