//! `nocap-crypt align check`/`align fix` — I/O buffer / block-device
//! alignment (O_DIRECT sector-size alignment), not ELF binary
//! alignment (see architecture plan §5.5 for the distinction this
//! tool deliberately targets).

use std::path::PathBuf;

use clap::{Args, ValueHint};
use nocap_crypt_blockio::{align_up, check_alignment, SectorFile};
use nocap_crypt_ui::{Event, Reporter};

use crate::exitcode::ExitCode;

#[derive(Args, Debug)]
pub struct AlignCheckArgs {
    #[arg(value_hint = ValueHint::AnyPath)]
    pub path: PathBuf,
    #[arg(long, default_value_t = 4096)]
    pub alignment: u64,
    #[arg(long, default_value_t = 0)]
    pub offset: u64,
}

#[derive(Args, Debug)]
pub struct AlignFixArgs {
    #[arg(value_hint = ValueHint::AnyPath)]
    pub path: PathBuf,
    #[arg(long, default_value_t = 4096)]
    pub alignment: u64,
}

pub fn run_check(args: &AlignCheckArgs, reporter: &dyn Reporter) -> ExitCode {
    let file_size = match std::fs::metadata(&args.path) {
        Ok(m) => m.len(),
        Err(e) => {
            reporter.report(Event::Error {
                text: format!("stat {}: {e}", args.path.display()),
            });
            return ExitCode::Io;
        }
    };

    let report = check_alignment(file_size, args.offset, args.alignment);
    reporter.report(Event::AlignmentStatus {
        path: args.path.display().to_string(),
        aligned: report.passes(),
        required_alignment: args.alignment,
    });
    if reporter.narrates() {
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_alignment_context().to_string(),
        });
    }
    reporter.report(Event::Message {
        text: format!(
            "file_size={} ({}), offset={} ({})",
            report.file_size,
            if report.file_size_aligned { "aligned" } else { "NOT aligned" },
            report.offset,
            if report.offset_aligned { "aligned" } else { "NOT aligned" },
        ),
    });

    if report.passes() {
        ExitCode::Success
    } else {
        ExitCode::AlignmentFailed
    }
}

pub fn run_fix(args: &AlignFixArgs, reporter: &dyn Reporter) -> ExitCode {
    let file_size = match std::fs::metadata(&args.path) {
        Ok(m) => m.len(),
        Err(e) => {
            reporter.report(Event::Error {
                text: format!("stat {}: {e}", args.path.display()),
            });
            return ExitCode::Io;
        }
    };

    let target = align_up(file_size, args.alignment);
    if target == file_size {
        reporter.report(Event::Message {
            text: format!("{} already aligned to {} bytes", args.path.display(), args.alignment),
        });
        return ExitCode::Success;
    }

    let sf = match SectorFile::open_write(&args.path, false) {
        Ok(f) => f,
        Err(e) => {
            reporter.report(Event::Error {
                text: format!("opening {}: {e}", args.path.display()),
            });
            return ExitCode::Io;
        }
    };
    if let Err(e) = sf.set_len(target) {
        reporter.report(Event::Error { text: e.to_string() });
        return ExitCode::Io;
    }

    reporter.report(Event::Message {
        text: format!(
            "padded {} from {} to {} bytes (sparse hole, alignment={})",
            args.path.display(),
            file_size,
            target,
            args.alignment
        ),
    });
    ExitCode::Success
}
