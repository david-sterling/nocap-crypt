//! `Reporter`: the single code path all `nocap-crypt` output goes
//! through. Centralizing this here (rather than sprinkling
//! `println!`/`eprintln!` through the codebase) is what makes the
//! silent-mode contract ("no writes to stdout/stderr at all, not even
//! on error") an audit-once guarantee rather than a "mostly quiet"
//! hope — arguably more important in Rust than the equivalent Go
//! logger-wrapper note, since `println!`/`eprintln!` are so
//! frictionless to type without thinking.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    CipherSelected {
        cipher: String,
        key_bits: u16,
    },
    HardwareAccelPath {
        description: String,
    },
    /// System info + the resolved concurrency mode. Renamed from the
    /// old "WorkerHeuristic" shape: as of the dm-crypt-modeled
    /// concurrency redesign, `effective_cores`/`disk_type` are
    /// reported for transparency but no longer imply a worker count
    /// was computed from them by default — `concurrency` states the
    /// actual resolved mode (`Synchronous` / `GlobalPool` /
    /// `Fixed(n)`).
    ConcurrencyInfo {
        effective_cores: usize,
        disk_type: String,
        chunk_sectors: u64,
        concurrency: String,
    },
    AlignmentStatus {
        path: String,
        aligned: bool,
        required_alignment: u64,
    },
    PhaseTiming {
        phase: String,
        duration_ms: u64,
        throughput_mb_s: Option<f64>,
    },
    EntropyScore {
        bits_per_byte: f64,
        chi_square_uniform_95: bool,
    },
    /// A live progress update — only emitted by callers when
    /// `Reporter::ci_mode()` is true, as the line-by-line replacement
    /// for the interactive `indicatif` bar (`--ci` output must never
    /// contain `\r` cursor-redraw sequences, which a CI log viewer
    /// shows as spam rather than a moving bar).
    Progress {
        percent: f64,
        bytes_per_sec: Option<f64>,
        elapsed_secs: f64,
    },
    /// The final pass/fail signal for the whole invocation — emitted
    /// once, generically, after any subcommand finishes, only when
    /// `Reporter::ci_mode()` is true. `error_code` is the stable,
    /// grep-able `NC-###` tag derived from the exit code (see
    /// `ExitCode::error_code` in `nocap-crypt-cli`), not the exit code
    /// integer itself, so a CI script can `grep` for it without
    /// depending on process exit-code plumbing surviving whatever
    /// wrapper script invoked this tool.
    Outcome {
        success: bool,
        error_code: String,
        elapsed_ms: u64,
        label: String,
    },
    /// Didactic-only narration (IV derivation walkthroughs, check
    /// explanations) — suppressed by [`crate::Verbose`],
    /// [`crate::Corporate`], and [`crate::Silent`].
    Narration {
        text: String,
    },
    /// Pre-formatted multi-line block (boot banners) printed verbatim,
    /// with no `[INFO]`/prefix wrapping in any reporter — the text
    /// already carries its own framing.
    Banner {
        text: String,
    },
    Message {
        text: String,
    },
    Error {
        text: String,
    },
}

/// Which progress-bar presentation a [`Reporter`] mode wants during the
/// actual encrypt/decrypt phase — the part of a run that dominates
/// wall-clock time on a real image, so it's not just cosmetic which of
/// these three a mode picks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressFlavor {
    /// The cosmetic Pepe/agency animation — real numbers underneath,
    /// flavor text on top. Default for [`crate::Verbose`].
    Meme,
    /// A colorless `[####....] 50%` bar, no ASCII, no jokes —
    /// [`crate::Corporate`]'s "disables the hardware flexing".
    Sterile,
    /// A green bar with a live technical context line (cipher,
    /// concurrency, hardware path) plus a rotating plain-language
    /// explanation of what's happening right now — no meme animation,
    /// since a serious teaching mode competing with flavor text for
    /// attention during the longest visible part of a run is exactly
    /// the inconsistency this variant exists to fix. [`crate::Didactic`]
    /// only.
    Didactic,
}

/// All `nocap-crypt` output flows through this trait. `Silent` is a hard
/// no-op; `Verbose`/`Didactic`/`Corporate` render structured,
/// single-line-per-event output (human text or JSON per
/// `--log-format`).
pub trait Reporter: Send + Sync {
    fn report(&self, event: Event);

    /// Whether this reporter renders [`Event::Narration`] — true only
    /// for [`crate::Didactic`]. `Silent` never reports anything
    /// regardless.
    fn narrates(&self) -> bool {
        false
    }

    /// A fixed banner printed once at the start of a real operation,
    /// before any [`Event`] — `None` for reporters that don't have
    /// one ([`crate::Silent`]).
    fn boot_banner(&self) -> Option<&'static str> {
        None
    }

    /// A one-off satirical compliance-theater line, picked randomly by
    /// the reporter itself so callers don't need their own RNG
    /// plumbing for pure flavor text. `None` outside [`crate::Corporate`]
    /// mode.
    fn corporate_joke(&self) -> Option<String> {
        None
    }

    /// Which [`ProgressFlavor`] this mode wants during the
    /// encrypt/decrypt phase. Defaults to [`ProgressFlavor::Meme`].
    fn progress_flavor(&self) -> ProgressFlavor {
        ProgressFlavor::Meme
    }

    /// True only for [`crate::Ci`]. Callers use this to decide: (a) skip
    /// the interactive `indicatif` bar entirely and emit periodic
    /// [`Event::Progress`] lines instead, and (b) emit a final
    /// [`Event::Outcome`] once the operation completes.
    fn ci_mode(&self) -> bool {
        false
    }

    /// A short orientation primer, printed once before any technical
    /// output — `None` for every reporter except [`crate::Didactic`].
    /// Unlike [`boot_banner`](Self::boot_banner) (which amuses), this
    /// exists to explain how to read the narration that follows.
    fn didactic_primer(&self) -> Option<&'static str> {
        None
    }
}

pub(crate) fn emit(event: &Event, json: bool) {
    if json {
        if let Ok(line) = serde_json::to_string(event) {
            println!("{line}");
        }
    } else {
        println!("{}", format_human(event));
    }
}

pub(crate) fn format_human(event: &Event) -> String {
    match event {
        Event::CipherSelected { cipher, key_bits } => {
            format!("cipher: {cipher} (AES-{key_bits})")
        }
        Event::HardwareAccelPath { description } => format!("hw accel: {description}"),
        Event::ConcurrencyInfo {
            effective_cores,
            disk_type,
            chunk_sectors,
            concurrency,
        } => format!(
            "concurrency: {concurrency} (cores={effective_cores}, disk={disk_type}, chunk_sectors={chunk_sectors})"
        ),
        Event::AlignmentStatus {
            path,
            aligned,
            required_alignment,
        } => format!(
            "alignment: {path} {} (required={required_alignment})",
            if *aligned { "OK" } else { "FAIL" }
        ),
        Event::PhaseTiming {
            phase,
            duration_ms,
            throughput_mb_s,
        } => match throughput_mb_s {
            Some(mb_s) => format!("phase {phase}: {duration_ms}ms ({mb_s:.1} MB/s)"),
            None => format!("phase {phase}: {duration_ms}ms"),
        },
        Event::EntropyScore {
            bits_per_byte,
            chi_square_uniform_95,
        } => format!(
            "entropy: {bits_per_byte:.4} bits/byte (chi-square uniform@95%: {chi_square_uniform_95})"
        ),
        Event::Progress {
            percent,
            bytes_per_sec,
            elapsed_secs,
        } => match bytes_per_sec {
            Some(mb_s) => format!("progress: {percent:.0}% ({mb_s:.1} MB/s, {elapsed_secs:.1}s elapsed)"),
            None => format!("progress: {percent:.0}% ({elapsed_secs:.1}s elapsed)"),
        },
        Event::Outcome {
            success,
            error_code,
            elapsed_ms,
            label,
        } => format!(
            "outcome: {} [{error_code}] {label} ({:.1}s)",
            if *success { "success" } else { "failure" },
            *elapsed_ms as f64 / 1000.0
        ),
        Event::Narration { text } => format!("  \u{2192} {text}"),
        Event::Banner { text } => text.clone(),
        Event::Message { text } => text.clone(),
        Event::Error { text } => format!("error: {text}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ci, Corporate, Didactic, Silent, Verbose};

    // Cross-cutting properties that compare more than one reporter
    // mode (or format_human together with format_corporate) live here
    // rather than in any single mode's own file.

    #[test]
    fn only_didactic_has_a_primer() {
        assert_eq!(Silent.didactic_primer(), None);
        assert_eq!(Verbose { json: false }.didactic_primer(), None);
        assert_eq!(Corporate { json: false }.didactic_primer(), None);
        assert_eq!(Ci { json: false, no_color: false }.didactic_primer(), None);
        assert_eq!(
            Didactic { json: false }.didactic_primer(),
            Some(crate::didactic::narrate::DIDACTIC_PRIMER)
        );
    }

    #[test]
    fn only_verbose_has_the_muga_banner() {
        // The meme banner amuses; Didactic explains instead (via
        // `didactic_primer`) and deliberately has no boot banner of its
        // own — mixing the two was the exact inconsistency this split
        // exists to avoid, same as `progress_flavor` dropping the Pepe
        // animation for Didactic.
        assert!(Verbose { json: false }.boot_banner().is_some());
        assert_eq!(Didactic { json: false }.boot_banner(), None);
    }

    #[test]
    fn progress_flavor_is_mode_specific() {
        assert_eq!(Silent.progress_flavor(), ProgressFlavor::Meme);
        assert_eq!(Verbose { json: false }.progress_flavor(), ProgressFlavor::Meme);
        assert_eq!(Corporate { json: false }.progress_flavor(), ProgressFlavor::Sterile);
        assert_eq!(Didactic { json: false }.progress_flavor(), ProgressFlavor::Didactic);
    }

    #[test]
    fn only_corporate_tells_jokes() {
        assert_eq!(Silent.corporate_joke(), None);
        assert_eq!(Verbose { json: false }.corporate_joke(), None);
        assert_eq!(Didactic { json: false }.corporate_joke(), None);
        assert!(Corporate { json: false }.corporate_joke().is_some());
    }

    #[test]
    fn only_ci_is_in_ci_mode() {
        assert!(!Silent.ci_mode());
        assert!(!Verbose { json: false }.ci_mode());
        assert!(!Didactic { json: false }.ci_mode());
        assert!(!Corporate { json: false }.ci_mode());
        assert!(Ci { json: false, no_color: false }.ci_mode());
    }

    #[test]
    fn banner_prints_verbatim_with_no_prefix_in_any_reporter() {
        let banner = "====\nSOME BANNER\n====";
        assert_eq!(
            crate::corporate::format_corporate(&Event::Banner { text: banner.to_string() }),
            Some(banner.to_string())
        );
        assert_eq!(format_human(&Event::Banner { text: banner.to_string() }), banner.to_string());
    }

    #[test]
    fn human_format_covers_all_variants_without_panic() {
        let events = vec![
            Event::CipherSelected { cipher: "aes-xts-plain64".into(), key_bits: 256 },
            Event::HardwareAccelPath { description: "AES-NI".into() },
            Event::ConcurrencyInfo {
                effective_cores: 4,
                disk_type: "Ssd".into(),
                chunk_sectors: 8,
                concurrency: "GlobalPool".into(),
            },
            Event::AlignmentStatus { path: "/tmp/x".into(), aligned: true, required_alignment: 4096 },
            Event::PhaseTiming { phase: "encrypt".into(), duration_ms: 12, throughput_mb_s: Some(150.2) },
            Event::EntropyScore { bits_per_byte: 7.998, chi_square_uniform_95: true },
            Event::Progress { percent: 50.0, bytes_per_sec: Some(120.0), elapsed_secs: 6.2 },
            Event::Outcome {
                success: true,
                error_code: "NC-000".into(),
                elapsed_ms: 1400,
                label: "completed successfully".into(),
            },
            Event::Narration { text: "sector 4096 -> IV = 0x1000000000000000 LE".into() },
            Event::Banner { text: "some banner".into() },
            Event::Message { text: "done".into() },
            Event::Error { text: "boom".into() },
        ];
        for event in events {
            assert!(!format_human(&event).is_empty());
        }
    }
}
