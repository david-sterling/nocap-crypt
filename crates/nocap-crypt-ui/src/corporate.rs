use rand::seq::IndexedRandom;

use crate::event::{Event, ProgressFlavor, Reporter};
use crate::quotes::SATIRICAL_QUOTES;

/// The "Boss Key" reporter: same [`Event`] data as every other mode
/// (real numbers stay real), rendered as a sterile enterprise log —
/// no color, no ASCII, no MUGA/4chan references. `--log-format json`
/// output is identical to [`crate::Verbose`]'s JSON — the sterile
/// phrasing is a text-mode-only stylistic choice.
pub struct Corporate {
    pub json: bool,
}

impl Reporter for Corporate {
    fn report(&self, event: Event) {
        if json_suppressed_in_corporate(&event) {
            return;
        }
        if self.json {
            if let Ok(line) = serde_json::to_string(&event) {
                println!("{line}");
            }
        } else if let Some(line) = format_corporate(&event) {
            println!("{line}");
        }
    }

    fn boot_banner(&self) -> Option<&'static str> {
        Some(CORPORATE_BOOT_BANNER)
    }

    fn corporate_joke(&self) -> Option<String> {
        let mut rng = rand::rng();
        SATIRICAL_QUOTES.choose(&mut rng).map(|s| s.to_string())
    }

    fn progress_flavor(&self) -> ProgressFlavor {
        ProgressFlavor::Sterile
    }
}

const CORPORATE_BOOT_BANNER: &str = "\
============================================================
ENTERPRISE CRYPTOGRAPHIC GOVERNANCE MODULE v1.0.4
Compliance Standard: NIST SP 800-38E / FIPS 140-2 Aligned
============================================================
[INFO] Establishing Zero-Trust Userspace Perimeter...";

/// Events the JSON branch of [`Corporate`] also drops — the same set
/// [`format_corporate`] has nothing sterile to say about (hardware
/// flexing, concurrency internals, raw alignment plumbing). Kept
/// separate from `format_corporate`'s `None` returns so JSON and text
/// output agree on what's suppressed.
fn json_suppressed_in_corporate(event: &Event) -> bool {
    matches!(
        event,
        Event::HardwareAccelPath { .. }
            | Event::ConcurrencyInfo { .. }
            | Event::AlignmentStatus { .. }
            | Event::Narration { .. }
            | Event::Progress { .. }
            | Event::Outcome { .. }
    )
}

/// Sterile Cisco-tier phrasing for [`Corporate`]. `None` means this
/// event is dropped in corporate mode (hardware flexing, concurrency
/// internals, raw alignment plumbing, and narration are all too
/// "flexy" for a boss-key screenshot).
pub(crate) fn format_corporate(event: &Event) -> Option<String> {
    match event {
        Event::CipherSelected { cipher, key_bits } => {
            Some(format!("[INFO] Applying {cipher} cipher (AES-{key_bits})."))
        }
        Event::HardwareAccelPath { .. } => None,
        Event::ConcurrencyInfo { .. } => None,
        Event::AlignmentStatus { .. } => None,
        Event::PhaseTiming {
            duration_ms,
            throughput_mb_s,
            ..
        } => {
            let secs = *duration_ms as f64 / 1000.0;
            let throughput = throughput_mb_s
                .map(|mb_s| format!(" ({mb_s:.1} MB/s)"))
                .unwrap_or_default();
            Some(format!(
                "[SUCCESS] Volume secured in {secs:.2}s{throughput}. Please update your OKRs."
            ))
        }
        Event::EntropyScore { bits_per_byte, .. } => Some(format!(
            "[INFO] Entropy Compliance: {bits_per_byte:.2}/8.0 bits/byte [NIST SP 800-38E ALIGNED]"
        )),
        Event::Progress { .. } => None,
        Event::Outcome { .. } => None,
        Event::Narration { .. } => None,
        Event::Banner { text } => Some(text.clone()),
        Event::Message { text } => Some(format!("[INFO] {text}")),
        Event::Error { text } => Some(format!("[ERROR] {text}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corporate_does_not_narrate() {
        assert!(!Corporate { json: false }.narrates());
    }

    #[test]
    fn corporate_banner_is_sterile_no_muga_references() {
        let banner = Corporate { json: false }.boot_banner().unwrap();
        let lower = banner.to_lowercase();
        assert!(!lower.contains("muga"));
        assert!(!lower.contains("patriot"));
        assert!(!lower.contains("great again"));
    }

    #[test]
    fn corporate_joke_is_one_of_the_registered_jokes() {
        let joke = Corporate { json: false }.corporate_joke().unwrap();
        assert!(SATIRICAL_QUOTES.contains(&joke.as_str()));
    }

    #[test]
    fn corporate_suppresses_flexy_events() {
        for event in [
            Event::HardwareAccelPath {
                description: "AES-NI".into(),
            },
            Event::ConcurrencyInfo {
                effective_cores: 4,
                disk_type: "Ssd".into(),
                chunk_sectors: 8,
                concurrency: "GlobalPool".into(),
            },
            Event::AlignmentStatus {
                path: "/tmp/x".into(),
                aligned: true,
                required_alignment: 4096,
            },
            Event::Narration {
                text: "sector 0".into(),
            },
            Event::Progress {
                percent: 50.0,
                bytes_per_sec: None,
                elapsed_secs: 1.0,
            },
            Event::Outcome {
                success: true,
                error_code: "NC-000".into(),
                elapsed_ms: 1,
                label: "x".into(),
            },
        ] {
            assert_eq!(format_corporate(&event), None);
        }
    }

    #[test]
    fn corporate_format_has_no_muga_wording() {
        let events = [
            Event::CipherSelected {
                cipher: "aes-xts-plain64".into(),
                key_bits: 256,
            },
            Event::PhaseTiming {
                phase: "encrypt".into(),
                duration_ms: 1400,
                throughput_mb_s: Some(150.2),
            },
            Event::EntropyScore {
                bits_per_byte: 7.998,
                chi_square_uniform_95: true,
            },
            Event::Banner {
                text: "some banner".into(),
            },
            Event::Message {
                text: "hello".into(),
            },
            Event::Error {
                text: "boom".into(),
            },
        ];
        for event in events {
            if let Some(line) = format_corporate(&event) {
                let lower = line.to_lowercase();
                assert!(!lower.contains("nocap"));
                assert!(!lower.contains("muga"));
                assert!(!lower.contains("cabal"));
            }
        }
    }
}
