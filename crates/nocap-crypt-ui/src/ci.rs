use crate::event::{format_human, Event, Reporter};

/// The `--ci` reporter: line-by-line, timestamped, no interactive
/// redraw, no ASCII/color noise during the run — one unmissable
/// colored pass/fail banner at the very end (text mode) or a
/// structured `Event::Outcome` line (json mode). No boot banner (CI
/// logs stay lean), no jokes, no narration — same suppression list as
/// [`crate::Corporate`] plus [`Event::Banner`] itself.
pub struct Ci {
    pub json: bool,
    pub no_color: bool,
}

impl Reporter for Ci {
    fn report(&self, event: Event) {
        if matches!(event, Event::Narration { .. } | Event::Banner { .. }) {
            return;
        }
        if self.json {
            if let Ok(line) = serde_json::to_string(&event) {
                println!("{line}");
            }
            return;
        }
        if let Event::Outcome {
            success,
            ref error_code,
            elapsed_ms,
            ref label,
        } = event
        {
            println!(
                "{}",
                render_outcome_banner(success, error_code, elapsed_ms, label, self.no_color)
            );
            return;
        }
        // `format_human`'s own `Event::Error` arm already prepends
        // "error: " — fine for Verbose/Didactic, where that's the only
        // marker, but redundant here since the `[ERROR]` level tag
        // already says it. Use the raw text for that one case instead.
        let body = match &event {
            Event::Error { text } => text.clone(),
            other => format_human(other),
        };
        println!("{} [{}] {}", timestamp_now(), level_for(&event), body);
    }

    fn ci_mode(&self) -> bool {
        true
    }
}

fn level_for(event: &Event) -> &'static str {
    match event {
        Event::Error { .. } => "ERROR",
        Event::Progress { .. } => "PROG ",
        _ => "INFO ",
    }
}

fn timestamp_now() -> String {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default()
}

/// Programmatically-sized colored block — every line's width is
/// derived from the content length, not hand-typed, so it can't drift
/// out of alignment the way freehand ASCII art can (see the frame
/// widths in `nocap-crypt-cli::progress`, which are hand-drawn and
/// verified separately for exactly that reason).
fn render_outcome_banner(success: bool, error_code: &str, elapsed_ms: u64, label: &str, no_color: bool) -> String {
    let elapsed_s = elapsed_ms as f64 / 1000.0;
    let (mark, word, bg) = if success {
        ("\u{2713}", "SUCCESS", "\x1b[42m\x1b[97m")
    } else {
        ("\u{2717}", "FAILURE", "\x1b[41m\x1b[97m")
    };
    let (bg, reset) = if no_color { ("", "") } else { (bg, "\x1b[0m") };

    let content = format!("{mark}  {word} [{error_code}] \u{2014} {label} ({elapsed_s:.1}s)");
    let content_len = content.chars().count();
    let width = (content_len + 8).max(60);
    let border = "\u{2588}".repeat(width);
    let blank = format!("\u{2588}\u{2588}{}\u{2588}\u{2588}", " ".repeat(width - 4));
    let content_line = format!(
        "\u{2588}\u{2588}  {content}{}  \u{2588}\u{2588}",
        " ".repeat(width - content_len - 8)
    );

    format!("{bg}{border}{reset}\n{bg}{blank}{reset}\n{bg}{content_line}{reset}\n{bg}{blank}{reset}\n{bg}{border}{reset}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_has_no_boot_banner_and_no_jokes() {
        let ci = Ci { json: false, no_color: false };
        assert_eq!(ci.boot_banner(), None);
        assert_eq!(ci.corporate_joke(), None);
    }

    #[test]
    fn outcome_banner_lines_are_all_equal_width() {
        for success in [true, false] {
            let banner = render_outcome_banner(success, "NC-003", 12345, "key validation failed", false);
            let widths: Vec<usize> = banner
                .lines()
                .map(|line| {
                    // Strip the ANSI color wrapper before measuring —
                    // width correctness is about the visible content,
                    // not the escape bytes.
                    line.trim_start_matches("\x1b[42m")
                        .trim_start_matches("\x1b[41m")
                        .trim_start_matches("\x1b[97m")
                        .trim_end_matches("\x1b[0m")
                        .chars()
                        .count()
                })
                .collect();
            assert_eq!(widths.iter().min(), widths.iter().max(), "banner lines have mismatched widths: {widths:?}");
        }
    }

    #[test]
    fn outcome_banner_contains_error_code_and_label() {
        let banner = render_outcome_banner(false, "NC-003", 500, "key validation failed", false);
        assert!(banner.contains("NC-003"));
        assert!(banner.contains("key validation failed"));
        assert!(banner.contains("FAILURE"));
    }

    #[test]
    fn outcome_banner_has_no_escape_bytes_when_no_color_is_set() {
        let banner = render_outcome_banner(true, "NC-000", 500, "completed successfully", true);
        assert!(!banner.contains('\x1b'));
        assert!(banner.contains("SUCCESS"));
    }

    #[test]
    fn timestamp_now_looks_like_rfc3339() {
        let ts = timestamp_now();
        assert!(ts.contains('T'));
        assert!(ts.ends_with('Z') || ts.contains('+') || ts.contains('-'));
    }
}
