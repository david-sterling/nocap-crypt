//! Plain-language, one-sentence-each explanations of what's happening
//! *right now* during the encrypt/decrypt phase — rotated on the same
//! wall-clock tick driving the (unrelated) meme animation, for
//! [`nocap_crypt_ui::ProgressFlavor::Didactic`]. Deliberately not a
//! repeat of the fuller `didactic::narrate` prose already shown
//! before/after this phase — these are the short version, meant to be
//! readable at a glance while a bar is moving.

const DIDACTIC_LINES: &[&str] = &[
    "Slicing your file into 512-byte sectors \u{2014} the same chunking real disk encryption uses.",
    "Each sector gets its own secret \"tweak\" from its position, so identical data looks different everywhere.",
    "Scrambling every sector with your key \u{2014} without it, this is just noise, forwards or backwards.",
    "Sectors don't depend on each other, so many can be encrypted at the same time, safely.",
    "The output is the same shape as the input \u{2014} no extra header, nothing marking it as encrypted.",
];

/// ~2.4s per line at the 120ms poll interval.
const DIDACTIC_LINE_TICKS: u64 = 20;

pub fn didactic_line_for(tick: u64) -> &'static str {
    DIDACTIC_LINES[(tick / DIDACTIC_LINE_TICKS) as usize % DIDACTIC_LINES.len()]
}

pub const DIDACTIC_FINISH_LINE: &str =
    "done \u{2014} every sector is now unreadable without the key, and there's no \
     header giving away that this file is encrypted at all.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn didactic_lines_rotate_over_ticks_and_wrap_around() {
        let first = didactic_line_for(0);
        let second = didactic_line_for(DIDACTIC_LINE_TICKS);
        assert_ne!(
            first, second,
            "line must change once enough ticks have passed"
        );
        assert_eq!(
            first,
            didactic_line_for(DIDACTIC_LINE_TICKS * DIDACTIC_LINES.len() as u64),
            "must wrap back to the first line after a full cycle"
        );
    }

    #[test]
    fn didactic_lines_are_all_nonempty_and_plain_language() {
        for line in DIDACTIC_LINES {
            assert!(!line.is_empty());
            // Structural guard against accidentally pasting ANSI-colored
            // meme-frame content in here instead of plain narration text.
            assert!(!line.contains('\u{1b}'));
        }
    }

    #[test]
    fn didactic_finish_line_is_nonempty_and_plain() {
        assert!(!DIDACTIC_FINISH_LINE.is_empty());
        assert!(!DIDACTIC_FINISH_LINE.contains('\u{1b}'));
    }
}
