//! Cosmetic ASCII-art frames for [`crate::progress::LiveProgress`]'s
//! [`nocap_crypt_ui::ProgressFlavor::Meme`] display — agency cap +
//! pose, escalating through a "hands up" and "cap lift" reveal near
//! completion. Flavor text only, same spirit as `--redpill`, never a
//! substitute for the real percent/ETA/throughput numbers `LiveProgress`
//! itself renders.

const AGENCIES: [&str; 8] = ["CIA", "NSA", "FBI", "ATF", "WEF", "IRS", "MI6", "CNI"];

// A small/fast file can finish between two polls, jumping real
// percent straight from ~0% to 100% and skipping the hands-up/cap-lift
// bands entirely — this is what "you can't see the pepe hands" was.
// These three give each phase a minimum tick budget in `frame_for`'s
// cosmetic floor (below), purely for the animation; the bar's real
// percent/ETA/throughput are untouched. A slow file is unaffected:
// real percent already dominates the `.min()` in the poll loop long
// before the floor saturates.
const PARANOID_PHASE_TICKS: u64 = 3;
const HANDS_UP_PHASE_TICKS: u64 = 4;
const LIFT_CAP_PHASE_TICKS: u64 = 3;
pub const TOTAL_MIN_ANIMATION_TICKS: u64 = PARANOID_PHASE_TICKS + HANDS_UP_PHASE_TICKS + LIFT_CAP_PHASE_TICKS;

/// Cosmetic cap on `frame_for`'s phase selection — held at 0 during
/// the paranoid phase's minimum ticks, then pinned at 90 (hands-up) and
/// 96 (cap-lift) for their own minimum ticks, so those two narrow bands
/// always get displayed even if real progress already blew past them.
pub fn cosmetic_percent_cap(tick: u64) -> f64 {
    if tick < PARANOID_PHASE_TICKS {
        0.0
    } else if tick < PARANOID_PHASE_TICKS + HANDS_UP_PHASE_TICKS {
        90.0
    } else if tick < TOTAL_MIN_ANIMATION_TICKS {
        96.0
    } else {
        100.0
    }
}

/// Agency tag shown in the hands-up cap ASCII art — kept separate from
/// `nocap_crypt_ui::SATIRICAL_QUOTES` (picked independently, see
/// `LiveProgress::start`) because the tag has a real constraint the
/// quote doesn't: it has to be exactly 3 characters to drop into the
/// existing (verified) hands-up frame.
pub const HANDS_UP_TAGS: [&str; 2] = ["WEF", "NSA"];

/// Select the animation frame for the current real progress: below
/// 90% cycles the three paranoid poses (pose every 4 ticks, agency
/// every 15 — both purely cosmetic, driven by wall-clock ticks, not
/// real progress); 90-96% is the "hands up" reveal (fixed to this
/// run's randomly-chosen variant); 96-100% is the cap-lift; at 100%
/// the caller renders the ending separately via `LiveProgress::finish`.
pub fn frame_for(percent: f64, tick: u64, hands_up_tag: &str) -> String {
    if percent < 90.0 {
        let agency = AGENCIES[(tick as usize / 15) % AGENCIES.len()];
        match (tick / 4) % 3 {
            0 => paranoid_left(agency),
            1 => paranoid_right(agency),
            _ => suspicious(agency),
        }
    } else if percent < 96.0 {
        hands_up(hands_up_tag)
    } else {
        lift_cap()
    }
}

fn paranoid_left(agency: &str) -> String {
    format!(
        "\x1b[38;5;33m      _..----.._    \x1b[0m\n\
         \x1b[38;5;33m    .' [ \x1b[97m{agency:^3}\x1b[38;5;33m ]  '.  \x1b[0m\n\
         \x1b[38;5;33m   /____......____\\ \x1b[0m\n\
         \x1b[38;5;77m  /                \\ \x1b[0m\n\
         \x1b[38;5;77m |   \x1b[97m__\x1b[38;5;77m        \x1b[97m__\x1b[38;5;77m   |\x1b[0m\n\
         \x1b[38;5;77m |  \x1b[97m/  \\\x1b[38;5;77m      \x1b[97m/  \\\x1b[38;5;77m  |\x1b[0m\n\
         \x1b[38;5;244m(|\x1b[38;5;77m | \x1b[97mo  |\x1b[38;5;77m    \x1b[97m| o  |\x1b[38;5;77m |\x1b[38;5;244m)\x1b[0m\n\
         \x1b[38;5;77m |  \x1b[97m\\__/\x1b[38;5;77m      \x1b[97m\\__/\x1b[38;5;77m  |\x1b[0m\n\
         \x1b[38;5;77m |                  |\x1b[0m\n\
         \x1b[38;5;77m  \\  \x1b[38;5;196m_==========_\x1b[38;5;77m  / \x1b[0m\n\
         \x1b[38;5;77m   \\ \x1b[38;5;196m\\__________/\x1b[38;5;77m /  \x1b[0m\n\
         \x1b[38;5;77m    '------------'   \x1b[0m"
    )
}

fn paranoid_right(agency: &str) -> String {
    format!(
        "\x1b[38;5;33m      _..----.._    \x1b[0m\n\
         \x1b[38;5;33m    .' [ \x1b[97m{agency:^3}\x1b[38;5;33m ]  '.  \x1b[0m\n\
         \x1b[38;5;33m   /____......____\\ \x1b[0m\n\
         \x1b[38;5;77m  /                \\ \x1b[0m\n\
         \x1b[38;5;77m |   \x1b[97m__\x1b[38;5;77m        \x1b[97m__\x1b[38;5;77m   |\x1b[0m\n\
         \x1b[38;5;77m |  \x1b[97m/  \\\x1b[38;5;77m      \x1b[97m/  \\\x1b[38;5;77m  |\x1b[0m\n\
         \x1b[38;5;244m(|\x1b[38;5;77m | \x1b[97m o |\x1b[38;5;77m    \x1b[97m|  o |\x1b[38;5;77m |\x1b[38;5;244m)\x1b[0m\n\
         \x1b[38;5;77m |  \x1b[97m\\__/\x1b[38;5;77m      \x1b[97m\\__/\x1b[38;5;77m  |\x1b[0m\n\
         \x1b[38;5;77m |                  |\x1b[0m\n\
         \x1b[38;5;77m  \\  \x1b[38;5;196m_==========_\x1b[38;5;77m  / \x1b[0m\n\
         \x1b[38;5;77m   \\ \x1b[38;5;196m\\__________/\x1b[38;5;77m /  \x1b[0m\n\
         \x1b[38;5;77m    '------------'   \x1b[0m"
    )
}

fn suspicious(agency: &str) -> String {
    format!(
        "\x1b[38;5;33m      _..----.._    \x1b[0m\n\
         \x1b[38;5;33m    .' [ \x1b[97m{agency:^3}\x1b[38;5;33m ]  '.  \x1b[0m\n\
         \x1b[38;5;33m   /____......____\\ \x1b[0m\n\
         \x1b[38;5;77m  /                \\ \x1b[0m\n\
         \x1b[38;5;77m |   \x1b[97m__\x1b[38;5;77m        \x1b[97m__\x1b[38;5;77m   |\x1b[0m\n\
         \x1b[38;5;77m |  \x1b[97m/--\\\x1b[38;5;77m      \x1b[97m/--\\\x1b[38;5;77m  |\x1b[0m\n\
         \x1b[38;5;244m(|\x1b[38;5;77m | \x1b[97m - |\x1b[38;5;77m    \x1b[97m|  - |\x1b[38;5;77m |\x1b[38;5;244m)\x1b[0m\n\
         \x1b[38;5;77m |  \x1b[97m\\__/\x1b[38;5;77m      \x1b[97m\\__/\x1b[38;5;77m  |\x1b[0m\n\
         \x1b[38;5;77m |                  |\x1b[0m\n\
         \x1b[38;5;77m  \\  \x1b[38;5;196m_==========_\x1b[38;5;77m  / \x1b[0m\n\
         \x1b[38;5;77m   \\ \x1b[38;5;196m\\__________/\x1b[38;5;77m /  \x1b[0m\n\
         \x1b[38;5;77m    '------------'   \x1b[0m"
    )
}

fn hands_up(agency: &str) -> String {
    format!(
        "\x1b[38;5;33m      _..----.._    \x1b[0m\n\
         \x1b[38;5;33m    .' [ \x1b[97m{agency:^3}\x1b[38;5;33m ]  '.  \x1b[0m\n\
         \x1b[38;5;33m   /____......____\\ \x1b[0m\n\
         \x1b[38;5;77m  /                \\ \x1b[0m\n\
         \x1b[38;5;77m |   \x1b[97m__\x1b[38;5;77m        \x1b[97m__\x1b[38;5;77m   |\x1b[0m\n\
         \x1b[38;5;77m |  \x1b[97m/  \\\x1b[38;5;77m      \x1b[97m/  \\\x1b[38;5;77m  |\x1b[0m\n\
         \x1b[38;5;244m(|\x1b[38;5;77m | \x1b[97mO  |\x1b[38;5;77m    \x1b[97m| O  |\x1b[38;5;77m |\x1b[38;5;244m)\x1b[0m\n\
         \x1b[38;5;77m |  \x1b[97m\\__/\x1b[38;5;77m      \x1b[97m\\__/\x1b[38;5;77m  |\x1b[0m\n\
         \x1b[38;5;77m |  _            _  |\x1b[0m\n\
         \x1b[38;5;77m  \\/ \\\x1b[38;5;196m_========_\x1b[38;5;77m/ \\/ \x1b[0m\n\
         \x1b[38;5;77m  | m |\x1b[38;5;196m\\______/\x1b[38;5;77m| m |\x1b[0m\n\
         \x1b[38;5;77m  \\___/        \\___/ \x1b[0m"
    )
}

fn lift_cap() -> String {
    "\x1b[38;5;33m      _..----.._    \x1b[0m\n\
     \x1b[38;5;33m    .' [\x1b[97mNOCAP\x1b[38;5;33m]  '.  \x1b[0m\n\
     \x1b[38;5;33m   /____......____\\ \x1b[0m\n\
     \x1b[38;5;77m     | |      | |   \x1b[0m\n\
     \x1b[38;5;77m    /            \\  \x1b[0m\n\
     \x1b[38;5;77m   |   \x1b[97m__\x1b[38;5;77m      \x1b[97m__\x1b[38;5;77m | \x1b[0m\n\
     \x1b[38;5;77m   |  \x1b[97m/--\\\x1b[38;5;77m    \x1b[97m/--\\\x1b[38;5;77m| \x1b[0m\n\
     \x1b[38;5;244m  (|\x1b[38;5;77m | \x1b[97m-  |\x1b[38;5;77m  \x1b[97m| -  |\x1b[38;5;77m|\x1b[38;5;244m)\x1b[0m\n\
     \x1b[38;5;77m   |  \x1b[97m\\__/\x1b[38;5;77m    \x1b[97m\\__/\x1b[38;5;77m| \x1b[0m\n\
     \x1b[38;5;77m    \\   \x1b[38;5;196m_======_\x1b[38;5;77m  / \x1b[0m\n\
     \x1b[38;5;77m     \\__\x1b[38;5;196m\\______/\x1b[38;5;77m__/ \x1b[0m\n\
     \x1b[38;5;77m      (m)      (m)  \x1b[0m"
        .to_string()
}

/// [`super::FinalEnding::BareHead`]'s frame.
pub fn final_reveal() -> String {
    "\n\
     \x1b[38;5;77m       _.........._     \x1b[0m\n\
     \x1b[38;5;77m      /            \\    \x1b[0m\n\
     \x1b[38;5;77m     /              \\   \x1b[0m\n\
     \x1b[38;5;77m    |   \x1b[97m===\x1b[38;5;77m      \x1b[97m===\x1b[38;5;77m   |\x1b[0m\n\
     \x1b[38;5;77m    |  \x1b[97m( - )\x1b[38;5;77m    \x1b[97m( - )\x1b[38;5;77m  |\x1b[0m\n\
     \x1b[38;5;77m   (|                  |) \x1b[0m\n\
     \x1b[38;5;77m    |      \x1b[38;5;196m'----'\x1b[38;5;77m      |\x1b[0m\n\
     \x1b[38;5;33m _..----.._            \x1b[38;5;77m|\x1b[0m\n\
     \x1b[38;5;33m.' [\x1b[97mNOCAP\x1b[38;5;33m]  '.          \x1b[38;5;77m/\x1b[0m\n\
     \x1b[38;5;33m/____......____\\\x1b[38;5;77m________/ \x1b[0m\n\
     \x1b[38;5;77m      (m)               \x1b[0m"
        .to_string()
}

/// [`super::FinalEnding::TinfoilHat`]'s frame. Shares `final_reveal`'s
/// body (everything from the eyes down) — only the head/hat rows differ.
pub fn tinfoil_hat() -> String {
    "\n\
     \x1b[38;5;250m       _//\\_            \x1b[0m\n\
     \x1b[38;5;250m      /_____\\           \x1b[0m\n\
     \x1b[38;5;77m     /       \\          \x1b[0m\n\
     \x1b[38;5;77m    |   \x1b[97m===\x1b[38;5;77m      \x1b[97m===\x1b[38;5;77m   |\x1b[0m\n\
     \x1b[38;5;77m    |  \x1b[97m( - )\x1b[38;5;77m    \x1b[97m( - )\x1b[38;5;77m  |\x1b[0m\n\
     \x1b[38;5;77m   (|                  |) \x1b[0m\n\
     \x1b[38;5;77m    |      \x1b[38;5;196m'----'\x1b[38;5;77m      |\x1b[0m\n\
     \x1b[38;5;33m _..----.._            \x1b[38;5;77m|\x1b[0m\n\
     \x1b[38;5;33m.' [\x1b[97mRING0\x1b[38;5;33m]  '.          \x1b[38;5;77m/\x1b[0m\n\
     \x1b[38;5;33m/____......____\\\x1b[38;5;77m________/ \x1b[0m\n\
     \x1b[38;5;77m      (m)               \x1b[0m"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::strip_ansi;

    #[test]
    fn agency_is_centered_in_all_three_poses() {
        for frame in [paranoid_left("FBI"), paranoid_right("FBI"), suspicious("FBI")] {
            assert!(strip_ansi(&frame).contains("[ FBI ]"));
        }
    }

    #[test]
    fn all_agencies_are_exactly_three_chars() {
        for agency in AGENCIES {
            assert_eq!(agency.len(), 3, "agency {agency:?} is not 3 chars");
        }
    }

    #[test]
    fn all_hands_up_tags_are_exactly_three_chars() {
        for tag in HANDS_UP_TAGS {
            assert_eq!(tag.len(), 3, "hands-up tag {tag:?} is not 3 chars");
        }
    }

    #[test]
    fn below_90_percent_cycles_paranoid_poses() {
        let a = frame_for(10.0, 0, "WEF");
        let b = frame_for(10.0, 4, "WEF");
        let c = frame_for(10.0, 8, "WEF");
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
        assert_eq!(frame_for(10.0, 0, "WEF"), frame_for(10.0, 12, "WEF"));
    }

    #[test]
    fn ninety_to_ninety_six_percent_is_hands_up_with_correct_tag() {
        let frame = frame_for(93.0, 0, "NSA");
        assert!(strip_ansi(&frame).contains("[ NSA ]"));
    }

    #[test]
    fn ninety_six_to_hundred_percent_is_lift_cap() {
        assert_eq!(frame_for(97.0, 0, "WEF"), lift_cap());
        assert_eq!(frame_for(99.9, 0, "WEF"), lift_cap());
    }

    #[test]
    fn boundaries_land_in_the_expected_band() {
        assert_ne!(frame_for(89.9, 0, "WEF"), hands_up("WEF"));
        assert_eq!(frame_for(90.0, 0, "WEF"), hands_up("WEF"));
        assert_ne!(frame_for(95.9, 0, "WEF"), lift_cap());
        assert_eq!(frame_for(96.0, 0, "WEF"), lift_cap());
    }

    /// Regression test for a real UX bug: a small/fast file could
    /// finish between two polls, so real percent jumped ~0% -> 100%
    /// and `frame_for` never landed a frame in the hands-up (90-96%)
    /// or lift-cap (96-100%) bands at all — "you can't see the pepe
    /// hands." `cosmetic_percent_cap` gives each phase a minimum tick
    /// budget regardless of real progress.
    #[test]
    fn cosmetic_cap_visits_every_phase_even_when_real_progress_is_already_done() {
        let real_percent: f64 = 100.0; // as if the file finished instantly
        let mut saw_paranoid = false;
        let mut saw_hands_up = false;
        let mut saw_lift_cap = false;
        for tick in 0..TOTAL_MIN_ANIMATION_TICKS {
            let display = real_percent.min(cosmetic_percent_cap(tick));
            if display < 90.0 {
                saw_paranoid = true;
            } else if display < 96.0 {
                saw_hands_up = true;
            } else {
                saw_lift_cap = true;
            }
        }
        assert!(saw_paranoid, "paranoid phase never displayed");
        assert!(saw_hands_up, "hands-up phase never displayed");
        assert!(saw_lift_cap, "lift-cap phase never displayed");
    }

    #[test]
    fn cosmetic_cap_never_exceeds_real_progress_for_a_slow_file() {
        // A slow file must not have its animation rushed ahead of
        // real progress — the cap only holds the animation BACK, it
        // never pushes it forward past what's actually done.
        let real_percent: f64 = 30.0;
        for tick in 0..(TOTAL_MIN_ANIMATION_TICKS * 2) {
            let display = real_percent.min(cosmetic_percent_cap(tick));
            assert!(display <= real_percent);
        }
    }

    #[test]
    fn cosmetic_cap_saturates_at_100_after_the_minimum_ticks() {
        assert_eq!(cosmetic_percent_cap(TOTAL_MIN_ANIMATION_TICKS), 100.0);
        assert_eq!(cosmetic_percent_cap(TOTAL_MIN_ANIMATION_TICKS + 50), 100.0);
    }

    #[test]
    fn both_endings_contain_expected_markers() {
        assert!(strip_ansi(&final_reveal()).contains("NOCAP"));
        assert!(strip_ansi(&tinfoil_hat()).contains("RING0"));
    }

    /// Regression test for a real reported bug: `tinfoil_hat`'s
    /// face/ears/mouth/cap rows were narrower than `final_reveal`'s
    /// (a 3-space gap between the eyes instead of 6), so the hat drifted
    /// left of the head it's supposed to sit on. Both endings share the
    /// same head/face/cap body — only the top few rows (bare head vs.
    /// hat) should differ — so every row below the head-outline must be
    /// the same width in both, line for line.
    #[test]
    fn tinfoil_hat_body_is_the_same_width_as_final_reveal_body() {
        let final_stripped = strip_ansi(&final_reveal());
        let tinfoil_stripped = strip_ansi(&tinfoil_hat());
        let final_lines: Vec<&str> = final_stripped.lines().filter(|l| !l.is_empty()).collect();
        let tinfoil_lines: Vec<&str> = tinfoil_stripped.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(final_lines.len(), tinfoil_lines.len(), "endings have a different number of rows");

        // Rows 0-2 are the head-outline-vs-hat rows, allowed to differ
        // in shape; every row from the eyes down must match exactly.
        for (i, (f, t)) in final_lines.iter().zip(tinfoil_lines.iter()).enumerate().skip(3) {
            assert_eq!(
                f.chars().count(),
                t.chars().count(),
                "row {i} width mismatch: final_reveal={f:?} ({}), tinfoil_hat={t:?} ({})",
                f.chars().count(),
                t.chars().count()
            );
        }
    }

    #[test]
    fn agencies_list_includes_cni() {
        assert!(AGENCIES.contains(&"CNI"));
    }

    #[test]
    fn strip_ansi_removes_every_escape_in_a_full_frame() {
        for frame in [
            paranoid_left("CIA"),
            paranoid_right("CIA"),
            suspicious("CIA"),
            hands_up("WEF"),
            lift_cap(),
            final_reveal(),
            tinfoil_hat(),
        ] {
            assert!(!strip_ansi(&frame).contains('\u{1b}'));
        }
    }
}
