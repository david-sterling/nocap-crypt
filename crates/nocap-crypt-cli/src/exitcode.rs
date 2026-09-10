//! Fixed, documented exit codes — the silent-mode contract CI depends
//! on. Covered by `exit_codes_are_stable` below as the golden test.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Success = 0,
    /// Reserved for a generic/unanticipated failure path (e.g. a future
    /// top-level panic handler) — no subcommand returns this yet since
    /// every current failure mode maps to a more specific code below.
    #[allow(dead_code)]
    Generic = 1,
    InvalidArgs = 2,
    KeyValidation = 3,
    EntropyFailed = 4,
    AlignmentFailed = 5,
    LuksCompat = 6,
    Io = 7,
    UnsupportedCipher = 8,
}

impl ExitCode {
    pub fn code(self) -> i32 {
        self as i32
    }

    /// Stable, grep-able tag for `--ci` mode's final outcome line/JSON
    /// event — e.g. `grep 'NC-003'` in a CI log reliably finds "key
    /// validation failed" runs, without depending on parsing the
    /// process exit code back out of whatever wrapper script invoked
    /// this tool. One-to-one with the exit code integer (zero-padded
    /// to 3 digits) precisely because the exit code contract itself is
    /// already documented and tested as stable (`exit_codes_are_stable`
    /// below) — this is a second, textual view of the same guarantee,
    /// not a separate one to keep in sync by hand.
    pub fn error_code(self) -> String {
        format!("NC-{:03}", self.code())
    }

    /// Short human label for the same outcome, used as the `--ci`
    /// banner's detail text (e.g. "FAILURE [NC-003] — key validation
    /// failed").
    pub fn outcome_label(self) -> &'static str {
        match self {
            ExitCode::Success => "completed successfully",
            ExitCode::Generic => "failed",
            ExitCode::InvalidArgs => "invalid arguments",
            ExitCode::KeyValidation => "key validation failed",
            ExitCode::EntropyFailed => "entropy check failed",
            ExitCode::AlignmentFailed => "alignment check failed",
            ExitCode::LuksCompat => "LUKS/dm-crypt compatibility check failed",
            ExitCode::Io => "I/O error",
            ExitCode::UnsupportedCipher => "unsupported cipher or key length mismatch",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(ExitCode::Success.code(), 0);
        assert_eq!(ExitCode::Generic.code(), 1);
        assert_eq!(ExitCode::InvalidArgs.code(), 2);
        assert_eq!(ExitCode::KeyValidation.code(), 3);
        assert_eq!(ExitCode::EntropyFailed.code(), 4);
        assert_eq!(ExitCode::AlignmentFailed.code(), 5);
        assert_eq!(ExitCode::LuksCompat.code(), 6);
        assert_eq!(ExitCode::Io.code(), 7);
        assert_eq!(ExitCode::UnsupportedCipher.code(), 8);
    }

    #[test]
    fn error_code_is_zero_padded_and_matches_exit_code() {
        assert_eq!(ExitCode::Success.error_code(), "NC-000");
        assert_eq!(ExitCode::KeyValidation.error_code(), "NC-003");
        assert_eq!(ExitCode::UnsupportedCipher.error_code(), "NC-008");
    }

    #[test]
    fn every_variant_has_a_nonempty_outcome_label() {
        for variant in [
            ExitCode::Success,
            ExitCode::Generic,
            ExitCode::InvalidArgs,
            ExitCode::KeyValidation,
            ExitCode::EntropyFailed,
            ExitCode::AlignmentFailed,
            ExitCode::LuksCompat,
            ExitCode::Io,
            ExitCode::UnsupportedCipher,
        ] {
            assert!(!variant.outcome_label().is_empty());
        }
    }
}
