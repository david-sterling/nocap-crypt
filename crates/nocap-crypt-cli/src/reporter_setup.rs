//! Reporter selection from global flags. Precedence: `-q` (silent-mode
//! contract, unconditional) > `--ci` (operationally serious — CI logs
//! shouldn't get jokes or an easter egg mixed in unpredictably) >
//! `--governance` (boss key, kills all the meme UI) > `--didactic` >
//! `-v` > default — each wins over everything listed after it if
//! combined, fail-safe so a script that forgets to strip flags doesn't
//! suddenly get chatty/decorated output mixed into a parsed stream.

use nocap_crypt_ui::{Ci, Corporate, Didactic, Reporter, Silent, Verbose};

pub fn build_reporter(
    quiet: bool,
    ci: bool,
    governance: bool,
    verbose: bool,
    didactic: bool,
    json: bool,
    no_color: bool,
) -> Box<dyn Reporter> {
    if quiet {
        Box::new(Silent)
    } else if ci {
        Box::new(Ci { json, no_color })
    } else if governance {
        Box::new(Corporate { json })
    } else if didactic {
        Box::new(Didactic { json })
    } else if verbose {
        Box::new(Verbose { json })
    } else {
        // No flag given: default to informative human output, same as
        // `-v`, for a sensible interactive default.
        Box::new(Verbose { json })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_wins_over_everything() {
        let r = build_reporter(true, true, true, true, true, false, false);
        assert!(!r.narrates());
        assert_eq!(r.boot_banner(), None);
        assert!(!r.ci_mode());
    }

    #[test]
    fn ci_wins_over_governance_didactic_and_verbose() {
        let r = build_reporter(false, true, true, true, true, false, false);
        assert!(r.ci_mode());
        assert!(r.corporate_joke().is_none());
        assert!(!r.narrates());
    }

    #[test]
    fn governance_wins_over_didactic_and_verbose() {
        let r = build_reporter(false, false, true, true, true, false, false);
        assert!(r.corporate_joke().is_some());
        assert!(!r.narrates());
        assert!(!r.ci_mode());
    }

    #[test]
    fn didactic_takes_priority_over_verbose() {
        let r = build_reporter(false, false, false, true, true, false, false);
        assert!(r.narrates());
    }

    #[test]
    fn default_is_informative() {
        let r = build_reporter(false, false, false, false, false, false, false);
        assert!(!r.narrates());
        assert!(r.corporate_joke().is_none());
        assert!(!r.ci_mode());
    }
}
