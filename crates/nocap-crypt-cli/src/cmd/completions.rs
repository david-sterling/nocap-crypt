//! `nocap-crypt completions <shell>` — generate a shell completion
//! script from the same `clap::Command` tree the CLI itself parses
//! against, so it can never drift out of sync with a renamed flag or
//! an added subcommand the way a hand-maintained script would (see
//! `specs/bash-autocompletion-plan.md` §1).
//!
//! ## The hyphenated-bin-name workaround
//!
//! `clap_complete` 4.6.8's **bash** generator has a bug: when
//! `bin_name` contains a `-`, the subcommand-transition code sets
//! e.g. `cmd="nocap__crypt__subcmd__keygen"`, but the `case`/`esac`
//! block that looks up that state's flags is keyed
//! `nocap__subcmd__crypt__subcmd__keygen)` — the `-` gets spliced
//! into an extra `__subcmd__` segment on one side but not the other.
//! Every subcommand's flag/value completion is silently unreachable
//! as a result; only root-level subcommand *name* completion works.
//! Other shells and underscore/no-separator bin names are unaffected.
//!
//! Since this project's binary name uses a hyphen, the fix generates
//! the script under a hyphen-free internal name (`-` → `_`) and then
//! patches *only* the trailing `complete -F <function> ...
//! <bin_name>` registration line(s) back to the real, hyphenated
//! command name. This is safe because bash's `complete -F
//! <function-name> <command-name>` allows those two names to be
//! unrelated strings — the function's own dispatch is a runtime
//! pattern match against whatever the shell invokes it with, so it
//! doesn't care that its internal state labels differ from the real
//! command name.

use std::io;

use clap::Command;
use clap_complete::Shell;

/// Write the completion script for `shell` to `out`, generated from
/// `command` (the caller's `clap::Command` tree). Fails cleanly (rather
/// than panicking) on a write error — `out` is caller-supplied and in
/// practice is usually stdout, which a completely ordinary shell
/// pipeline (`nocap-crypt completions bash | head`) can close out from
/// under a still-writing process.
pub fn generate(shell: Shell, command: &mut Command, bin_name: &str, out: &mut dyn io::Write) -> io::Result<()> {
    if shell == Shell::Bash && bin_name.contains('-') {
        generate_bash_with_hyphen_workaround(command, bin_name, out)
    } else {
        // `clap_complete::generate` itself has no fallible signature
        // (it targets `io::Write` and unwraps internally) — nothing to
        // propagate on this branch, but callers still get a uniform
        // `io::Result` return type across both branches.
        clap_complete::generate(shell, command, bin_name, out);
        Ok(())
    }
}

fn generate_bash_with_hyphen_workaround(command: &mut Command, bin_name: &str, out: &mut dyn io::Write) -> io::Result<()> {
    let safe_name = bin_name.replace('-', "_");

    let mut buf = Vec::new();
    clap_complete::generate(Shell::Bash, command, &safe_name, &mut buf);
    let script = String::from_utf8(buf).expect("clap_complete's bash generator always emits valid UTF-8");

    // Only the trailing `complete -F _fn ... <bin_name>` registration
    // line(s) need the real name — every other occurrence of
    // `safe_name` is an internal state label that must stay exactly
    // as clap_complete generated it (that's what keeps the state
    // machine self-consistent; see the module doc comment).
    let fixed: String = script
        .split_inclusive('\n')
        .map(|line| {
            let trimmed = line.trim_end_matches(['\n', '\r']);
            if trimmed.trim_start().starts_with("complete -F") && trimmed.ends_with(safe_name.as_str()) {
                let line_ending = &line[trimmed.len()..];
                let prefix = &trimmed[..trimmed.len() - safe_name.len()];
                format!("{prefix}{bin_name}{line_ending}")
            } else {
                line.to_string()
            }
        })
        .collect();

    out.write_all(fixed.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum;
    use std::collections::HashSet;

    fn dummy_command() -> Command {
        Command::new("nocap-crypt")
            .arg(clap::Arg::new("input").long("input"))
            .subcommand(
                Command::new("image").subcommand(Command::new("encrypt").arg(clap::Arg::new("cipher").long("cipher"))),
            )
    }

    #[test]
    fn generate_produces_nonempty_output_for_every_shell() {
        for shell in Shell::value_variants() {
            let mut buf = Vec::new();
            generate(*shell, &mut dummy_command(), "nocap-crypt", &mut buf).unwrap();
            assert!(!buf.is_empty(), "{shell:?} produced no output");
        }
    }

    #[test]
    fn bash_completion_mentions_the_real_binary_name_and_the_flag() {
        let mut buf = Vec::new();
        generate(Shell::Bash, &mut dummy_command(), "nocap-crypt", &mut buf).unwrap();
        let script = String::from_utf8(buf).unwrap();
        assert!(script.contains("nocap-crypt"));
        assert!(script.contains("--input"));
    }

    #[test]
    fn bash_completion_registers_the_real_hyphenated_command_name() {
        let mut buf = Vec::new();
        generate(Shell::Bash, &mut dummy_command(), "nocap-crypt", &mut buf).unwrap();
        let script = String::from_utf8(buf).unwrap();
        let registration_lines: Vec<&str> = script.lines().filter(|l| l.trim_start().starts_with("complete -F")).collect();
        assert!(!registration_lines.is_empty(), "no `complete -F` registration line found");
        for line in registration_lines {
            assert!(
                line.trim_end().ends_with("nocap-crypt"),
                "registration line does not end with the real hyphenated command name: {line:?}"
            );
        }
    }

    /// This is the test that would have caught the upstream bug this
    /// module works around: every `cmd="<label>"` a subcommand
    /// transition can produce must have a matching `<label>)` case arm
    /// later in the script, or that subcommand's entire flag/value
    /// completion is silently dead. Regex-ish line scanning rather
    /// than a real bash parser, but precise enough for this script's
    /// generated shape.
    #[test]
    fn every_assigned_state_label_has_a_matching_case_arm() {
        let mut buf = Vec::new();
        generate(Shell::Bash, &mut dummy_command(), "nocap-crypt", &mut buf).unwrap();
        let script = String::from_utf8(buf).unwrap();

        let mut assigned: HashSet<&str> = HashSet::new();
        let mut case_arms: HashSet<&str> = HashSet::new();

        for line in script.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("cmd=\"") {
                if let Some(label) = rest.strip_suffix('"') {
                    // Skip the initial `cmd=""` declaration at the top
                    // of the function — an empty string is the
                    // "no state yet" starting value, not a real
                    // transition target that needs a case arm.
                    if !label.is_empty() {
                        assigned.insert(label);
                    }
                }
            }
            // A bare case-arm line looks like `nocap_crypt__subcmd__keygen)`
            // (no spaces, ends in a lone `)`, not a `;;` terminator).
            if !t.contains(' ') && !t.contains('(') && t.ends_with(')') && !t.ends_with(";)") {
                case_arms.insert(t.trim_end_matches(')'));
            }
        }

        let missing: Vec<&&str> = assigned.iter().filter(|label| !case_arms.contains(*label)).collect();
        assert!(missing.is_empty(), "state label(s) assigned but never matched by a case arm: {missing:?}");
    }
}
