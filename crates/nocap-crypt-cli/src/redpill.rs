//! `--redpill`: purely cosmetic easter egg, no bearing on real behavior.
//! Interactive pill choice per the marketing spec — blue pill mocks the
//! kernel-privileged path, red pill runs a short fake hardware
//! animation. The "STATE MATRIX" bytes below are static/synthetic, same
//! principle as `nocap-crypt-ui::sbox`'s demo byte: illustrative
//! only, never real key/plaintext material.

use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

use crate::exitcode::ExitCode;

const INTRO: &str = r#"
                         ___
                        /o=o\
                       | (.) |            THEY LIVE, WE SLEEP
                        \_-_/
                         | |
                   ______|_|______
                  /       |       \
                 |  RED   |  BLUE  |
                 | ▓▓▓▓▓▓ | ░░░░░░ |
                 | ▓▓▓▓▓▓ | ░░░░░░ |
                  \_______|_______/
                 RED: unprivileged userspace (nocap-crypt)
                 BLUE: bloated kernel space (cryptsetup)

THE RING 0 CABAL HAS LIED TO YOU.

For years, the Linux Kernel told you that you needed them.
They said you needed --privileged.
They said you needed CAP_SYS_ADMIN.
They forced your CI/CD pipelines to bow to dm-crypt.

It was a psyop to keep your containers bloated and your permissions vulnerable.
Kernel-space cryptography is a Deep State bureaucracy.

We don't need their permissions.
We have hardware acceleration. We have userspace. We have the math.
Where We Encrypt One, We Encrypt All.

        [ thread archived — powered by 4chan.org/g/ — anonymous ]
"#;

const BLUE_PILL: &str = r#"
[!] INITIATING LEGACY BLUE PILL PROTOCOL...
[ FATAL ] Missing capability: CAP_SYS_ADMIN
[ FATAL ] Device mapper (dm-crypt) denied access.

Enjoy your privileged containers, wage cage anon.
"#;

const MATRIX_ROWS: [&str; 4] = ["4A  F1  8C", "B3  77  1E", "00  CA  3F", "A8  9B  D4"];
const FRAME_PERCENTS: [u32; 5] = [20, 45, 68, 92, 100];
const BAR_WIDTH: usize = 30;

/// Runs the interactive redpill flow (silently a no-op under `-q`, per
/// the same silent-mode contract every other subcommand honors) and
/// returns the exit code to use.
pub fn run(quiet: bool) -> ExitCode {
    if quiet {
        return ExitCode::Success;
    }

    println!("{INTRO}");
    print!("pick your architecture [r/b]: ");
    let _ = io::stdout().flush();

    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
    let choice = input
        .trim()
        .chars()
        .next()
        .unwrap_or('r')
        .to_ascii_lowercase();

    if choice == 'b' {
        println!("{BLUE_PILL}");
        ExitCode::Generic
    } else {
        run_red_pill_animation();
        ExitCode::Success
    }
}

fn run_red_pill_animation() {
    clear_screen();
    println!("[\u{2713}] SWALLOWING RED PILL...");
    sleep(Duration::from_millis(250));
    println!("[\u{2713}] RING 0 BYPASSED. USERSPACE LIBERATED.");
    sleep(Duration::from_millis(250));
    println!("[\u{2713}] ENGAGING AES-NI HARDWARE ACCELERATION...");
    sleep(Duration::from_millis(250));

    for &pct in &FRAME_PERCENTS {
        clear_screen();
        println!("  STATE MATRIX         ENCRYPTING: /build/firmware.ext4");
        println!(" \u{250c}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2510}");
        for row in MATRIX_ROWS {
            println!(" \u{2502} {row}  \u{2502}");
        }
        println!(" \u{2514}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2518}");
        let filled = (pct as usize * BAR_WIDTH) / 100;
        let bar: String = "\u{2588}".repeat(filled) + &"\u{2591}".repeat(BAR_WIDTH - filled);
        println!("      {bar} {pct}%");
        let _ = io::stdout().flush();
        sleep(Duration::from_millis(180));
    }

    println!();
    println!("[\u{2713}] ENCRYPTION COMPLETE. Trust The Cipher.");
}

fn clear_screen() {
    print!("\x1B[2J\x1B[H");
    let _ = io::stdout().flush();
}
