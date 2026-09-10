//! `nocap-crypt validate` — "will this work as a LUKS/dm-crypt volume".
//! Primary target is headerless *plain* dm-crypt (structural check,
//! always run); with `--key-file`, additionally attempts a dry-run
//! decrypt of the first sectors and checks for a plausible filesystem
//! superblock magic — the strongest practical signal that
//! key+cipher+IV scheme are all correct together, short of an actual
//! `cryptsetup open`.

use std::path::PathBuf;

use clap::{Args, ValueHint};
use nocap_crypt_blockio::SectorFile;
use nocap_crypt_core::SectorEngine;
use nocap_crypt_ui::{Event, Reporter};

use crate::exitcode::ExitCode;
use crate::keyload::{load_key_file, resolve_cipher_spec, CipherArg, KeyFormatArg};

#[derive(Args, Debug)]
pub struct ValidateArgs {
    #[arg(value_hint = ValueHint::FilePath)]
    pub input: PathBuf,
    #[arg(long, value_enum, default_value = "aes-xts-plain64")]
    pub cipher: CipherArg,
    #[arg(long)]
    pub key_size: Option<u16>,
    #[arg(long, value_hint = ValueHint::FilePath)]
    pub key_file: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "auto")]
    pub key_format: KeyFormatArg,
}

const SECTOR_SIZE: u64 = nocap_crypt_core::SECTOR_SIZE as u64;

fn detect_fs_magic(data: &[u8]) -> Option<&'static str> {
    if data.len() >= 4 && &data[0..4] == b"hsqs" {
        return Some("squashfs");
    }
    if data.len() >= 0x438 + 2 {
        let magic = u16::from_le_bytes([data[0x438], data[0x438 + 1]]);
        if magic == 0xEF53 {
            return Some("ext2/ext3/ext4");
        }
    }
    None
}

pub fn run(args: &ValidateArgs, reporter: &dyn Reporter) -> ExitCode {
    if reporter.narrates() {
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_headerless_plain(),
        });
    }

    let file_size = match std::fs::metadata(&args.input) {
        Ok(m) => m.len(),
        Err(e) => {
            reporter.report(Event::Error {
                text: format!("stat {}: {e}", args.input.display()),
            });
            return ExitCode::Io;
        }
    };

    let spec = match resolve_cipher_spec(args.cipher, args.key_size) {
        Ok(s) => s,
        Err(e) => {
            reporter.report(Event::Error { text: e.to_string() });
            return ExitCode::UnsupportedCipher;
        }
    };

    let spec_str = spec.as_str();
    let structural = nocap_crypt_luks::validate_plain_structural(file_size, &spec_str);
    let size_note = if structural.size_is_sector_multiple {
        format!(
            "file size {file_size} bytes is a whole multiple of the {SECTOR_SIZE}-byte sector \
             size (required: headerless plain dm-crypt has no header to record a partial \
             trailing sector, so the file itself has to land exactly on a sector boundary)"
        )
    } else {
        format!(
            "file size {file_size} bytes is NOT a whole multiple of the {SECTOR_SIZE}-byte \
             sector size ({} leftover byte{}) — this can't be a valid plain dm-crypt volume",
            file_size % SECTOR_SIZE,
            if file_size % SECTOR_SIZE == 1 { "" } else { "s" }
        )
    };
    let cipher_note = if structural.cipher_spec_round_trips {
        format!(
            "cipher spec \"{spec_str}\" is recognized and round-trips through the same parser \
             this tool would use to mount it — matches what real cryptsetup accepts"
        )
    } else {
        format!("cipher spec \"{spec_str}\" was not recognized by the plain dm-crypt cipher-spec parser")
    };
    reporter.report(Event::Message {
        text: format!("structural check: {size_note}; {cipher_note}"),
    });
    if !structural.passes() {
        reporter.report(Event::Error {
            text: "structural validation failed".to_string(),
        });
        return ExitCode::LuksCompat;
    }

    let Some(key_path) = &args.key_file else {
        return ExitCode::Success;
    };

    let key = match load_key_file(key_path, args.key_format) {
        Ok(k) => k,
        Err(e) => {
            reporter.report(Event::Error { text: e.to_string() });
            return ExitCode::Io;
        }
    };
    let engine = match SectorEngine::new(spec, &key) {
        Ok(e) => e,
        Err(e) => {
            reporter.report(Event::Error { text: e.to_string() });
            return ExitCode::KeyValidation;
        }
    };

    let head_sectors = (file_size / SECTOR_SIZE).min(8);
    if head_sectors == 0 {
        reporter.report(Event::Message {
            text: "round-trip check skipped: file too short for even one sector".to_string(),
        });
        return ExitCode::Success;
    }

    let sf = match SectorFile::open_read(&args.input) {
        Ok(f) => f,
        Err(e) => {
            reporter.report(Event::Error { text: e.to_string() });
            return ExitCode::Io;
        }
    };
    let mut head = vec![0u8; (head_sectors * SECTOR_SIZE) as usize];
    if let Err(e) = sf.read_at_exact(0, &mut head) {
        reporter.report(Event::Error { text: e.to_string() });
        return ExitCode::Io;
    }
    engine.decrypt_range(0, &mut head);

    match detect_fs_magic(&head) {
        Some(fs) => {
            reporter.report(Event::Message {
                text: format!("round-trip check: detected {fs} superblock magic — key+cipher+IV scheme consistent"),
            });
            ExitCode::Success
        }
        None => {
            reporter.report(Event::Error {
                text: "round-trip check: no known filesystem magic detected at expected offsets".to_string(),
            });
            ExitCode::LuksCompat
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("nocap-crypt-cli-validate-test-{}-{}", std::process::id(), name))
    }

    struct RecordingReporter {
        events: std::sync::Mutex<Vec<Event>>,
    }

    impl Reporter for RecordingReporter {
        fn report(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }
    }

    fn args_for(input: PathBuf) -> ValidateArgs {
        ValidateArgs {
            input,
            cipher: CipherArg::AesXtsPlain64,
            key_size: None,
            key_file: None,
            key_format: KeyFormatArg::Auto,
        }
    }

    /// The structural-check message used to just dump two raw booleans
    /// (`size_is_sector_multiple=true cipher_spec_round_trips=true`)
    /// with no indication of what was actually checked or why it
    /// matters — this pins the fix: real numbers and plain-English
    /// rationale, for the passing case.
    #[test]
    fn structural_message_names_the_real_size_and_explains_why_sector_alignment_matters() {
        let path = temp_path("aligned.img");
        std::fs::write(&path, vec![0u8; 1024]).unwrap();

        let reporter = RecordingReporter {
            events: std::sync::Mutex::new(Vec::new()),
        };
        let exit = run(&args_for(path.clone()), &reporter);
        assert_eq!(exit, ExitCode::Success);

        let events = reporter.events.lock().unwrap();
        let text = events
            .iter()
            .find_map(|e| match e {
                Event::Message { text } if text.starts_with("structural check:") => Some(text.clone()),
                _ => None,
            })
            .expect("expected a structural check message");

        assert!(text.contains("1024 bytes"), "should name the real file size: {text:?}");
        assert!(text.contains("512-byte sector"), "should name the real sector size: {text:?}");
        assert!(text.contains("whole multiple"), "should say what the check actually verified: {text:?}");
        assert!(
            text.contains("headerless plain dm-crypt has no header"),
            "should explain why this check exists, not just report the boolean: {text:?}"
        );
        assert!(text.contains("aes-xts-plain64"), "should name the actual cipher spec checked: {text:?}");

        std::fs::remove_file(&path).ok();
    }

    /// Same fix, failing case: the leftover-byte count and the reason
    /// it fails should both be visible, not just `=false`.
    #[test]
    fn structural_message_reports_the_leftover_byte_count_on_misalignment() {
        let path = temp_path("misaligned.img");
        std::fs::write(&path, vec![0u8; 513]).unwrap();

        let reporter = RecordingReporter {
            events: std::sync::Mutex::new(Vec::new()),
        };
        let exit = run(&args_for(path.clone()), &reporter);
        assert_eq!(exit, ExitCode::LuksCompat);

        let events = reporter.events.lock().unwrap();
        let text = events
            .iter()
            .find_map(|e| match e {
                Event::Message { text } if text.starts_with("structural check:") => Some(text.clone()),
                _ => None,
            })
            .expect("expected a structural check message");

        assert!(text.contains("513 bytes"), "should name the real file size: {text:?}");
        assert!(text.contains("NOT a whole multiple"), "should say the check failed, not just print false: {text:?}");
        assert!(text.contains("1 leftover byte"), "should name the actual remainder: {text:?}");
        assert!(!text.contains("1 leftover bytes"), "singular remainder should not pluralize: {text:?}");

        std::fs::remove_file(&path).ok();
    }
}
