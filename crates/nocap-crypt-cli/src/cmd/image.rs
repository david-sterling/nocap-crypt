//! `nocap-crypt image encrypt`/`decrypt` — the first vertical slice:
//! parity with the bash `encrypt_fs_image()` function this tool
//! replaces (see Rust Architecture Plan §1).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use clap::{Args, ValueHint};
use nocap_crypt_blockio::{create_sparse_output, SectorFile};
use nocap_crypt_core::{plain64_iv, CipherSpec, SectorEngine};
use nocap_crypt_ui::{Event, ProgressFlavor, Reporter};
use nocap_crypt_worker::{
    chunk_ranges, compute_system_info, process_ranges, resolve_concurrency, Concurrency, DispatchInfo, SectorRange,
    DEFAULT_SMALL_FILE_THRESHOLD_BYTES,
};

use crate::ci_progress;
use crate::cryptsetup_compat;
use crate::exitcode::ExitCode;
use crate::keyload::{load_key_file, resolve_cipher_spec, CipherArg, KeyFormatArg};
use crate::progress::LiveProgress;

/// Everything `dispatch_with_progress`/`transfer_and_report_timing`
/// need to run one transfer, grouped into named fields instead of a
/// long positional parameter list of same-typed values. `Copy` since
/// every field is either a reference or an already-`Copy` scalar/enum.
///
/// `real_data_len` is the true input length, used to clamp reads;
/// `progress_total_bytes` is the full byte count `ranges` covers
/// (which for encrypt includes alignment padding) and drives the
/// progress bar/throughput numbers. They differ whenever alignment
/// padding is in play, so they're kept as two fields rather than one.
#[derive(Clone, Copy)]
struct TransferJob<'a> {
    input_file: &'a SectorFile,
    output_file: &'a SectorFile,
    engine: &'a SectorEngine,
    ranges: &'a [SectorRange],
    real_data_len: u64,
    progress_total_bytes: u64,
    concurrency: Concurrency,
    encrypt: bool,
}

/// Dispatch `process_ranges` with the progress display matching
/// `reporter`'s mode: `--ci` gets periodic `Event::Progress` lines
/// from a `std::thread::scope`-spawned worker (real work happens on a
/// scoped thread so `reporter` never needs to be `'static`/`Arc`'d —
/// the calling thread just polls the shared counter while it waits);
/// every other mode gets the interactive `LiveProgress` bar unchanged.
fn dispatch_with_progress(
    reporter: &dyn Reporter,
    job: TransferJob,
    context: String,
    show_progress: bool,
    no_color: bool,
) -> io::Result<()> {
    if reporter.ci_mode() {
        let counter = AtomicU64::new(0);
        std::thread::scope(|s| {
            let handle = s.spawn(|| {
                process_ranges(
                    job.input_file,
                    job.output_file,
                    job.engine,
                    job.ranges,
                    job.real_data_len,
                    job.concurrency,
                    job.encrypt,
                    Some(&counter),
                )
            });
            ci_progress::run(reporter, &counter, job.progress_total_bytes, || handle.is_finished());
            handle.join().expect("worker thread panicked")
        })
    } else {
        let progress = LiveProgress::start(job.progress_total_bytes, context, show_progress, reporter.progress_flavor(), no_color);
        let progress_counter: Option<&AtomicU64> = progress.as_ref().map(|p| p.counter().as_ref());
        let result = process_ranges(
            job.input_file,
            job.output_file,
            job.engine,
            job.ranges,
            job.real_data_len,
            job.concurrency,
            job.encrypt,
            progress_counter,
        );
        if let Some(p) = progress {
            p.finish();
        }
        result
    }
}

/// The progress bar's ALGORITHM/technical line. Under
/// [`ProgressFlavor::Didactic`], this is the one place a PhD-level
/// reader gets the real config (concurrency mode, hardware path, chunk
/// size) pinned next to the bar for the whole run, rather than
/// scrolled out of view above it; every other flavor keeps the
/// existing terse `"encrypt / cipher"` label.
fn progress_context(
    reporter: &dyn Reporter,
    op: &str,
    spec: &CipherSpec,
    concurrency: Concurrency,
    chunk_sectors: u64,
    hw_description: Option<&str>,
) -> String {
    if reporter.progress_flavor() != ProgressFlavor::Didactic {
        return format!("{op} / {}", spec.as_str());
    }
    let hw = hw_description.map(|d| format!(" | hw: {d}")).unwrap_or_default();
    format!(
        "{} (AES-{}) | concurrency: {concurrency:?}{hw} | chunk: {chunk_sectors} sectors",
        spec.as_str(),
        spec.aes_bits.bits()
    )
}

#[derive(Args, Debug)]
pub struct EncryptArgs {
    /// Plaintext image or device to encrypt — typically a squashfs/ext4
    /// image built by `mksquashfs`/`mkfs`, or any raw file/block device.
    #[arg(long, value_hint = ValueHint::FilePath)]
    pub input: PathBuf,
    /// Destination ciphertext container. This is the file you'd later
    /// mount for real with `cryptsetup open --type plain --cipher
    /// <cipher> --key-size <bits> <output> <volume-name>` (see
    /// `nocap-crypt validate` to check it before you try).
    #[arg(long, value_hint = ValueHint::AnyPath)]
    pub output: PathBuf,
    /// Key material file (raw/hex/base64, see --key-format).
    #[arg(long, value_hint = ValueHint::FilePath)]
    pub key_file: PathBuf,
    #[arg(long, value_enum, default_value = "auto")]
    pub key_format: KeyFormatArg,
    #[arg(long, value_enum, default_value = "aes-xts-plain64")]
    pub cipher: CipherArg,
    /// AES key size in bits (128/256 for XTS, 256 for CBC-ESSIV).
    /// Defaults to the cipher's own default (256 -> 64-byte XTS key,
    /// matching cryptsetup's default).
    #[arg(long)]
    pub key_size: Option<u16>,
    #[arg(long, default_value_t = 4096)]
    pub align_block_size: u64,
    #[arg(long, default_value_t = 1)]
    pub align_extra_block: u64,
    /// Explicit worker-count override (opt-in deviation from the
    /// default: rayon's own unmodified global pool, modeled on
    /// dm-crypt's auto-balanced unbound workqueue). Omit for the
    /// default.
    #[arg(long)]
    pub max_workers: Option<usize>,
    /// Below this input size, skip pooled dispatch entirely and
    /// encrypt synchronously on the calling thread — mirrors
    /// dm-crypt's `no_read_workqueue`/`no_write_workqueue`, where
    /// dispatch overhead can exceed the crypto cost on fast paths.
    #[arg(long, default_value_t = DEFAULT_SMALL_FILE_THRESHOLD_BYTES)]
    pub small_file_threshold: u64,
    /// Process everything on the calling thread, unconditionally —
    /// mirrors dm-crypt's `samecpucrypt`. Useful for a reproducible
    /// single-threaded baseline, not normal use.
    #[arg(long, default_value_t = false)]
    pub pin_to_submission_thread: bool,
    /// Shell out to real `cryptsetup` (if present on PATH) to encrypt
    /// a small fixture with the same key/cipher and diff outputs — the
    /// project's core CI gate. Needs Linux + dm-crypt + loop devices
    /// plus root/CAP_SYS_ADMIN (see `specs/fips_check.md` Tier 4); on
    /// any other platform, or without cryptsetup/privilege available,
    /// the check is reported as skipped rather than failed. Only an
    /// actual ciphertext mismatch fails the run.
    #[arg(long, default_value_t = false)]
    pub dry_run_cryptsetup_compat: bool,
}

#[derive(Args, Debug)]
pub struct DecryptArgs {
    /// Ciphertext container to decrypt — either one this tool produced,
    /// or any real headerless `plain` dm-crypt volume with a matching
    /// cipher spec and key.
    #[arg(long, value_hint = ValueHint::FilePath)]
    pub input: PathBuf,
    /// Destination for the recovered plaintext image.
    #[arg(long, value_hint = ValueHint::AnyPath)]
    pub output: PathBuf,
    /// Key material file (raw/hex/base64, see --key-format).
    #[arg(long, value_hint = ValueHint::FilePath)]
    pub key_file: PathBuf,
    #[arg(long, value_enum, default_value = "auto")]
    pub key_format: KeyFormatArg,
    #[arg(long, value_enum, default_value = "aes-xts-plain64")]
    pub cipher: CipherArg,
    #[arg(long)]
    pub key_size: Option<u16>,
    #[arg(long)]
    pub max_workers: Option<usize>,
    #[arg(long, default_value_t = DEFAULT_SMALL_FILE_THRESHOLD_BYTES)]
    pub small_file_threshold: u64,
    #[arg(long, default_value_t = false)]
    pub pin_to_submission_thread: bool,
}

// --- Shared encrypt/decrypt preamble -----------------------------------
//
// The steps below are identical between `run_encrypt`/`run_decrypt`
// (spec/key resolution, engine construction, concurrency resolution,
// file open/create, sample-IV narration, dispatch+timing). What stays
// inline in each function is what actually differs: alignment/padding
// and ciphertext entropy scoring are encrypt-only, and the dispatch
// direction and progress label differ.

/// Steps 2-4 of both operations: resolve the cipher spec, load the key
/// file, and validate the key against the spec. Identical for
/// encrypt/decrypt because the key has to be valid before either
/// direction can proceed.
fn resolve_spec_and_key(
    cipher: CipherArg,
    key_size: Option<u16>,
    key_file: &Path,
    key_format: KeyFormatArg,
    reporter: &dyn Reporter,
) -> Result<(CipherSpec, Vec<u8>), ExitCode> {
    let spec = resolve_cipher_spec(cipher, key_size).map_err(|e| {
        reporter.report(Event::Error { text: e.to_string() });
        ExitCode::UnsupportedCipher
    })?;

    let key = load_key_file(key_file, key_format).map_err(|e| {
        reporter.report(Event::Error { text: e.to_string() });
        ExitCode::Io
    })?;

    if let Err(e) = nocap_crypt_keymgmt::validate_key(&spec, &key) {
        reporter.report(Event::Error { text: e.to_string() });
        return Err(ExitCode::KeyValidation);
    }

    Ok((spec, key))
}

/// The block-cipher/XTS narration block plus `Event::CipherSelected` —
/// identical in both operations, always fires right after the key is
/// confirmed valid.
fn narrate_cipher_intro(reporter: &dyn Reporter, spec: &CipherSpec) {
    if reporter.narrates() {
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_block_cipher_basics().to_string(),
        });
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_xts_tweakability().to_string(),
        });
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::xts_ascii_diagram().to_string(),
        });
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_xts_malleability().to_string(),
        });
    }
    reporter.report(Event::CipherSelected {
        cipher: spec.as_str(),
        key_bits: spec.aes_bits.bits(),
    });
}

fn build_engine(spec: CipherSpec, key: &[u8], reporter: &dyn Reporter) -> Result<SectorEngine, ExitCode> {
    SectorEngine::new(spec, key).map_err(|e| {
        reporter.report(Event::Error { text: e.to_string() });
        ExitCode::KeyValidation
    })
}

fn stat_input_len(path: &Path, reporter: &dyn Reporter) -> Result<u64, ExitCode> {
    std::fs::metadata(path).map(|m| m.len()).map_err(|e| {
        reporter.report(Event::Error {
            text: format!("stat {}: {e}", path.display()),
        });
        ExitCode::Io
    })
}

/// `(blockcount + align_extra_block) * align_block_size`, checked:
/// `align_block_size == 0` would otherwise divide-by-zero panic on the
/// `div_ceil` below, and an oversized `--align-block-size` combined
/// with `--align-extra-block` can overflow `u64` — which release
/// builds (no `overflow-checks`) silently wrap instead of panicking
/// on, producing a truncated `output_size` and a shorter-than-claimed
/// ciphertext file with `ExitCode::Success` still reported. Both are
/// real, user-reachable CLI inputs, not internal invariants, so they
/// get a clean `ExitCode::InvalidArgs` instead.
fn aligned_output_size(
    input_len: u64,
    align_block_size: u64,
    align_extra_block: u64,
    reporter: &dyn Reporter,
) -> Result<u64, ExitCode> {
    if align_block_size == 0 {
        reporter.report(Event::Error {
            text: "--align-block-size must be nonzero".to_string(),
        });
        return Err(ExitCode::InvalidArgs);
    }
    let blockcount = input_len.div_ceil(align_block_size);
    blockcount
        .checked_add(align_extra_block)
        .and_then(|blocks| blocks.checked_mul(align_block_size))
        .ok_or_else(|| {
            reporter.report(Event::Error {
                text: "--align-block-size/--align-extra-block combination overflows".to_string(),
            });
            ExitCode::InvalidArgs
        })
}

/// System info + concurrency resolution + `Event::ConcurrencyInfo` —
/// identical shape in both operations, kept as a free function over
/// primitive params since `EncryptArgs`/`DecryptArgs` don't share a type.
fn resolve_and_report_concurrency(
    input_path: &Path,
    input_len: u64,
    small_file_threshold: u64,
    pin_to_submission_thread: bool,
    max_workers: Option<usize>,
    reporter: &dyn Reporter,
) -> (DispatchInfo, Concurrency) {
    let sys_info = compute_system_info(input_path);
    let concurrency = resolve_concurrency(input_len, input_path, small_file_threshold, pin_to_submission_thread, max_workers);
    reporter.report(Event::ConcurrencyInfo {
        effective_cores: sys_info.effective_cores,
        disk_type: format!("{:?}", sys_info.disk_type),
        chunk_sectors: sys_info.chunk_sectors,
        concurrency: format!("{concurrency:?}"),
    });
    (sys_info, concurrency)
}

fn open_input_file(path: &Path, reporter: &dyn Reporter) -> Result<SectorFile, ExitCode> {
    SectorFile::open_read(path).map_err(|e| {
        reporter.report(Event::Error {
            text: format!("opening {}: {e}", path.display()),
        });
        ExitCode::Io
    })
}

fn open_output_file(path: &Path, size: u64, reporter: &dyn Reporter) -> Result<SectorFile, ExitCode> {
    create_sparse_output(path, size).map_err(|e| {
        reporter.report(Event::Error {
            text: format!("creating {}: {e}", path.display()),
        });
        ExitCode::Io
    })
}

fn narrate_sample_iv_if_applicable(reporter: &dyn Reporter, input_len: u64) {
    if reporter.narrates() && input_len > 0 {
        let sample_iv = plain64_iv(0);
        reporter.report(Event::Narration {
            text: format!(
                "{}\n  {}\n  {}",
                nocap_crypt_ui::explain_plain64_tweak_is_not_secret(),
                nocap_crypt_ui::explain_iv_derivation(0, &sample_iv),
                nocap_crypt_ui::narration_sample_note()
            ),
        });
    }
}

/// Dispatch the actual transfer and report its `Event::PhaseTiming` —
/// same shape for both operations, differing only in direction,
/// label, and which byte count the throughput number is computed
/// from (`progress_total_bytes`: `output_size` for encrypt so the
/// alignment padding counts as real work, `input_len` for decrypt).
fn transfer_and_report_timing(
    reporter: &dyn Reporter,
    job: TransferJob,
    phase: &str,
    context: String,
    show_progress: bool,
    no_color: bool,
) -> Result<(), ExitCode> {
    let start = Instant::now();
    let progress_total_bytes = job.progress_total_bytes;
    let result = dispatch_with_progress(reporter, job, context, show_progress, no_color);
    if let Err(e) = result {
        reporter.report(Event::Error { text: e.to_string() });
        return Err(ExitCode::Io);
    }
    let elapsed = start.elapsed();
    let mb = progress_total_bytes as f64 / (1024.0 * 1024.0);
    reporter.report(Event::PhaseTiming {
        phase: phase.to_string(),
        duration_ms: (elapsed.as_secs_f64() * 1000.0) as u64,
        throughput_mb_s: Some(mb / elapsed.as_secs_f64().max(1e-9)),
    });
    Ok(())
}

// --- Encrypt/decrypt entry points ---------------------------------------

pub fn run_encrypt(args: &EncryptArgs, reporter: &dyn Reporter, show_progress: bool, no_color: bool) -> ExitCode {
    match run_encrypt_impl(args, reporter, show_progress, no_color) {
        Ok(code) | Err(code) => code,
    }
}

fn run_encrypt_impl(args: &EncryptArgs, reporter: &dyn Reporter, show_progress: bool, no_color: bool) -> Result<ExitCode, ExitCode> {
    if let Some(banner) = reporter.boot_banner() {
        reporter.report(Event::Banner { text: banner.to_string() });
    }

    let (spec, key) = resolve_spec_and_key(args.cipher, args.key_size, &args.key_file, args.key_format, reporter)?;
    narrate_cipher_intro(reporter, &spec);

    if reporter.narrates() {
        reporter.report(Event::Narration {
            text: format!("key fingerprint: {}", nocap_crypt_keymgmt::fingerprint(&key)),
        });
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_headerless_plain_reference().to_string(),
        });
    }
    if let Some(joke) = reporter.corporate_joke() {
        reporter.report(Event::Message {
            text: format!("WARNING: {joke}"),
        });
        reporter.report(Event::Message {
            text: "SECURING VOLUME ANYWAY.".to_string(),
        });
    }

    let hw = nocap_crypt_sysinfo::detect_hw_accel();
    reporter.report(Event::HardwareAccelPath {
        description: hw.active_path_description.clone(),
    });

    let engine = build_engine(spec, &key, reporter)?;
    let input_len = stat_input_len(&args.input, reporter)?;

    let output_size = aligned_output_size(input_len, args.align_block_size, args.align_extra_block, reporter)?;
    reporter.report(Event::AlignmentStatus {
        path: args.output.display().to_string(),
        aligned: true,
        required_alignment: args.align_block_size,
    });
    if reporter.narrates() {
        reporter.report(Event::Narration {
            text: nocap_crypt_ui::explain_alignment_context().to_string(),
        });
    }

    let (sys_info, concurrency) = resolve_and_report_concurrency(
        &args.input,
        input_len,
        args.small_file_threshold,
        args.pin_to_submission_thread,
        args.max_workers,
        reporter,
    );

    let input_file = open_input_file(&args.input, reporter)?;
    let output_file = open_output_file(&args.output, output_size, reporter)?;

    narrate_sample_iv_if_applicable(reporter, input_len);

    // Ranges must cover `output_size`, not `input_len`: the alignment
    // padding region (`input_len..output_size`) needs to actually be
    // encrypted too, not left as raw zero bytes from
    // `create_sparse_output`'s sparse hole. `real_data_len` below
    // stays `input_len` so `process_ranges` still only *reads* real
    // input bytes — the padding sectors get zero-filled buffers that
    // are then genuinely encrypted, same as any other all-zero
    // plaintext sector.
    let ranges = chunk_ranges(output_size, sys_info.chunk_sectors);
    transfer_and_report_timing(
        reporter,
        TransferJob {
            input_file: &input_file,
            output_file: &output_file,
            engine: &engine,
            ranges: &ranges,
            real_data_len: input_len,
            progress_total_bytes: output_size,
            concurrency,
            encrypt: true,
        },
        "encrypt",
        progress_context(reporter, "encrypt", &spec, concurrency, sys_info.chunk_sectors, Some(&hw.active_path_description)),
        show_progress,
        no_color,
    )?;

    if input_len > 0 {
        if let Ok(ciphertext) = std::fs::read(&args.output) {
            let real = &ciphertext[..(input_len as usize).min(ciphertext.len())];
            let bits_per_byte = nocap_crypt_entropy::shannon_entropy(real);
            reporter.report(Event::EntropyScore {
                bits_per_byte,
                chi_square_uniform_95: nocap_crypt_entropy::is_uniform(real, 1.645),
            });
            if reporter.narrates() {
                reporter.report(Event::Narration {
                    text: nocap_crypt_ui::explain_entropy_result_ciphertext(bits_per_byte),
                });
            }
        }
    }

    if args.dry_run_cryptsetup_compat {
        let outcome = cryptsetup_compat::run(spec, &key);
        reporter.report(Event::Message { text: outcome.message() });
        if outcome.is_failure() {
            return Ok(ExitCode::LuksCompat);
        }
    }

    Ok(ExitCode::Success)
}

pub fn run_decrypt(args: &DecryptArgs, reporter: &dyn Reporter, show_progress: bool, no_color: bool) -> ExitCode {
    match run_decrypt_impl(args, reporter, show_progress, no_color) {
        Ok(code) | Err(code) => code,
    }
}

fn run_decrypt_impl(args: &DecryptArgs, reporter: &dyn Reporter, show_progress: bool, no_color: bool) -> Result<ExitCode, ExitCode> {
    if let Some(banner) = reporter.boot_banner() {
        reporter.report(Event::Banner { text: banner.to_string() });
    }

    let (spec, key) = resolve_spec_and_key(args.cipher, args.key_size, &args.key_file, args.key_format, reporter)?;
    narrate_cipher_intro(reporter, &spec);

    let engine = build_engine(spec, &key, reporter)?;
    let input_len = stat_input_len(&args.input, reporter)?;

    let (sys_info, concurrency) = resolve_and_report_concurrency(
        &args.input,
        input_len,
        args.small_file_threshold,
        args.pin_to_submission_thread,
        args.max_workers,
        reporter,
    );

    let input_file = open_input_file(&args.input, reporter)?;
    let output_file = open_output_file(&args.output, input_len, reporter)?;

    narrate_sample_iv_if_applicable(reporter, input_len);

    // Decrypt has no padding concept — the ciphertext's own length is
    // the whole story, so `real_data_len` and `progress_total_bytes`
    // are the same value here (unlike encrypt, see that function's
    // `chunk_ranges`/`transfer_and_report_timing` call comments).
    let ranges = chunk_ranges(input_len, sys_info.chunk_sectors);
    transfer_and_report_timing(
        reporter,
        TransferJob {
            input_file: &input_file,
            output_file: &output_file,
            engine: &engine,
            ranges: &ranges,
            real_data_len: input_len,
            progress_total_bytes: input_len,
            concurrency,
            encrypt: false,
        },
        "decrypt",
        progress_context(reporter, "decrypt", &spec, concurrency, sys_info.chunk_sectors, None),
        show_progress,
        no_color,
    )?;

    Ok(ExitCode::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nocap_crypt_ui::Silent;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("nocap-crypt-cli-image-test-{}-{}", std::process::id(), name))
    }

    /// Regression test: `--align-block-size`/`--align-extra-block`'s
    /// padding region must actually be dispatched to the cipher, not
    /// left as `create_sparse_output`'s raw zero-initialized sparse
    /// hole in ciphertext this tool claims is fully encrypted.
    #[test]
    fn alignment_padding_region_is_actually_encrypted_not_left_as_raw_zeros() {
        let input_path = temp_path("plain.img");
        let output_path = temp_path("cipher.img");
        let key_path = temp_path("key.bin");

        let plaintext: Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
        std::fs::write(&input_path, &plaintext).unwrap();
        let key: Vec<u8> = (0..64).map(|i| i as u8).collect();
        std::fs::write(&key_path, &key).unwrap();

        let args = EncryptArgs {
            input: input_path.clone(),
            output: output_path.clone(),
            key_file: key_path.clone(),
            key_format: KeyFormatArg::Raw,
            cipher: CipherArg::AesXtsPlain64,
            key_size: None,
            align_block_size: 4096,
            align_extra_block: 1,
            max_workers: None,
            small_file_threshold: DEFAULT_SMALL_FILE_THRESHOLD_BYTES,
            pin_to_submission_thread: true,
            dry_run_cryptsetup_compat: false,
        };

        let exit = run_encrypt(&args, &Silent, false, true);
        assert_eq!(exit, ExitCode::Success);

        let ciphertext = std::fs::read(&output_path).unwrap();
        // 4096-byte input, align_block_size=4096, align_extra_block=1
        // -> output_size = (1 + 1) * 4096 = 8192.
        assert_eq!(ciphertext.len(), 8192);

        let padding_region = &ciphertext[4096..8192];
        assert!(
            padding_region.iter().any(|&b| b != 0),
            "padding region is all-zero — it was never actually encrypted"
        );

        // The real-data region must still decrypt back correctly —
        // this bug fix must not have broken the part that already
        // worked.
        let decrypted_path = temp_path("roundtrip.img");
        let decrypt_args = DecryptArgs {
            input: output_path.clone(),
            output: decrypted_path.clone(),
            key_file: key_path.clone(),
            key_format: KeyFormatArg::Raw,
            cipher: CipherArg::AesXtsPlain64,
            key_size: None,
            max_workers: None,
            small_file_threshold: DEFAULT_SMALL_FILE_THRESHOLD_BYTES,
            pin_to_submission_thread: true,
        };
        let exit = run_decrypt(&decrypt_args, &Silent, false, true);
        assert_eq!(exit, ExitCode::Success);
        let recovered = std::fs::read(&decrypted_path).unwrap();
        assert_eq!(&recovered[..4096], plaintext.as_slice());

        for p in [input_path, output_path, key_path, decrypted_path] {
            std::fs::remove_file(p).ok();
        }
    }

    struct RecordingReporter {
        events: std::sync::Mutex<Vec<Event>>,
    }

    impl Reporter for RecordingReporter {
        fn report(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }
    }

    /// `--dry-run-cryptsetup-compat` must never fail the encrypt op just
    /// because the check itself couldn't run (no cryptsetup, wrong
    /// platform, no privilege) — only an actual ciphertext mismatch
    /// should. This dev/CI machine (Windows) always takes the
    /// `UnsupportedPlatform` branch of `cryptsetup_compat::run`, so this
    /// exercises that path end-to-end through the real CLI wiring.
    #[test]
    fn dry_run_cryptsetup_compat_reports_a_message_and_does_not_fail_the_encrypt() {
        let input_path = temp_path("compat-plain.img");
        let output_path = temp_path("compat-cipher.img");
        let key_path = temp_path("compat-key.bin");

        let plaintext: Vec<u8> = (0..512u32).map(|i| (i % 256) as u8).collect();
        std::fs::write(&input_path, &plaintext).unwrap();
        let key: Vec<u8> = (0..64).map(|i| i as u8).collect();
        std::fs::write(&key_path, &key).unwrap();

        let args = EncryptArgs {
            input: input_path.clone(),
            output: output_path.clone(),
            key_file: key_path.clone(),
            key_format: KeyFormatArg::Raw,
            cipher: CipherArg::AesXtsPlain64,
            key_size: None,
            align_block_size: 4096,
            align_extra_block: 1,
            max_workers: None,
            small_file_threshold: DEFAULT_SMALL_FILE_THRESHOLD_BYTES,
            pin_to_submission_thread: true,
            dry_run_cryptsetup_compat: true,
        };

        let reporter = RecordingReporter {
            events: std::sync::Mutex::new(Vec::new()),
        };
        let exit = run_encrypt(&args, &reporter, false, true);
        assert_eq!(exit, ExitCode::Success);

        let events = reporter.events.lock().unwrap();
        let found = events
            .iter()
            .any(|e| matches!(e, Event::Message { text } if text.contains("dry-run-cryptsetup-compat")));
        assert!(found, "expected a --dry-run-cryptsetup-compat message event, got: {events:?}");

        for p in [input_path, output_path, key_path] {
            std::fs::remove_file(p).ok();
        }
    }
}
