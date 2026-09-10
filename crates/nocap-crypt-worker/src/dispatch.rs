//! Sector-range dispatch: chunk a byte range into `chunk_sectors`-sized
//! jobs and run them per the resolved [`Concurrency`] mode. Safe to
//! parallelize because `plain64` IV is a pure function of absolute
//! sector number — no chaining between sectors, so any range can be
//! encrypted/decrypted independently with no shared mutable state
//! beyond the key and the underlying file. Each range does its own
//! read+encrypt+write with no shared upstream phase — the kind of
//! accidental serialization point (e.g. a single-threaded read phase
//! gating all encrypt/write work) that has bitten dm-crypt's own
//! workqueue design historically (see `concurrency.rs` module docs).

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use nocap_crypt_blockio::SectorFile;
use nocap_crypt_core::{SectorEngine, SECTOR_SIZE};
use rayon::prelude::*;

use crate::concurrency::Concurrency;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectorRange {
    pub first_sector: u64,
    pub sector_count: u64,
}

/// Split `[0, data_len)` (in bytes) into `chunk_sectors`-sized
/// (512-byte-sector-granular) ranges. `data_len` need not be a
/// multiple of the sector size — the final range is padded up to a
/// full sector by [`process_ranges`], not here.
pub fn chunk_ranges(data_len: u64, chunk_sectors: u64) -> Vec<SectorRange> {
    assert!(chunk_sectors > 0);
    let total_sectors = data_len.div_ceil(SECTOR_SIZE as u64);
    let mut ranges = Vec::new();
    let mut start = 0u64;
    while start < total_sectors {
        let count = chunk_sectors.min(total_sectors - start);
        ranges.push(SectorRange {
            first_sector: start,
            sector_count: count,
        });
        start += count;
    }
    ranges
}

/// Encrypt or decrypt `[0, data_len)` of `input` into `output`, sector
/// range by sector range, per `concurrency`.
///
/// `data_len` need not be a multiple of the sector size — a real
/// source image's length rarely is. A sector is the atomic unit for
/// dm-crypt-compatible ciphertext (there's no such thing as a
/// "partially encrypted sector" on a real block device), so when
/// `data_len` falls mid-sector, the final sector's tail is zero-padded
/// *before* encryption and the *entire* encrypted sector — padding
/// included — is written back, not truncated at `data_len`. Only
/// bytes strictly beyond `ranges`' coverage (the alignment padding
/// block, handled by the caller) stay untouched/sparse — see
/// `nocap-crypt-blockio::create_sparse_output`.
///
/// `progress`, if given, is incremented (relaxed, `fetch_add`) by the
/// real byte count of each range as it completes — a caller can poll
/// it from another thread for a live throughput display driven by
/// actual completed work, not a simulated animation.
#[allow(clippy::too_many_arguments)]
pub fn process_ranges(
    input: &SectorFile,
    output: &SectorFile,
    engine: &SectorEngine,
    ranges: &[SectorRange],
    data_len: u64,
    concurrency: Concurrency,
    encrypt: bool,
    progress: Option<&AtomicU64>,
) -> io::Result<()> {
    match concurrency {
        Concurrency::Synchronous => {
            for range in ranges {
                process_one_range(input, output, engine, *range, data_len, encrypt, progress)?;
            }
            Ok(())
        }
        Concurrency::GlobalPool => ranges
            .par_iter()
            .try_for_each(|range| process_one_range(input, output, engine, *range, data_len, encrypt, progress)),
        Concurrency::Fixed(num_threads) => {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(num_threads.max(1))
                .build()
                .map_err(io::Error::other)?;
            pool.install(|| {
                ranges.par_iter().try_for_each(|range| {
                    process_one_range(input, output, engine, *range, data_len, encrypt, progress)
                })
            })
        }
    }
}

fn process_one_range(
    input: &SectorFile,
    output: &SectorFile,
    engine: &SectorEngine,
    range: SectorRange,
    data_len: u64,
    encrypt: bool,
    progress: Option<&AtomicU64>,
) -> io::Result<()> {
    let byte_offset = range.first_sector * SECTOR_SIZE as u64;
    let byte_len = (range.sector_count as usize) * SECTOR_SIZE;
    let mut buf = vec![0u8; byte_len];

    // Only real bytes are read; any tail beyond data_len within the
    // final sector is implicitly zero (the buffer's own
    // zero-initialization).
    let available = data_len.saturating_sub(byte_offset).min(byte_len as u64) as usize;
    if available > 0 {
        input.read_at_exact(byte_offset, &mut buf[..available])?;
    }

    if encrypt {
        engine.encrypt_range(range.first_sector, &mut buf);
    } else {
        engine.decrypt_range(range.first_sector, &mut buf);
    }

    output.write_at_exact(byte_offset, &buf)?;
    if let Some(counter) = progress {
        counter.fetch_add(byte_len as u64, Ordering::Relaxed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_ranges_exact_multiple() {
        let ranges = chunk_ranges(4096 * 3, 8); // 3 chunks of 8 sectors (4096B) each
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0], SectorRange { first_sector: 0, sector_count: 8 });
        assert_eq!(ranges[2], SectorRange { first_sector: 16, sector_count: 8 });
    }

    #[test]
    fn chunk_ranges_partial_final_chunk() {
        let ranges = chunk_ranges(4096 + 100, 8);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[1].sector_count, 1); // 100 bytes -> 1 partial sector
    }

    #[test]
    fn chunk_ranges_empty_input() {
        assert!(chunk_ranges(0, 8).is_empty());
    }

    fn round_trip_with_concurrency(concurrency: Concurrency) {
        use nocap_crypt_core::CipherSpec;

        let dir = std::env::temp_dir().join(format!(
            "nocap-crypt-worker-test-{}-{:?}",
            std::process::id(),
            concurrency
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let in_path = dir.join("plain.bin");
        let enc_path = dir.join("enc.bin");
        let dec_path = dir.join("dec.bin");

        let plaintext: Vec<u8> = (0..(SECTOR_SIZE * 10 + 37) as u32).map(|i| (i % 256) as u8).collect();
        std::fs::write(&in_path, &plaintext).unwrap();

        let spec = CipherSpec::parse("aes-xts-plain64").unwrap();
        let key: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let engine = SectorEngine::new(spec, &key).unwrap();

        let data_len = plaintext.len() as u64;
        let ranges = chunk_ranges(data_len, 8);

        // Ciphertext covers whole sectors: ceil(data_len / SECTOR_SIZE).
        let sector_rounded_len = data_len.div_ceil(SECTOR_SIZE as u64) * SECTOR_SIZE as u64;

        let input = SectorFile::open_read(&in_path).unwrap();
        let output = nocap_crypt_blockio::create_sparse_output(&enc_path, sector_rounded_len).unwrap();
        process_ranges(&input, &output, &engine, &ranges, data_len, concurrency, true, None).unwrap();
        drop(output);

        let ciphertext = std::fs::read(&enc_path).unwrap();
        assert_eq!(ciphertext.len() as u64, sector_rounded_len);
        assert_ne!(&ciphertext[..plaintext.len()], plaintext.as_slice());

        let enc_input = SectorFile::open_read(&enc_path).unwrap();
        let dec_output = nocap_crypt_blockio::create_sparse_output(&dec_path, sector_rounded_len).unwrap();
        // Decrypt reads the full sector-rounded ciphertext (every byte
        // written above is real, encrypted content — including the
        // padded tail sector), so data_len here is the ciphertext's
        // own length, not the original plaintext length.
        process_ranges(&enc_input, &dec_output, &engine, &ranges, sector_rounded_len, concurrency, false, None).unwrap();
        drop(dec_output);

        let decrypted = std::fs::read(&dec_path).unwrap();
        // Only the real plaintext prefix is meaningful; the trailing
        // sector padding round-trips back to the zero bytes it was
        // encrypted from, same as a real dm-crypt volume's unused
        // tail would.
        assert_eq!(&decrypted[..plaintext.len()], plaintext.as_slice());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn process_ranges_round_trip_synchronous() {
        round_trip_with_concurrency(Concurrency::Synchronous);
    }

    #[test]
    fn process_ranges_round_trip_global_pool() {
        round_trip_with_concurrency(Concurrency::GlobalPool);
    }

    #[test]
    fn process_ranges_round_trip_fixed() {
        round_trip_with_concurrency(Concurrency::Fixed(4));
    }

    /// Tier 3 property from `specs/fips_check.md` §2: encrypting the
    /// same plaintext with `--max-workers 1` must produce
    /// byte-identical ciphertext to `--max-workers N` for any `N` —
    /// this is the test that would catch dm-crypt's own historical
    /// single-thread-to-multi-thread scaling bug class (concurrency
    /// mode must never change *what* gets computed, only how the work
    /// is scheduled). Covers all three `Concurrency` variants, several
    /// worker counts, both a sector-aligned and a deliberately
    /// non-sector-aligned (partial final sector) length, since that's
    /// exactly the edge where a scheduling bug would most plausibly
    /// leak into the output.
    #[test]
    fn ciphertext_is_identical_across_every_concurrency_mode() {
        use nocap_crypt_core::CipherSpec;

        let spec = CipherSpec::parse("aes-xts-plain64").unwrap();
        let key: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let engine = SectorEngine::new(spec, &key).unwrap();

        let modes = [
            Concurrency::Synchronous,
            Concurrency::GlobalPool,
            Concurrency::Fixed(1),
            Concurrency::Fixed(2),
            Concurrency::Fixed(8),
        ];

        for data_len_bytes in [SECTOR_SIZE * 37, SECTOR_SIZE * 37 + 129] {
            let plaintext: Vec<u8> = (0..data_len_bytes as u32).map(|i| (i % 256) as u8).collect();
            let sector_rounded_len = (data_len_bytes as u64).div_ceil(SECTOR_SIZE as u64) * SECTOR_SIZE as u64;

            let mut reference: Option<Vec<u8>> = None;
            for &mode in &modes {
                let dir = std::env::temp_dir().join(format!(
                    "nocap-crypt-worker-equiv-test-{}-{data_len_bytes}-{mode:?}",
                    std::process::id()
                ));
                std::fs::create_dir_all(&dir).unwrap();
                let in_path = dir.join("plain.bin");
                let enc_path = dir.join("enc.bin");
                std::fs::write(&in_path, &plaintext).unwrap();

                let data_len = plaintext.len() as u64;
                let ranges = chunk_ranges(data_len, 8);
                let input = SectorFile::open_read(&in_path).unwrap();
                let output = nocap_crypt_blockio::create_sparse_output(&enc_path, sector_rounded_len).unwrap();
                process_ranges(&input, &output, &engine, &ranges, data_len, mode, true, None).unwrap();
                drop(output);

                let ciphertext = std::fs::read(&enc_path).unwrap();
                std::fs::remove_dir_all(&dir).ok();

                match &reference {
                    None => reference = Some(ciphertext),
                    Some(reference) => {
                        assert_eq!(
                            reference, &ciphertext,
                            "ciphertext diverged for {mode:?} at data_len_bytes={data_len_bytes} — \
                             concurrency mode must never change *what* gets computed"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn progress_counter_reaches_full_sector_rounded_length() {
        use nocap_crypt_core::CipherSpec;

        let dir = std::env::temp_dir().join(format!("nocap-crypt-worker-progress-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let in_path = dir.join("plain.bin");
        let enc_path = dir.join("enc.bin");

        let plaintext = vec![0xAAu8; SECTOR_SIZE * 20 + 5];
        std::fs::write(&in_path, &plaintext).unwrap();

        let spec = CipherSpec::parse("aes-xts-plain64").unwrap();
        let key: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let engine = SectorEngine::new(spec, &key).unwrap();

        let data_len = plaintext.len() as u64;
        let sector_rounded_len = data_len.div_ceil(SECTOR_SIZE as u64) * SECTOR_SIZE as u64;
        let ranges = chunk_ranges(data_len, 8);

        let input = SectorFile::open_read(&in_path).unwrap();
        let output = nocap_crypt_blockio::create_sparse_output(&enc_path, sector_rounded_len).unwrap();

        let progress = AtomicU64::new(0);
        process_ranges(&input, &output, &engine, &ranges, data_len, Concurrency::Fixed(4), true, Some(&progress)).unwrap();

        // Progress counts real bytes written (whole sectors, including
        // any zero-padded tail), so it lands on the sector-rounded
        // length, not the raw plaintext length.
        assert_eq!(progress.load(Ordering::Relaxed), sector_rounded_len);

        std::fs::remove_dir_all(&dir).ok();
    }
}
