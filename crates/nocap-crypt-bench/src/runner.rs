//! Benchmark runner: encrypts synthetic data through the real
//! file-backed dispatch path (`nocap-crypt-worker::process_ranges`) so
//! throughput numbers reflect actual I/O + crypto cost, not just the
//! in-memory cipher.

use std::io;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use nocap_crypt_blockio::{create_sparse_output, SectorFile};
use nocap_crypt_core::{CipherSpec, SectorEngine, SECTOR_SIZE};
use nocap_crypt_worker::{chunk_ranges, process_ranges, Concurrency};
use serde::Serialize;

use crate::datagen::BenchDataGenerator;

#[derive(Debug, Clone, Serialize)]
pub struct BenchResult {
    pub cipher: String,
    pub data_len_bytes: u64,
    pub worker_count: usize,
    pub chunk_sectors: u64,
    pub duration_ms: f64,
    pub throughput_mb_s: f64,
}

#[derive(Debug, Clone)]
pub struct BenchParams {
    pub cipher: CipherSpec,
    pub key: Vec<u8>,
    pub data_len_bytes: u64,
    pub worker_count: usize,
    pub chunk_sectors: u64,
    pub seed: u64,
}

/// Run one encrypt pass over `params.data_len_bytes` of deterministic
/// synthetic plaintext, through real temp files, and report elapsed
/// time / throughput. Temp files are cleaned up before returning.
///
/// `progress`, if given, is updated with real bytes-processed as the
/// run proceeds (see `nocap_crypt_worker::process_ranges`) — a caller
/// can poll it from another thread for a live display.
pub fn run(params: &BenchParams, progress: Option<&AtomicU64>) -> io::Result<BenchResult> {
    let engine = SectorEngine::new(params.cipher, &params.key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let dir = std::env::temp_dir().join(format!("nocap-crypt-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let in_path: PathBuf = dir.join("plain.bin");
    let out_path: PathBuf = dir.join("cipher.bin");

    let mut gen = BenchDataGenerator::new(params.seed);
    let data = gen.generate(params.data_len_bytes as usize);
    std::fs::write(&in_path, &data)?;

    let sector_rounded_len = params.data_len_bytes.div_ceil(SECTOR_SIZE as u64) * SECTOR_SIZE as u64;
    let ranges = chunk_ranges(params.data_len_bytes, params.chunk_sectors.max(1));

    let input = SectorFile::open_read(&in_path)?;
    let output = create_sparse_output(&out_path, sector_rounded_len)?;

    // bench always dispatches with an explicit, fixed worker count —
    // that's the whole point of the sweep (measuring throughput vs.
    // worker count), so it deliberately bypasses the small-file
    // synchronous path and the GlobalPool default that real `image
    // encrypt`/`decrypt` use.
    let start = Instant::now();
    process_ranges(
        &input,
        &output,
        &engine,
        &ranges,
        params.data_len_bytes,
        Concurrency::Fixed(params.worker_count.max(1)),
        true,
        progress,
    )?;
    let elapsed = start.elapsed();

    std::fs::remove_dir_all(&dir).ok();

    let mb = params.data_len_bytes as f64 / (1024.0 * 1024.0);
    let secs = elapsed.as_secs_f64().max(1e-9);

    Ok(BenchResult {
        cipher: params.cipher.as_str(),
        data_len_bytes: params.data_len_bytes,
        worker_count: params.worker_count.max(1),
        chunk_sectors: params.chunk_sectors.max(1),
        duration_ms: elapsed.as_secs_f64() * 1000.0,
        throughput_mb_s: mb / secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_and_reports_positive_throughput() {
        let spec = CipherSpec::parse("aes-xts-plain64").unwrap();
        let key: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let params = BenchParams {
            cipher: spec,
            key,
            data_len_bytes: SECTOR_SIZE as u64 * 32,
            worker_count: 2,
            chunk_sectors: 8,
            seed: 123,
        };
        let progress = AtomicU64::new(0);
        let result = run(&params, Some(&progress)).unwrap();
        assert_eq!(result.data_len_bytes, params.data_len_bytes);
        assert!(result.throughput_mb_s > 0.0);
        assert!(result.duration_ms >= 0.0);
        assert!(progress.load(std::sync::atomic::Ordering::Relaxed) >= params.data_len_bytes);
    }
}
