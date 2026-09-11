//! Windowed entropy over a stream, without loading the whole file into
//! memory. Per-window scores matter as much as the global figure: a
//! plaintext region accidentally left unencrypted at the start/end of an
//! otherwise-encrypted image shows up as one low-entropy window against
//! high-entropy neighbors, which a single whole-file average would mask.

use std::io::{self, Read};

use crate::chisquare::chi_square_statistic;
use crate::shannon::shannon_entropy;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WindowScore {
    pub window_index: usize,
    pub offset: u64,
    pub len: usize,
    pub shannon_bits_per_byte: f64,
    pub chi_square: f64,
}

#[derive(Debug, Clone)]
pub struct StreamEntropyReport {
    pub windows: Vec<WindowScore>,
    pub overall_shannon_bits_per_byte: f64,
    pub total_bytes: u64,
}

impl StreamEntropyReport {
    /// The weakest window — the figure a CI gate should actually check,
    /// since it's the one a localized plaintext leak would depress.
    pub fn min_window_entropy(&self) -> Option<f64> {
        self.windows
            .iter()
            .map(|w| w.shannon_bits_per_byte)
            .fold(None, |acc, v| Some(acc.map_or(v, |a: f64| a.min(v))))
    }
}

/// Read `reader` in `window_size`-byte chunks (default caller choice —
/// 4KiB matches typical sector/page granularity, see `nocap-crypt entropy`
/// CLI default), scoring each window independently plus an overall
/// whole-stream Shannon figure.
pub fn analyze_stream<R: Read>(
    mut reader: R,
    window_size: usize,
) -> io::Result<StreamEntropyReport> {
    assert!(window_size > 0, "window_size must be nonzero");

    let mut buf = vec![0u8; window_size];
    let mut windows = Vec::new();
    let mut offset: u64 = 0;
    let mut global_counts = [0u64; 256];
    let mut total_bytes: u64 = 0;
    let mut window_index = 0;

    loop {
        let n = read_full(&mut reader, &mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        for &b in chunk {
            global_counts[b as usize] += 1;
        }
        windows.push(WindowScore {
            window_index,
            offset,
            len: n,
            shannon_bits_per_byte: shannon_entropy(chunk),
            chi_square: chi_square_statistic(chunk),
        });
        offset += n as u64;
        total_bytes += n as u64;
        window_index += 1;
        if n < window_size {
            break;
        }
    }

    let overall_shannon_bits_per_byte = if total_bytes == 0 {
        0.0
    } else {
        let len = total_bytes as f64;
        global_counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum()
    };

    Ok(StreamEntropyReport {
        windows,
        overall_shannon_bits_per_byte,
        total_bytes,
    })
}

fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn empty_stream_has_no_windows() {
        let report = analyze_stream(Cursor::new(Vec::<u8>::new()), 4096).unwrap();
        assert!(report.windows.is_empty());
        assert_eq!(report.total_bytes, 0);
        assert_eq!(report.min_window_entropy(), None);
    }

    #[test]
    fn exact_multiple_of_window_size_produces_expected_window_count() {
        let data = vec![0xAAu8; 4096 * 3];
        let report = analyze_stream(Cursor::new(data), 4096).unwrap();
        assert_eq!(report.windows.len(), 3);
        assert_eq!(report.total_bytes, 4096 * 3);
    }

    #[test]
    fn partial_final_window_is_included() {
        let data = vec![0x00u8; 4096 + 100];
        let report = analyze_stream(Cursor::new(data), 4096).unwrap();
        assert_eq!(report.windows.len(), 2);
        assert_eq!(report.windows[1].len, 100);
    }

    #[test]
    fn low_entropy_window_is_detected_against_high_entropy_neighbors() {
        // Simulate a plaintext region (all zero) at the head of an
        // otherwise-encrypted-looking (full-byte-range) file.
        let mut data = vec![0u8; 4096];
        let mut state: u64 = 0x9E3779B97F4A7C15;
        for _ in 0..4096 * 4 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            data.push((state & 0xFF) as u8);
        }
        let report = analyze_stream(Cursor::new(data), 4096).unwrap();
        assert_eq!(report.windows[0].shannon_bits_per_byte, 0.0);
        assert!(report.windows[1].shannon_bits_per_byte > 7.0);
        assert_eq!(report.min_window_entropy(), Some(0.0));
    }
}
