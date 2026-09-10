//! Aggregate benchmark report: results plus the same hardware/heuristic
//! context `nocap-crypt info` reports, so a result is self-describing and
//! comparable across runs months apart on different nodes.

use nocap_crypt_sysinfo::SystemInfo;
use serde::Serialize;

use crate::runner::BenchResult;

#[derive(Debug, Clone, Serialize)]
pub struct BenchReport {
    pub system: SystemInfo,
    pub results: Vec<BenchResult>,
}

pub fn build_report(results: Vec<BenchResult>) -> BenchReport {
    BenchReport {
        system: nocap_crypt_sysinfo::collect(),
        results,
    }
}

pub fn render_human_table(report: &BenchReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "hw accel: {}\n",
        report.system.hw_accel.active_path_description
    ));
    out.push_str(&format!(
        "{:<20} {:>12} {:>8} {:>10} {:>12}\n",
        "cipher", "bytes", "workers", "chunk_sec", "MB/s"
    ));
    for r in &report.results {
        out.push_str(&format!(
            "{:<20} {:>12} {:>8} {:>10} {:>12.2}\n",
            r.cipher, r.data_len_bytes, r.worker_count, r.chunk_sectors, r.throughput_mb_s
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::BenchResult;

    #[test]
    fn human_table_lists_every_result() {
        let report = build_report(vec![BenchResult {
            cipher: "aes-xts-plain64".to_string(),
            data_len_bytes: 4096,
            worker_count: 4,
            chunk_sectors: 8,
            duration_ms: 1.5,
            throughput_mb_s: 100.0,
        }]);
        let table = render_human_table(&report);
        assert!(table.contains("aes-xts-plain64"));
        assert!(table.contains("100.00"));
    }

    #[test]
    fn json_serializes_without_error() {
        let report = build_report(vec![]);
        assert!(serde_json::to_string(&report).is_ok());
    }
}
