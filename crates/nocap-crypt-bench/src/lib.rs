//! Benchmark harness: deterministic/true-random synthetic data,
//! file-backed throughput measurement through the real dispatch path,
//! and a self-describing report (results + hardware/heuristic context).

pub mod datagen;
pub mod report;
pub mod runner;

pub use datagen::{true_random, BenchDataGenerator};
pub use report::{build_report, render_human_table, BenchReport};
pub use runner::{run, BenchParams, BenchResult};
