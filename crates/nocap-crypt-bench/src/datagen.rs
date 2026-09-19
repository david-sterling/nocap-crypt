//! Benchmark data generation: two deliberately separate types.
//!
//! `BenchDataGenerator` is a seedable, non-cryptographic PRNG for
//! reproducible performance-regression tracking (`--bench-deterministic
//! <seed>`). `true_random` sources from the OS CSPRNG for a genuinely
//! random run. These are kept as distinct types with no shared
//! function-plus-flag, on purpose — mirroring
//! `nocap-crypt-keymgmt::keygen`'s isolation of real key material from any
//! seedable code path, so a benchmark data generator can never be
//! reached for actual key generation by accident.

use rand::rngs::SysRng;
use rand::TryRng;

/// Deterministic xorshift64* generator — fast, reproducible, and
/// explicitly *not* cryptographically secure. Only ever used to fill
/// synthetic benchmark plaintext, never key material.
pub struct BenchDataGenerator {
    state: u64,
}

impl BenchDataGenerator {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x9E3779B97F4A7C15 } else { seed },
        }
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            self.state ^= self.state << 13;
            self.state ^= self.state >> 7;
            self.state ^= self.state << 17;
            let bytes = self.state.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    pub fn generate(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        self.fill(&mut buf);
        buf
    }
}

/// Genuinely random benchmark data, sourced from the OS CSPRNG. Slower
/// to generate than [`BenchDataGenerator`] but not reproducible run to
/// run — the two have different, both valid, purposes.
pub fn true_random(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    SysRng
        .try_fill_bytes(&mut buf)
        .expect("OS CSPRNG failed to fill benchmark data");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_is_reproducible() {
        let mut a = BenchDataGenerator::new(42);
        let mut b = BenchDataGenerator::new(42);
        assert_eq!(a.generate(1024), b.generate(1024));
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = BenchDataGenerator::new(1);
        let mut b = BenchDataGenerator::new(2);
        assert_ne!(a.generate(1024), b.generate(1024));
    }

    #[test]
    fn generates_requested_length() {
        let mut g = BenchDataGenerator::new(7);
        assert_eq!(g.generate(1000).len(), 1000);
    }

    #[test]
    fn true_random_generates_requested_length() {
        assert_eq!(true_random(256).len(), 256);
    }
}
