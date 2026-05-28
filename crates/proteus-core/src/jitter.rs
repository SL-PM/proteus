//! Inter-arrival timing jitter (v0.5-rc.2 M6.5).
//!
//! A bounded random delay applied before each outgoing proxy-stream
//! frame, to decorrelate PROTEUS's send timing from the application's
//! data-production timing. Design + trade-offs in
//! [`docs/PROTEUS-v0.5-plan.md`](../../../docs/PROTEUS-v0.5-plan.md) §11.
//!
//! This module is intentionally **pure and async-free**: it only
//! *computes* a [`Duration`]. The actual sleeping happens in the proxy
//! bridge (`crate::proxy`), which already runs under tokio. Keeping the
//! sampler pure makes it trivially unit-testable (sample many, assert
//! every result is within bounds) with no runtime.
//!
//! Distribution is **uniform** `[min_ms, max_ms]` for the rc.2 first
//! cut — a decorrelator, not a mimic. Matching a real cover host's
//! inter-arrival distribution needs the same recorded-profile
//! machinery deferred for size sampling, and is a later increment.

use std::time::Duration;

use rand::Rng;

/// A configured timing-jitter sampler. Cheap to copy; carries just the
/// inclusive millisecond bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Jitter {
    min_ms: u64,
    max_ms: u64,
}

impl Jitter {
    /// Build from inclusive millisecond bounds. If `min_ms > max_ms`
    /// the two are swapped defensively (callers should validate via
    /// [`crate::config::TimingJitterConfig::validate`] for a loud
    /// error, but this keeps the sampler total).
    pub fn new(min_ms: u64, max_ms: u64) -> Self {
        let (min_ms, max_ms) = if min_ms <= max_ms {
            (min_ms, max_ms)
        } else {
            (max_ms, min_ms)
        };
        Self { min_ms, max_ms }
    }

    /// Lower bound in milliseconds.
    pub fn min_ms(&self) -> u64 {
        self.min_ms
    }

    /// Upper bound in milliseconds.
    pub fn max_ms(&self) -> u64 {
        self.max_ms
    }

    /// Sample a delay using the thread-local RNG.
    pub fn next_delay(&self) -> Duration {
        self.next_delay_with(&mut rand::thread_rng())
    }

    /// Sample a delay using a caller-supplied RNG (for deterministic
    /// tests). Always returns a `Duration` in `[min_ms, max_ms]`.
    pub fn next_delay_with<R: Rng>(&self, rng: &mut R) -> Duration {
        // Fast paths avoid touching the RNG when there's no real range.
        if self.max_ms == 0 {
            return Duration::ZERO;
        }
        let ms = if self.min_ms == self.max_ms {
            self.min_ms
        } else {
            rng.gen_range(self.min_ms..=self.max_ms)
        };
        Duration::from_millis(ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn samples_stay_within_bounds() {
        let j = Jitter::new(2, 20);
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        for _ in 0..10_000 {
            let d = j.next_delay_with(&mut rng).as_millis() as u64;
            assert!((2..=20).contains(&d), "sample {d} out of [2, 20]");
        }
    }

    #[test]
    fn equal_bounds_is_constant() {
        let j = Jitter::new(7, 7);
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..1000 {
            assert_eq!(j.next_delay_with(&mut rng), Duration::from_millis(7));
        }
    }

    #[test]
    fn zero_max_is_always_zero() {
        let j = Jitter::new(0, 0);
        let mut rng = StdRng::seed_from_u64(2);
        for _ in 0..1000 {
            assert_eq!(j.next_delay_with(&mut rng), Duration::ZERO);
        }
    }

    #[test]
    fn inverted_bounds_are_swapped() {
        let j = Jitter::new(50, 10);
        assert_eq!(j.min_ms(), 10);
        assert_eq!(j.max_ms(), 50);
        let mut rng = StdRng::seed_from_u64(3);
        for _ in 0..1000 {
            let d = j.next_delay_with(&mut rng).as_millis() as u64;
            assert!((10..=50).contains(&d), "sample {d} out of [10, 50]");
        }
    }

    #[test]
    fn full_range_is_reachable_at_both_ends() {
        // Over enough samples a [0, 3] range should hit both 0 and 3.
        let j = Jitter::new(0, 3);
        let mut rng = StdRng::seed_from_u64(42);
        let mut seen_min = false;
        let mut seen_max = false;
        for _ in 0..10_000 {
            match j.next_delay_with(&mut rng).as_millis() {
                0 => seen_min = true,
                3 => seen_max = true,
                _ => {}
            }
        }
        assert!(seen_min, "never sampled the lower bound 0");
        assert!(seen_max, "never sampled the upper bound 3");
    }
}
