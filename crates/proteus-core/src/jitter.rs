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

    /// Midpoint of the range as a `Duration` — used by [`Pacer`] as the
    /// nominal token-refill interval.
    pub fn mean(&self) -> Duration {
        Duration::from_millis((self.min_ms + self.max_ms) / 2)
    }
}

/// What the send path needs to apply timing jitter: the delay
/// distribution plus a token-bucket burst allowance (M9.5).
///
/// `burst == 0` means "no bucket" — every frame pays the full jittered
/// delay, identical to the rc.2 per-frame behavior. `burst >= 1` lets
/// that many frames through with zero added delay before pacing kicks
/// in, and the allowance refills over idle time.
#[derive(Debug, Clone, Copy)]
pub struct JitterPlan {
    pub jitter: Jitter,
    pub burst: u32,
}

impl JitterPlan {
    pub fn new(jitter: Jitter, burst: u32) -> Self {
        Self { jitter, burst }
    }
}

/// Token-bucket pacer (v0.5 M9.5). Refines the rc.2 per-frame jitter:
/// instead of delaying *every* frame, it hands out `burst` free sends,
/// then paces further sends at roughly one per [`Jitter::mean`] with a
/// jittered wait. The bucket refills over time, so a quiet gap restores
/// the free-burst allowance — matching real interactive patterns
/// (click → small burst → idle → click → …).
///
/// **Honest scope:** this lowers the *latency* cost of jitter for
/// bursty / interactive traffic (the case where the timing fingerprint
/// matters most). It does NOT raise the *sustained* bulk-throughput
/// ceiling — any time-spacing scheme rate-limits sustained output to
/// ~`frame_size / mean_interval`. See `docs/m10.5-pacer-signoff.md`.
///
/// Capacity `0` reduces this to exactly the rc.2 per-frame jitter (the
/// bucket can never hold a token, so every frame takes the wait branch).
#[derive(Debug, Clone)]
pub struct Pacer {
    jitter: Jitter,
    capacity: f64,
    tokens: f64,
    last: std::time::Instant,
}

impl Pacer {
    /// Build a pacer. `now` seeds the refill clock (injectable for
    /// tests); the bucket starts full so an initial burst is free.
    pub fn new(plan: JitterPlan, now: std::time::Instant) -> Self {
        let capacity = plan.burst as f64;
        Self {
            jitter: plan.jitter,
            capacity,
            tokens: capacity,
            last: now,
        }
    }

    /// Delay to wait before sending the next frame, updating bucket
    /// state. `now` is injectable so tests don't depend on wall-clock.
    /// Returns `Duration::ZERO` when a token is available (no pacing).
    pub fn next_delay(&mut self, now: std::time::Instant) -> Duration {
        self.next_delay_with(now, &mut rand::thread_rng())
    }

    /// As [`Pacer::next_delay`] but with a caller-supplied RNG.
    pub fn next_delay_with<R: Rng>(&mut self, now: std::time::Instant, rng: &mut R) -> Duration {
        let mean = self.jitter.mean();
        if mean.is_zero() {
            // Degenerate jitter range ([0,0]) — pacing is a no-op.
            return Duration::ZERO;
        }
        // Refill proportional to elapsed time, capped at capacity.
        let elapsed = now.saturating_duration_since(self.last);
        self.last = now;
        self.tokens = (self.tokens + elapsed.as_secs_f64() / mean.as_secs_f64()).min(self.capacity);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Duration::ZERO
        } else {
            // Not enough credit: wait a jittered interval scaled by the
            // missing fraction of a token, then send. The wait time is
            // accounted for by the next call's refill.
            let missing = 1.0 - self.tokens;
            self.tokens = 0.0;
            self.jitter.next_delay_with(rng).mul_f64(missing)
        }
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

    // ---------------- Pacer ----------------

    use std::time::Instant;

    fn pacer(burst: u32, min_ms: u64, max_ms: u64, now: Instant) -> Pacer {
        Pacer::new(JitterPlan::new(Jitter::new(min_ms, max_ms), burst), now)
    }

    #[test]
    fn burst_frames_pass_without_delay() {
        let mut rng = StdRng::seed_from_u64(1);
        let t0 = Instant::now();
        // capacity 4, constant 20ms jitter. No time advances between
        // calls, so only the initial 4 tokens are available.
        let mut p = pacer(4, 20, 20, t0);
        for i in 0..4 {
            assert_eq!(
                p.next_delay_with(t0, &mut rng),
                Duration::ZERO,
                "burst frame {i} should be free"
            );
        }
        // 5th frame: bucket empty, no refill (same instant) → paced.
        let d = p.next_delay_with(t0, &mut rng);
        assert_eq!(d, Duration::from_millis(20), "post-burst frame paced");
    }

    #[test]
    fn capacity_zero_reduces_to_per_frame_jitter() {
        let mut rng = StdRng::seed_from_u64(2);
        let t0 = Instant::now();
        // burst 0 → bucket can never hold a token → every frame waits
        // the full jittered delay, exactly like rc.2 per-frame jitter.
        let mut p = pacer(0, 20, 20, t0);
        for _ in 0..5 {
            assert_eq!(p.next_delay_with(t0, &mut rng), Duration::from_millis(20));
        }
    }

    #[test]
    fn idle_time_refills_the_burst_allowance() {
        let mut rng = StdRng::seed_from_u64(3);
        let t0 = Instant::now();
        let mut p = pacer(2, 10, 10, t0); // mean = 10ms, capacity 2
        // Drain the 2 initial tokens.
        assert_eq!(p.next_delay_with(t0, &mut rng), Duration::ZERO);
        assert_eq!(p.next_delay_with(t0, &mut rng), Duration::ZERO);
        // Empty now (same instant) → next is paced.
        assert!(p.next_delay_with(t0, &mut rng) > Duration::ZERO);
        // Advance 25ms = 2.5 token-intervals → refills to cap (2).
        let t1 = t0 + Duration::from_millis(25);
        assert_eq!(p.next_delay_with(t1, &mut rng), Duration::ZERO);
        assert_eq!(p.next_delay_with(t1, &mut rng), Duration::ZERO);
        assert!(p.next_delay_with(t1, &mut rng) > Duration::ZERO);
    }

    #[test]
    fn zero_range_pacer_is_always_free() {
        let mut rng = StdRng::seed_from_u64(4);
        let t0 = Instant::now();
        let mut p = pacer(0, 0, 0, t0); // mean 0 → pacing no-op
        for _ in 0..10 {
            assert_eq!(p.next_delay_with(t0, &mut rng), Duration::ZERO);
        }
    }

    #[test]
    fn sustained_rate_is_bounded_by_mean() {
        // Over a fixed wall-time window, the number of *free* sends a
        // pacer grants is bounded by capacity + window/mean — i.e. it
        // really does rate-limit sustained traffic (the honest caveat).
        let mut rng = StdRng::seed_from_u64(5);
        let t0 = Instant::now();
        let capacity = 3u32;
        let mut p = pacer(capacity, 10, 10, t0); // mean 10ms
        // Hammer at the same instant: only `capacity` free sends.
        let mut free = 0;
        for _ in 0..50 {
            if p.next_delay_with(t0, &mut rng).is_zero() {
                free += 1;
            }
        }
        assert_eq!(free, capacity as usize, "only the burst is free at t0");
    }
}
