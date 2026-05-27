//! Per-IP auth-attempt rate limiter (roadmap M18.1).
//!
//! Bounds how often a single peer IP can initiate a PROTEUS auth
//! exchange. The intent is to defeat brute-force of `client_id` /
//! signature combinations from a small set of source addresses.
//!
//! v0.3 design: simple sliding window. Each `check_and_record` call
//! records a timestamp in the IP's bucket and trims entries older
//! than the window. If the trimmed bucket already holds the
//! configured max, the new attempt is rejected.
//!
//! Out of scope for v0.3:
//! - distributed rate limiting (this is per-process)
//! - per-`client_id` buckets (the auth path validates `client_id`
//!   *after* the rate-limit check)
//! - bounded total memory under adversarial inputs (an attacker
//!   controlling many source IPs can register one bucket each).
//!   Acceptable for a research prototype; v0.4 would add LRU eviction.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{Result, bail};

#[derive(Debug)]
pub struct AuthRateLimiter {
    max_per_window: usize,
    window: Duration,
    inner: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl AuthRateLimiter {
    pub fn new(max_per_window: usize, window: Duration) -> Self {
        Self {
            max_per_window,
            window,
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn max_per_window(&self) -> usize {
        self.max_per_window
    }

    pub fn window(&self) -> Duration {
        self.window
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("rate-limit map poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Record an auth attempt from `ip`. Returns `Ok(())` if allowed,
    /// `Err` if the rate limit is exceeded.
    pub fn check_and_record(&self, ip: IpAddr) -> Result<()> {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("rate-limit map poisoned");
        let bucket = inner.entry(ip).or_default();
        bucket.retain(|t| now.duration_since(*t) < self.window);
        if bucket.len() >= self.max_per_window {
            bail!(
                "rate limit: {} attempts in {}s from {ip}",
                self.max_per_window,
                self.window.as_secs()
            );
        }
        bucket.push(now);
        Ok(())
    }

    /// Drop buckets whose entries are all expired. Returns how many
    /// buckets were removed.
    pub fn sweep(&self) -> usize {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("rate-limit map poisoned");
        let before = inner.len();
        inner.retain(|_, bucket| {
            bucket.retain(|t| now.duration_since(*t) < self.window);
            !bucket.is_empty()
        });
        before - inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn limiter(max: usize, ms: u64) -> AuthRateLimiter {
        AuthRateLimiter::new(max, Duration::from_millis(ms))
    }

    #[test]
    fn allows_attempts_up_to_max() {
        let l = limiter(3, 60_000);
        l.check_and_record(ip("127.0.0.1")).unwrap();
        l.check_and_record(ip("127.0.0.1")).unwrap();
        l.check_and_record(ip("127.0.0.1")).unwrap();
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn rejects_after_max() {
        let l = limiter(2, 60_000);
        l.check_and_record(ip("127.0.0.1")).unwrap();
        l.check_and_record(ip("127.0.0.1")).unwrap();
        let err = l.check_and_record(ip("127.0.0.1")).unwrap_err();
        assert!(err.to_string().contains("rate limit"), "got: {err}");
    }

    #[test]
    fn different_ips_have_separate_buckets() {
        let l = limiter(1, 60_000);
        l.check_and_record(ip("10.0.0.1")).unwrap();
        l.check_and_record(ip("10.0.0.2")).unwrap();
        assert!(l.check_and_record(ip("10.0.0.1")).is_err());
        assert!(l.check_and_record(ip("10.0.0.2")).is_err());
    }

    #[test]
    fn window_resets_after_ttl() {
        let l = limiter(1, 50);
        l.check_and_record(ip("1.2.3.4")).unwrap();
        sleep(Duration::from_millis(80));
        l.check_and_record(ip("1.2.3.4")).unwrap();
    }

    #[test]
    fn sweep_drops_expired_buckets() {
        let l = limiter(5, 50);
        l.check_and_record(ip("1.1.1.1")).unwrap();
        l.check_and_record(ip("2.2.2.2")).unwrap();
        sleep(Duration::from_millis(80));
        let dropped = l.sweep();
        assert_eq!(dropped, 2);
        assert!(l.is_empty());
    }

    #[test]
    fn sweep_keeps_fresh_buckets() {
        let l = limiter(5, 60_000);
        l.check_and_record(ip("1.1.1.1")).unwrap();
        assert_eq!(l.sweep(), 0);
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn ipv6_is_separate_from_ipv4() {
        let l = limiter(1, 60_000);
        l.check_and_record(ip("127.0.0.1")).unwrap();
        l.check_and_record(ip("::1")).unwrap();
        assert!(l.check_and_record(ip("127.0.0.1")).is_err());
        assert!(l.check_and_record(ip("::1")).is_err());
    }
}
