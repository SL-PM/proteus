//! Per-client replay cache for AUTH_REQUEST nonces (spec v0.2 §8.3).
//!
//! Holds `(client_id, nonce)` keys with insertion timestamps. The same
//! key inside the TTL window is rejected as a replay; an expired entry
//! is treated as new and overwritten.
//!
//! Eviction:
//! - lazy on lookup (expired entries are overwritten when re-seen)
//! - explicit via [`ReplayCache::sweep`], which the server calls on a
//!   tokio interval
//!
//! The cache uses [`std::sync::Mutex`] — operations are short and we
//! never hold the lock across `.await`.
//!
//! Note: defending against bounded memory growth on hostile inputs is
//! a v0.4 concern (per-client cap with LRU eviction, mentioned in the
//! spec). v0.3 trusts the auth path to filter unauthenticated nonces
//! before they reach this cache.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{Result, bail};

#[derive(Debug)]
pub struct ReplayCache {
    ttl: Duration,
    inner: Mutex<HashMap<(String, [u8; 32]), Instant>>,
}

impl ReplayCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("replay cache poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `Ok(())` if `(client_id, nonce)` is new — or if a
    /// previous entry has expired — and records it as freshly seen.
    /// Returns `Err` if a non-expired entry already exists (replay).
    pub fn check_and_record(&self, client_id: &str, nonce: &[u8; 32]) -> Result<()> {
        let key = (client_id.to_string(), *nonce);
        let mut inner = self.inner.lock().expect("replay cache poisoned");
        if let Some(seen) = inner.get(&key)
            && seen.elapsed() < self.ttl
        {
            bail!("replay: nonce already seen for client_id {client_id:?}");
        }
        inner.insert(key, Instant::now());
        Ok(())
    }

    /// Drop entries older than [`ReplayCache::ttl`]. Returns how many.
    pub fn sweep(&self) -> usize {
        let mut inner = self.inner.lock().expect("replay cache poisoned");
        let before = inner.len();
        inner.retain(|_, seen| seen.elapsed() < self.ttl);
        before - inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    const N1: [u8; 32] = [0x11; 32];
    const N2: [u8; 32] = [0x22; 32];

    fn cache(ttl_ms: u64) -> ReplayCache {
        ReplayCache::new(Duration::from_millis(ttl_ms))
    }

    #[test]
    fn first_succeeds_second_fails() {
        let c = cache(60_000);
        c.check_and_record("alice", &N1).unwrap();
        let err = c.check_and_record("alice", &N1).unwrap_err();
        assert!(err.to_string().contains("replay"), "got: {err}");
    }

    #[test]
    fn different_clients_can_share_a_nonce() {
        let c = cache(60_000);
        c.check_and_record("alice", &N1).unwrap();
        c.check_and_record("bob", &N1).unwrap();
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn same_client_different_nonces_ok() {
        let c = cache(60_000);
        c.check_and_record("alice", &N1).unwrap();
        c.check_and_record("alice", &N2).unwrap();
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn check_after_expiry_succeeds() {
        let c = cache(50);
        c.check_and_record("alice", &N1).unwrap();
        sleep(Duration::from_millis(80));
        // Same key, now expired — should be accepted.
        c.check_and_record("alice", &N1).unwrap();
    }

    #[test]
    fn sweep_removes_expired() {
        let c = cache(50);
        c.check_and_record("alice", &N1).unwrap();
        c.check_and_record("alice", &N2).unwrap();
        sleep(Duration::from_millis(80));
        let dropped = c.sweep();
        assert_eq!(dropped, 2);
        assert!(c.is_empty());
    }

    #[test]
    fn sweep_keeps_fresh() {
        let c = cache(60_000);
        c.check_and_record("alice", &N1).unwrap();
        let dropped = c.sweep();
        assert_eq!(dropped, 0);
        assert_eq!(c.len(), 1);
    }
}
