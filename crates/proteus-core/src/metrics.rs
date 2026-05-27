//! Runtime counters for the PROTEUS server (roadmap M17).
//!
//! Atomic counters updated by the hot path (auth, replay, policy, and
//! proxy handlers) and snapshot for periodic stderr logging by a
//! background task. v0.3 keeps this in-process only; an HTTP metrics
//! endpoint would be a natural follow-up.
//!
//! Byte counters (e.g. bytes_client_to_upstream) are intentionally
//! out of scope here — they would require threading a metrics handle
//! through `proxy::bridge_quic_{tcp,udp}` and are deferred to M17.1.

use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Debug, Default)]
pub struct Metrics {
    pub auth_attempts: AtomicU64,
    pub auth_success: AtomicU64,
    pub auth_failed: AtomicU64,
    pub rate_limited: AtomicU64,
    pub replay_rejected: AtomicU64,
    pub policy_rejected: AtomicU64,
    pub proxy_tcp_opened: AtomicU64,
    pub proxy_udp_opened: AtomicU64,
    pub proxy_upstream_unreachable: AtomicU64,
    pub active_sessions: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            auth_attempts: self.auth_attempts.load(Ordering::Relaxed),
            auth_success: self.auth_success.load(Ordering::Relaxed),
            auth_failed: self.auth_failed.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            replay_rejected: self.replay_rejected.load(Ordering::Relaxed),
            policy_rejected: self.policy_rejected.load(Ordering::Relaxed),
            proxy_tcp_opened: self.proxy_tcp_opened.load(Ordering::Relaxed),
            proxy_udp_opened: self.proxy_udp_opened.load(Ordering::Relaxed),
            proxy_upstream_unreachable: self.proxy_upstream_unreachable.load(Ordering::Relaxed),
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
        }
    }

    pub fn auth_attempt(&self) {
        self.auth_attempts.fetch_add(1, Ordering::Relaxed);
    }
    pub fn auth_success_inc(&self) {
        self.auth_success.fetch_add(1, Ordering::Relaxed);
    }
    pub fn auth_failed_inc(&self) {
        self.auth_failed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn rate_limited_inc(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }
    pub fn replay_rejected_inc(&self) {
        self.replay_rejected.fetch_add(1, Ordering::Relaxed);
    }
    pub fn policy_rejected_inc(&self) {
        self.policy_rejected.fetch_add(1, Ordering::Relaxed);
    }
    pub fn proxy_tcp_opened_inc(&self) {
        self.proxy_tcp_opened.fetch_add(1, Ordering::Relaxed);
    }
    pub fn proxy_udp_opened_inc(&self) {
        self.proxy_udp_opened.fetch_add(1, Ordering::Relaxed);
    }
    pub fn proxy_upstream_unreachable_inc(&self) {
        self.proxy_upstream_unreachable
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn active_session_inc(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }
    pub fn active_session_dec(&self) {
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub auth_attempts: u64,
    pub auth_success: u64,
    pub auth_failed: u64,
    pub rate_limited: u64,
    pub replay_rejected: u64,
    pub policy_rejected: u64,
    pub proxy_tcp_opened: u64,
    pub proxy_udp_opened: u64,
    pub proxy_upstream_unreachable: u64,
    pub active_sessions: u64,
}

impl fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "auth:    {} attempts ({} ok, {} failed)",
            self.auth_attempts, self.auth_success, self.auth_failed
        )?;
        writeln!(
            f,
            "reject:  {} replay, {} policy, {} rate-limited, {} upstream unreachable",
            self.replay_rejected,
            self.policy_rejected,
            self.rate_limited,
            self.proxy_upstream_unreachable
        )?;
        writeln!(
            f,
            "proxy:   {} tcp + {} udp streams opened",
            self.proxy_tcp_opened, self.proxy_udp_opened
        )?;
        write!(f, "active:  {} sessions", self.active_sessions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_metrics_are_all_zero() {
        let m = Metrics::new();
        assert_eq!(m.snapshot(), MetricsSnapshot::default());
    }

    #[test]
    fn counters_increment() {
        let m = Metrics::new();
        m.auth_attempt();
        m.auth_attempt();
        m.auth_success_inc();
        m.replay_rejected_inc();
        m.policy_rejected_inc();
        m.proxy_tcp_opened_inc();
        m.proxy_udp_opened_inc();
        m.proxy_upstream_unreachable_inc();
        m.rate_limited_inc();
        let s = m.snapshot();
        assert_eq!(s.auth_attempts, 2);
        assert_eq!(s.auth_success, 1);
        assert_eq!(s.replay_rejected, 1);
        assert_eq!(s.policy_rejected, 1);
        assert_eq!(s.rate_limited, 1);
        assert_eq!(s.proxy_tcp_opened, 1);
        assert_eq!(s.proxy_udp_opened, 1);
        assert_eq!(s.proxy_upstream_unreachable, 1);
    }

    #[test]
    fn active_sessions_inc_dec() {
        let m = Metrics::new();
        m.active_session_inc();
        m.active_session_inc();
        m.active_session_inc();
        m.active_session_dec();
        assert_eq!(m.snapshot().active_sessions, 2);
    }

    #[test]
    fn snapshot_display_includes_all_categories() {
        let m = Metrics::new();
        m.auth_attempt();
        m.auth_success_inc();
        m.proxy_tcp_opened_inc();
        m.active_session_inc();
        let display = format!("{}", m.snapshot());
        assert!(display.contains("1 attempts"));
        assert!(display.contains("1 ok"));
        assert!(display.contains("1 tcp"));
        assert!(display.contains("1 sessions"));
    }

    #[test]
    fn counters_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Metrics>();
        assert_send_sync::<MetricsSnapshot>();
    }
}
