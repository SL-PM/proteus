//! Server-side policy engine (roadmap M12).
//!
//! Decisions are taken on already-resolved IP addresses, so this module
//! is sync and DNS-free; the caller (the server bin) is expected to
//! resolve the `PROXY_OPEN` target via `tokio::net::lookup_host` before
//! invoking the policy checks.
//!
//! Configuration shape (server YAML `policy:` section):
//!
//! ```yaml
//! policy:
//!   block_private_ranges: true        # reject loopback / RFC1918 / link-local
//!   allowed_ports: [80, 443, 8080]    # empty list = no allowlist constraint
//!   denied_ports: [22, 25]            # always rejected, even if also allowed
//!   allow_udp: false                  # gate UDP traffic separately from TCP
//! ```
//!
//! Precedence: deny list > allow list > address range. `allow_udp` gates
//! UDP traffic before any of the above.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};

use crate::config::PolicyConfig;

/// In-memory representation of a `PolicyConfig`, optimized for repeated
/// lookups during a server's lifetime. Cheap to clone (Vec<u16> is small).
#[derive(Debug, Clone)]
pub struct PolicyChecker {
    block_private_ranges: bool,
    allowed_ports: Vec<u16>,
    denied_ports: Vec<u16>,
    allow_udp: bool,
}

impl PolicyChecker {
    pub fn from_config(cfg: &PolicyConfig) -> Self {
        Self {
            block_private_ranges: cfg.block_private_ranges,
            allowed_ports: cfg.allowed_ports.clone(),
            denied_ports: cfg.denied_ports.clone(),
            allow_udp: cfg.allow_udp,
        }
    }

    /// Check that a TCP target is allowed by policy.
    pub fn check_tcp(&self, port: u16, resolved: &[IpAddr]) -> Result<()> {
        self.check_port(port)?;
        self.check_addrs(resolved)?;
        Ok(())
    }

    /// Check that a UDP target is allowed. UDP is gated by `allow_udp`
    /// in addition to the port + address-range checks.
    pub fn check_udp(&self, port: u16, resolved: &[IpAddr]) -> Result<()> {
        if !self.allow_udp {
            bail!("UDP traffic disabled by policy");
        }
        self.check_port(port)?;
        self.check_addrs(resolved)?;
        Ok(())
    }

    fn check_port(&self, port: u16) -> Result<()> {
        if self.denied_ports.contains(&port) {
            bail!("port {port} is on the deny list");
        }
        if !self.allowed_ports.is_empty() && !self.allowed_ports.contains(&port) {
            bail!("port {port} is not on the allow list");
        }
        Ok(())
    }

    fn check_addrs(&self, addrs: &[IpAddr]) -> Result<()> {
        if !self.block_private_ranges {
            return Ok(());
        }
        if addrs.is_empty() {
            bail!("no resolved addresses to check");
        }
        for ip in addrs {
            if is_blocked(*ip) {
                bail!("{ip} is in a blocked range (loopback / private / link-local)");
            }
        }
        Ok(())
    }
}

/// Returns true if `ip` is in a range that `block_private_ranges` rejects.
///
/// IPv4: loopback (127/8), RFC1918 (10/8, 172.16/12, 192.168/16),
/// link-local (169.254/16), unspecified (0.0.0.0), broadcast
/// (255.255.255.255), TEST-NET documentation ranges.
///
/// IPv6: loopback (::1), unspecified (::), link-local (fe80::/10),
/// unique-local (fc00::/7).
pub fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v4(v4: Ipv4Addr) -> bool {
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_documentation()
}

fn is_blocked_v6(v6: Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() {
        return true;
    }
    let first = v6.segments()[0];
    // Link-local fe80::/10
    if first & 0xffc0 == 0xfe80 {
        return true;
    }
    // Unique-local fc00::/7
    if first & 0xfe00 == 0xfc00 {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(
        block_private: bool,
        allowed: Vec<u16>,
        denied: Vec<u16>,
        allow_udp: bool,
    ) -> PolicyChecker {
        PolicyChecker {
            block_private_ranges: block_private,
            allowed_ports: allowed,
            denied_ports: denied,
            allow_udp,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_policy_allows_everything() {
        let p = mk(false, vec![], vec![], true);
        p.check_tcp(80, &[ip("127.0.0.1")]).unwrap();
        p.check_tcp(443, &[ip("8.8.8.8")]).unwrap();
        p.check_udp(53, &[ip("1.1.1.1")]).unwrap();
    }

    #[test]
    fn block_private_rejects_v4_loopback() {
        let p = mk(true, vec![], vec![], true);
        assert!(p.check_tcp(80, &[ip("127.0.0.1")]).is_err());
        assert!(p.check_tcp(80, &[ip("127.5.5.5")]).is_err());
    }

    #[test]
    fn block_private_rejects_v4_rfc1918() {
        let p = mk(true, vec![], vec![], true);
        assert!(p.check_tcp(80, &[ip("10.0.0.1")]).is_err());
        assert!(p.check_tcp(80, &[ip("172.16.0.1")]).is_err());
        assert!(p.check_tcp(80, &[ip("192.168.1.1")]).is_err());
    }

    #[test]
    fn block_private_rejects_v4_link_local_and_broadcast() {
        let p = mk(true, vec![], vec![], true);
        assert!(p.check_tcp(80, &[ip("169.254.1.1")]).is_err());
        assert!(p.check_tcp(80, &[ip("255.255.255.255")]).is_err());
        assert!(p.check_tcp(80, &[ip("0.0.0.0")]).is_err());
    }

    #[test]
    fn block_private_allows_v4_public() {
        let p = mk(true, vec![], vec![], true);
        p.check_tcp(80, &[ip("8.8.8.8")]).unwrap();
        p.check_tcp(443, &[ip("1.1.1.1")]).unwrap();
    }

    #[test]
    fn block_private_rejects_v6_loopback_link_local_unique() {
        let p = mk(true, vec![], vec![], true);
        assert!(p.check_tcp(80, &[ip("::1")]).is_err());
        assert!(p.check_tcp(80, &[ip("fe80::1")]).is_err());
        assert!(p.check_tcp(80, &[ip("fc00::1")]).is_err());
    }

    #[test]
    fn block_private_allows_v6_public() {
        let p = mk(true, vec![], vec![], true);
        p.check_tcp(443, &[ip("2606:4700:4700::1111")]).unwrap();
    }

    #[test]
    fn block_private_rejects_if_any_resolved_is_private() {
        let p = mk(true, vec![], vec![], true);
        // Defense against split DNS rebinding: any private hit fails.
        let err = p
            .check_tcp(80, &[ip("8.8.8.8"), ip("127.0.0.1")])
            .unwrap_err();
        assert!(err.to_string().contains("127.0.0.1"), "got: {err}");
    }

    #[test]
    fn empty_allowed_ports_means_no_allowlist() {
        let p = mk(false, vec![], vec![], true);
        p.check_tcp(80, &[ip("1.1.1.1")]).unwrap();
        p.check_tcp(12345, &[ip("1.1.1.1")]).unwrap();
    }

    #[test]
    fn allowed_ports_enforced() {
        let p = mk(false, vec![80, 443], vec![], true);
        p.check_tcp(80, &[ip("1.1.1.1")]).unwrap();
        p.check_tcp(443, &[ip("1.1.1.1")]).unwrap();
        assert!(p.check_tcp(22, &[ip("1.1.1.1")]).is_err());
    }

    #[test]
    fn denied_ports_take_precedence_over_allowed() {
        let p = mk(false, vec![22, 443], vec![22], true);
        p.check_tcp(443, &[ip("1.1.1.1")]).unwrap();
        assert!(p.check_tcp(22, &[ip("1.1.1.1")]).is_err());
    }

    #[test]
    fn allow_udp_gates_udp_only() {
        let p_off = mk(false, vec![], vec![], false);
        assert!(p_off.check_udp(53, &[ip("1.1.1.1")]).is_err());
        // TCP is unaffected when allow_udp = false.
        p_off.check_tcp(443, &[ip("1.1.1.1")]).unwrap();

        let p_on = mk(false, vec![], vec![], true);
        p_on.check_udp(53, &[ip("1.1.1.1")]).unwrap();
    }

    #[test]
    fn from_config_round_trip() {
        let cfg = PolicyConfig {
            block_private_ranges: true,
            allowed_ports: vec![80, 443],
            denied_ports: vec![22],
            allow_udp: false,
        };
        let p = PolicyChecker::from_config(&cfg);
        p.check_tcp(443, &[ip("1.1.1.1")]).unwrap();
        assert!(p.check_tcp(22, &[ip("1.1.1.1")]).is_err());
        assert!(p.check_tcp(443, &[ip("10.0.0.1")]).is_err());
        assert!(p.check_udp(443, &[ip("1.1.1.1")]).is_err());
    }
}
