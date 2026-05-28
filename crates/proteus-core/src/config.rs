//! YAML config schemas for `proteus-server` and `proteus-client`.
//!
//! The schema is forward-looking: fields used only by later milestones
//! (M6 auth, M12 policy, M13 decoy, etc.) are `Option`-typed so M1 can
//! parse a full example config without the later code being present yet.

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ---------- server ----------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub listen: ListenConfig,
    /// M6+: TLS cert/key for the QUIC listener.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// M2/M6: client_id -> base64-encoded Ed25519 public key.
    #[serde(default)]
    pub clients: Option<HashMap<String, String>>,
    /// M12: policy engine.
    #[serde(default)]
    pub policy: Option<PolicyConfig>,
    /// M13: local H3 decoy.
    #[serde(default)]
    pub decoy: Option<DecoyConfig>,
    /// v0.5 M1.5+: bucket padding for outgoing frames.
    #[serde(default)]
    pub padding: PaddingConfig,
    /// v0.5 M3.5: server-side idle dummy traffic.
    #[serde(default)]
    pub idle_padding: IdlePaddingConfig,
    /// v0.5-rc.2 M6.5: inter-arrival timing jitter on the send path.
    #[serde(default)]
    pub timing_jitter: TimingJitterConfig,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListenConfig {
    pub addr: SocketAddr,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub block_private_ranges: bool,
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
    #[serde(default)]
    pub denied_ports: Vec<u16>,
    #[serde(default)]
    pub allow_udp: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DecoyConfig {
    pub static_page: PathBuf,
    /// M8.4.1: optional JSON snapshot of the cover host's response
    /// headers (produced by `proteus-tools fetch-decoy --out-headers`).
    /// When absent, the server falls back to a hardcoded minimal
    /// nginx-style header set (M3.4 original behavior).
    #[serde(default)]
    pub static_headers: Option<PathBuf>,
}

/// v0.5 M1.5+: bucket padding for wire-fingerprint reduction.
///
/// Both server and client carry the same shape, and both ends MUST be
/// configured identically in v0.5-rc.1 — there's no protocol-level
/// negotiation. Mismatched padding settings produce decode errors on
/// the receiving side.
///
/// Read paths auto-depad regardless of this config (the `FLAG_PADDED`
/// bit on the wire is self-describing). Write paths consult this
/// config to decide whether to pad outgoing frames.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PaddingConfig {
    /// Master switch. `false` (default) = behave exactly like v0.4.
    #[serde(default)]
    pub enabled: bool,
    /// Bucket sizes in bytes. Defaults to
    /// [`crate::padding::DEFAULT_BUCKETS`] when omitted or empty.
    #[serde(default)]
    pub buckets: Vec<usize>,
}

impl PaddingConfig {
    /// Effective bucket set: caller's explicit override if non-empty,
    /// otherwise the workspace default.
    pub fn effective_buckets(&self) -> &[usize] {
        if self.buckets.is_empty() {
            crate::padding::DEFAULT_BUCKETS
        } else {
            &self.buckets
        }
    }
}

/// v0.5 M3.5: server-side idle dummy traffic. When enabled, the server
/// emits one PING frame per proxy stream after `interval_secs` of
/// stream-quiet time (no real DATA flowing server→client), eliminating
/// the "PROTEUS-idle = total silence" wire signal. Server-only — the
/// client discards inbound PING frames regardless.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdlePaddingConfig {
    /// Master switch. Default false.
    #[serde(default)]
    pub enabled: bool,
    /// Seconds of stream-quiet before a dummy PING is sent. Default 5.
    #[serde(default = "default_idle_interval_secs")]
    pub interval_secs: u64,
    /// Wire `payload_len` bucket the dummy PING is padded to. Default
    /// 1024. Should be one of the `padding.buckets` values for
    /// consistency, though it's not required to be.
    #[serde(default = "default_idle_bucket")]
    pub bucket: usize,
}

fn default_idle_interval_secs() -> u64 {
    5
}

fn default_idle_bucket() -> usize {
    1024
}

impl Default for IdlePaddingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_idle_interval_secs(),
            bucket: default_idle_bucket(),
        }
    }
}

/// v0.5-rc.2 M6.5: inter-arrival timing jitter. A bounded random delay
/// is applied before each outgoing proxy-stream frame, decorrelating
/// PROTEUS's send timing from the application's data-production timing.
///
/// Sender-side only — there is NO wire-format change and NO lockstep
/// requirement. Each end may enable this independently. See
/// [`PROTEUS-v0.5-plan.md`](../../../docs/PROTEUS-v0.5-plan.md) §11.
///
/// The cost is throughput: a uniform `[min_ms, max_ms]` delay adds an
/// average of `(min+max)/2` ms of latency per frame. Keep the range
/// small for bulk traffic; widen it only for low-volume/interactive use.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TimingJitterConfig {
    /// Master switch. Default false = no delay, behave like rc.1.
    #[serde(default)]
    pub enabled: bool,
    /// Lower bound of the uniform delay in milliseconds. Default 0.
    #[serde(default)]
    pub min_ms: u64,
    /// Upper bound of the uniform delay in milliseconds. Default 5.
    #[serde(default = "default_jitter_max_ms")]
    pub max_ms: u64,
}

fn default_jitter_max_ms() -> u64 {
    5
}

impl Default for TimingJitterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_ms: 0,
            max_ms: default_jitter_max_ms(),
        }
    }
}

impl TimingJitterConfig {
    /// Validate the range. Returns an error if `min_ms > max_ms` so a
    /// misconfigured deployment fails loudly at startup rather than
    /// silently swapping the bounds.
    pub fn validate(&self) -> Result<()> {
        if self.enabled && self.min_ms > self.max_ms {
            anyhow::bail!(
                "timing_jitter.min_ms ({}) must be <= max_ms ({})",
                self.min_ms,
                self.max_ms
            );
        }
        Ok(())
    }
}

impl ServerConfig {
    pub fn from_yaml_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read server config {}", path.display()))?;
        serde_yaml::from_str(&raw)
            .with_context(|| format!("parse server config {}", path.display()))
    }
}

// ---------- client ----------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientConfig {
    pub server: ServerEndpoint,
    pub identity: ClientIdentity,
    pub socks5: Socks5Config,
    /// v0.5 M1.5+: bucket padding for outgoing frames.
    #[serde(default)]
    pub padding: PaddingConfig,
    /// v0.5-rc.2 M6.5: inter-arrival timing jitter on the send path.
    #[serde(default)]
    pub timing_jitter: TimingJitterConfig,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerEndpoint {
    pub addr: SocketAddr,
    pub sni: String,
    /// SHA-256 hex of the server cert (TOFU pin). Empty = accept any
    /// (v0.3 lab only, equivalent to the spike's `AcceptAnyCert`).
    #[serde(default)]
    pub cert_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientIdentity {
    pub client_id: String,
    pub private_key: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Socks5Config {
    pub listen: SocketAddr,
}

impl ClientConfig {
    pub fn from_yaml_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read client config {}", path.display()))?;
        serde_yaml::from_str(&raw)
            .with_context(|| format!("parse client config {}", path.display()))
    }
}

// ---------- defaults ----------

fn default_log_level() -> String {
    "info".to_string()
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_EXAMPLE: &str = include_str!("../../../configs/server.example.yaml");
    const CLIENT_EXAMPLE: &str = include_str!("../../../configs/client.example.yaml");

    #[test]
    fn server_example_parses() {
        let cfg: ServerConfig = serde_yaml::from_str(SERVER_EXAMPLE).unwrap();
        assert_eq!(cfg.listen.addr.to_string(), "0.0.0.0:4433");
        assert_eq!(cfg.log_level, "info");
        let policy = cfg.policy.expect("policy section present in example");
        assert!(policy.block_private_ranges);
        assert!(policy.allowed_ports.contains(&443));
        assert!(!policy.allow_udp);
        // The `tls:` section is commented out in the example as of
        // v0.4 M4.4 — server falls back to a self-signed cert when
        // absent, which is the safer default for an example anyone
        // can copy-paste. See docs/CONFIG.md.
        assert!(cfg.tls.is_none(), "example should have tls commented out");
    }

    #[test]
    fn client_example_parses() {
        let cfg: ClientConfig = serde_yaml::from_str(CLIENT_EXAMPLE).unwrap();
        assert_eq!(cfg.server.addr.to_string(), "127.0.0.1:4433");
        assert_eq!(cfg.server.sni, "localhost");
        assert_eq!(cfg.identity.client_id, "alice");
        assert_eq!(cfg.socks5.listen.to_string(), "127.0.0.1:1080");
        assert_eq!(cfg.log_level, "info");
    }

    #[test]
    fn missing_required_field_errors() {
        let bad = "log_level: debug\n";
        let err = serde_yaml::from_str::<ServerConfig>(bad).unwrap_err();
        assert!(err.to_string().contains("listen"), "got: {err}");
    }
}
