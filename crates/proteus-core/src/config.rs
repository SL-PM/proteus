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
