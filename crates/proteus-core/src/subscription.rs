//! Subscription blob: a self-contained, one-click client config (v0.6).
//!
//! The panel generates one per client (at creation, while it still has
//! the private key); the client app imports it to connect — no manual
//! field entry, à la Hiddify/vmess subscription links.
//!
//! Wire form: `proteus://<base64url(json)>`, where the JSON is this
//! struct. The blob carries the **private key**, so it IS the credential
//! — treat it like a password (anyone with the blob can connect as that
//! client). Distribute over a trusted channel; the panel shows/QR-codes
//! it exactly once.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

/// URL scheme prefix for PROTEUS subscription links.
pub const SCHEME: &str = "proteus://";

/// Everything a client needs to connect, in one importable blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    /// Server endpoint, `host:port` (e.g. `212.227.12.251:4433`).
    pub server_addr: String,
    /// TLS SNI to present.
    pub sni: String,
    /// Lowercase-hex SHA-256 pin of the server's leaf cert (empty =
    /// accept any, lab only).
    pub cert_sha256: String,
    /// PROTEUS client_id.
    pub client_id: String,
    /// Base64 (standard) Ed25519 private key — the credential.
    pub private_key_b64: String,
    /// Optional human label (shown in the client app).
    #[serde(default)]
    pub label: String,
}

impl Subscription {
    /// Encode as a `proteus://<base64url(json)>` link.
    pub fn to_url(&self) -> String {
        let json = serde_json::to_vec(self).expect("Subscription serializes");
        format!("{SCHEME}{}", URL_SAFE_NO_PAD.encode(json))
    }

    /// Parse a `proteus://…` link (tolerates surrounding whitespace).
    pub fn from_url(s: &str) -> Result<Self> {
        let s = s.trim();
        let b64 = s
            .strip_prefix(SCHEME)
            .with_context(|| format!("subscription must start with `{SCHEME}`"))?;
        let json = URL_SAFE_NO_PAD
            .decode(b64.trim())
            .context("subscription payload not valid base64url")?;
        let sub: Subscription =
            serde_json::from_slice(&json).context("subscription payload not valid JSON")?;
        if sub.server_addr.is_empty() || sub.client_id.is_empty() || sub.private_key_b64.is_empty()
        {
            bail!("subscription missing server_addr / client_id / private_key");
        }
        Ok(sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Subscription {
        Subscription {
            server_addr: "212.227.12.251:4433".into(),
            sni: "localhost".into(),
            cert_sha256: "2902a743b97e3b511c012c7a47b4bf2518a144a606a8bf58a2c15b7c93610e7c".into(),
            client_id: "c-Cmq-JNmO".into(),
            private_key_b64: "Aiv/TbMjaI8STgiAstSoApoPPFAkLKYUyjNM74abrno=".into(),
            label: "kunde-1".into(),
        }
    }

    #[test]
    fn url_roundtrip() {
        let s = sample();
        let url = s.to_url();
        assert!(url.starts_with("proteus://"));
        let back = Subscription::from_url(&url).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn roundtrip_tolerates_whitespace() {
        let url = sample().to_url();
        let padded = format!("  {url}\n");
        assert_eq!(Subscription::from_url(&padded).unwrap(), sample());
    }

    #[test]
    fn rejects_wrong_scheme() {
        let err = Subscription::from_url("https://example.com").unwrap_err();
        assert!(err.to_string().contains("proteus://"), "got: {err}");
    }

    #[test]
    fn rejects_garbage_payload() {
        assert!(Subscription::from_url("proteus://!!!notbase64!!!").is_err());
        // valid base64url of non-JSON
        let bad = format!("proteus://{}", URL_SAFE_NO_PAD.encode(b"not json"));
        assert!(Subscription::from_url(&bad).is_err());
    }

    #[test]
    fn rejects_missing_fields() {
        let mut s = sample();
        s.client_id = String::new();
        let url = s.to_url();
        let err = Subscription::from_url(&url).unwrap_err();
        assert!(err.to_string().contains("missing"), "got: {err}");
    }
}
