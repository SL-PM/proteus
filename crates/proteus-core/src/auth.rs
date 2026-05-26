//! Exporter-bound Ed25519 authentication (spec v0.2 §7.3 + §8).
//!
//! Wire payloads ride inside PROTEUS frames on the control stream:
//! - AUTH_REQUEST  (frame type 0x0001): `[cid_len u8][cid][nonce 32][sig 64]`
//! - AUTH_RESPONSE (frame type 0x0002): `[status u8][reason_len u8][reason]`
//!
//! The signature input is `"PROTEUS-v0.3-auth" || exporter || nonce`,
//! where `exporter` is 32 bytes of RFC 5705 keying material requested
//! with label [`EXPORTER_LABEL`] and empty context. M5 proved this is
//! available on both sides of a Quinn 0.11 + rustls 0.23 connection.
//!
//! All ed25519-dalek interaction is encapsulated here; the bin crates
//! never name `SigningKey` / `VerifyingKey` directly.

use std::{collections::HashMap, path::Path};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use bytes::{BufMut, Bytes, BytesMut};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{RngCore, rngs::OsRng};

pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-PROTEUS-v0.3";
pub const EXPORTER_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;
pub const SIG_LEN: usize = 64;
pub const MAX_CLIENT_ID_LEN: usize = 64;

const SIG_PREFIX: &[u8] = b"PROTEUS-v0.3-auth";

/// AUTH_RESPONSE status code for authentication failure.
///
/// On the wire, the QUIC connection close uses the application code
/// `0x0101` (H3_GENERAL_PROTOCOL_ERROR) per spec §8.4 — defined as a
/// `u32` in the bin code.
pub const STATUS_AUTH_FAILED: u8 = 1;

// ---------- AuthRequest ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub client_id: String,
    pub nonce: [u8; NONCE_LEN],
    pub signature: [u8; SIG_LEN],
}

impl AuthRequest {
    /// Build by signing `SIG_PREFIX || exporter || nonce` with `sk`.
    pub fn sign(client_id: &str, sk: &SigningKey, exporter: &[u8; EXPORTER_LEN]) -> Result<Self> {
        check_client_id(client_id)?;
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let sig = sk.sign(&sig_input(exporter, &nonce));
        Ok(Self {
            client_id: client_id.to_string(),
            nonce,
            signature: sig.to_bytes(),
        })
    }

    /// Verify the signature against `vk` + the given exporter material.
    pub fn verify(&self, vk: &VerifyingKey, exporter: &[u8; EXPORTER_LEN]) -> Result<()> {
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&sig_input(exporter, &self.nonce), &sig)
            .context("ed25519 verify")
    }

    pub fn encode(&self) -> Result<Bytes> {
        check_client_id(&self.client_id)?;
        let cid = self.client_id.as_bytes();
        let mut buf = BytesMut::with_capacity(1 + cid.len() + NONCE_LEN + SIG_LEN);
        buf.put_u8(cid.len() as u8);
        buf.extend_from_slice(cid);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.signature);
        Ok(buf.freeze())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            bail!("AUTH_REQUEST empty");
        }
        let cid_len = bytes[0] as usize;
        if cid_len == 0 || cid_len > MAX_CLIENT_ID_LEN {
            bail!("client_id_len out of range: {cid_len}");
        }
        let need = 1 + cid_len + NONCE_LEN + SIG_LEN;
        if bytes.len() < need {
            bail!("AUTH_REQUEST truncated: have {} need {}", bytes.len(), need);
        }
        let cid_end = 1 + cid_len;
        let client_id = std::str::from_utf8(&bytes[1..cid_end])
            .context("client_id utf-8")?
            .to_string();
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[cid_end..cid_end + NONCE_LEN]);
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(&bytes[cid_end + NONCE_LEN..need]);
        Ok(Self {
            client_id,
            nonce,
            signature,
        })
    }
}

fn check_client_id(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > MAX_CLIENT_ID_LEN {
        bail!(
            "client_id length {} out of range [1, {}]",
            s.len(),
            MAX_CLIENT_ID_LEN
        );
    }
    Ok(())
}

fn sig_input(exporter: &[u8; EXPORTER_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIG_PREFIX.len() + EXPORTER_LEN + NONCE_LEN);
    v.extend_from_slice(SIG_PREFIX);
    v.extend_from_slice(exporter);
    v.extend_from_slice(nonce);
    v
}

// ---------- AuthResponse ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    pub status: u8,
    pub reason: Bytes,
}

impl AuthResponse {
    pub fn ok() -> Self {
        Self {
            status: 0,
            reason: Bytes::new(),
        }
    }

    pub fn err(code: u8) -> Self {
        debug_assert_ne!(code, 0, "use AuthResponse::ok() for status=0");
        Self {
            status: code,
            reason: Bytes::new(),
        }
    }

    pub fn encode(&self) -> Result<Bytes> {
        let reason_len = self.reason.len();
        if reason_len > u8::MAX as usize {
            bail!("AUTH_RESPONSE reason > 255 bytes");
        }
        if self.status != 0 && reason_len != 0 {
            bail!("AUTH_RESPONSE reason must be empty on status != 0 (spec §7.3)");
        }
        let mut buf = BytesMut::with_capacity(2 + reason_len);
        buf.put_u8(self.status);
        buf.put_u8(reason_len as u8);
        buf.extend_from_slice(&self.reason);
        Ok(buf.freeze())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            bail!("AUTH_RESPONSE too short");
        }
        let status = bytes[0];
        let reason_len = bytes[1] as usize;
        if bytes.len() < 2 + reason_len {
            bail!("AUTH_RESPONSE truncated");
        }
        Ok(Self {
            status,
            reason: Bytes::copy_from_slice(&bytes[2..2 + reason_len]),
        })
    }
}

// ---------- Client registry ----------

/// In-memory registry of authorized clients, built from the server YAML
/// `clients:` section.
#[derive(Debug, Default)]
pub struct ClientRegistry {
    keys: HashMap<String, VerifyingKey>,
}

impl ClientRegistry {
    pub fn from_config_map(map: Option<&HashMap<String, String>>) -> Result<Self> {
        let mut keys = HashMap::new();
        if let Some(m) = map {
            for (id, b64) in m {
                let vk = parse_public_key_b64(b64).with_context(|| format!("client {id}"))?;
                keys.insert(id.clone(), vk);
            }
        }
        Ok(Self { keys })
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Look up + verify in one call. Returns the verified client_id on
    /// success. On failure, the error is intentionally generic — callers
    /// must not leak the reason on the wire (spec §8.4).
    pub fn verify(&self, req: &AuthRequest, exporter: &[u8; EXPORTER_LEN]) -> Result<String> {
        let vk = self
            .keys
            .get(&req.client_id)
            .with_context(|| format!("unknown client_id {:?}", req.client_id))?;
        req.verify(vk, exporter)?;
        Ok(req.client_id.clone())
    }
}

// ---------- Key (de)serialization ----------

/// Decode a base64-encoded 32-byte Ed25519 public key (as produced by
/// `proteus-tools keygen`).
pub fn parse_public_key_b64(s: &str) -> Result<VerifyingKey> {
    let bytes = B64.decode(s.trim()).context("public key not base64")?;
    if bytes.len() != 32 {
        bail!("public key must be 32 bytes (got {})", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).context("invalid Ed25519 public key")
}

/// Load a base64-encoded 32-byte Ed25519 private key from disk (as
/// written by `proteus-tools keygen`).
pub fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read private key {}", path.display()))?;
    let bytes = B64.decode(body.trim()).context("private key not base64")?;
    if bytes.len() != 32 {
        bail!("private key must be 32 bytes (got {})", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&arr))
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_sk(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn fixed_exporter() -> [u8; EXPORTER_LEN] {
        [0xAB; EXPORTER_LEN]
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = fixed_sk(7);
        let exporter = fixed_exporter();
        let req = AuthRequest::sign("alice", &sk, &exporter).unwrap();
        req.verify(&sk.verifying_key(), &exporter).unwrap();
    }

    #[test]
    fn verify_fails_with_wrong_exporter() {
        let sk = fixed_sk(7);
        let req = AuthRequest::sign("alice", &sk, &fixed_exporter()).unwrap();
        assert!(
            req.verify(&sk.verifying_key(), &[0u8; EXPORTER_LEN])
                .is_err()
        );
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let sk = fixed_sk(7);
        let other = fixed_sk(42);
        let exporter = fixed_exporter();
        let req = AuthRequest::sign("alice", &sk, &exporter).unwrap();
        assert!(req.verify(&other.verifying_key(), &exporter).is_err());
    }

    #[test]
    fn sign_rejects_empty_and_overlong_client_id() {
        let sk = fixed_sk(7);
        let e = fixed_exporter();
        assert!(AuthRequest::sign("", &sk, &e).is_err());
        let long = "x".repeat(MAX_CLIENT_ID_LEN + 1);
        assert!(AuthRequest::sign(&long, &sk, &e).is_err());
    }

    #[test]
    fn request_encode_decode_roundtrip() {
        let sk = fixed_sk(7);
        let req = AuthRequest::sign("bob", &sk, &fixed_exporter()).unwrap();
        let bytes = req.encode().unwrap();
        let got = AuthRequest::decode(&bytes).unwrap();
        assert_eq!(got, req);
    }

    #[test]
    fn request_decode_rejects_empty_and_zero_cid_len() {
        assert!(AuthRequest::decode(&[]).is_err());
        let mut bad = BytesMut::new();
        bad.put_u8(0);
        bad.extend_from_slice(&[0u8; NONCE_LEN + SIG_LEN]);
        assert!(AuthRequest::decode(&bad).is_err());
    }

    #[test]
    fn request_decode_rejects_truncated_after_header() {
        let sk = fixed_sk(7);
        let req = AuthRequest::sign("alice", &sk, &fixed_exporter()).unwrap();
        let bytes = req.encode().unwrap();
        assert!(AuthRequest::decode(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn response_ok_encodes_two_bytes() {
        let bytes = AuthResponse::ok().encode().unwrap();
        assert_eq!(bytes.as_ref(), &[0, 0]);
        let got = AuthResponse::decode(&bytes).unwrap();
        assert_eq!(got, AuthResponse::ok());
    }

    #[test]
    fn response_err_with_reason_is_rejected() {
        let r = AuthResponse {
            status: STATUS_AUTH_FAILED,
            reason: Bytes::from_static(b"because"),
        };
        assert!(r.encode().is_err());
    }

    #[test]
    fn registry_verifies_known_and_rejects_unknown() {
        let sk = fixed_sk(7);
        let mut cfg = HashMap::new();
        cfg.insert(
            "alice".to_string(),
            B64.encode(sk.verifying_key().to_bytes()),
        );
        let registry = ClientRegistry::from_config_map(Some(&cfg)).unwrap();
        assert_eq!(registry.len(), 1);

        let exporter = fixed_exporter();
        let req = AuthRequest::sign("alice", &sk, &exporter).unwrap();
        assert_eq!(registry.verify(&req, &exporter).unwrap(), "alice");

        let bogus = AuthRequest::sign("eve", &sk, &exporter).unwrap();
        assert!(registry.verify(&bogus, &exporter).is_err());
    }

    #[test]
    fn parse_public_key_roundtrip() {
        let sk = fixed_sk(7);
        let b64 = B64.encode(sk.verifying_key().to_bytes());
        let vk = parse_public_key_b64(&b64).unwrap();
        assert_eq!(vk.to_bytes(), sk.verifying_key().to_bytes());
    }

    #[test]
    fn parse_public_key_rejects_wrong_length() {
        assert!(parse_public_key_b64("abcd").is_err());
    }
}
