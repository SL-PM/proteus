//! Shared TLS / QUIC config helpers for server and client.
//!
//! v0.4 status (M4.4 — PEM cert loading lands here):
//! - Server cert: PEM cert chain + PKCS#8/PKCS#1/SEC1 private key
//!   loaded from `tls.cert` / `tls.key` if the YAML config has them.
//!   Falls back to a fresh self-signed cert (SAN `localhost`) per
//!   startup if the `tls:` section is absent — convenient for local
//!   dev only; **not** for any real deployment.
//! - Client verifier: `cert_sha256` hex from config pins the leaf cert.
//!   Empty pin = accept any (lab only).
//! - ALPN: `proteus/0.3` and `h3`. Server dispatches on negotiated
//!   ALPN post-handshake (M13 decoy). v0.4 M1.4+M2.4 will drop the
//!   distinctive `proteus/0.3` ALPN; until then it stays.

use std::{fs::File, io::BufReader, path::Path, sync::Arc};

use anyhow::{Context, Result, bail};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};

use crate::config::TlsConfig;

/// ALPN identifier for PROTEUS v0.3 traffic.
pub const ALPN: &[u8] = b"proteus/0.3";

/// Install the default rustls crypto provider. Idempotent.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Default transport config for both server and client.
///
/// - Caps the QUIC idle timeout at 30 seconds (M18 — slow-loris bound).
/// - Leaves connection migration ON (Quinn default). PROTEUS's
///   replay cache is keyed on `client_id` not 5-tuple, so a migration
///   doesn't disturb the auth state. See `docs/m7.4-connection-migration.md`.
pub fn default_transport_config() -> quinn::TransportConfig {
    let mut tc = quinn::TransportConfig::default();
    tc.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
        30_000,
    ))));
    tc
}

/// Build a Quinn server config. Returns the chosen leaf cert too, so the
/// caller can print its SHA-256 for clients to pin.
///
/// If `tls` is `Some(...)`, both files are loaded from disk as PEM. If
/// `None`, a fresh self-signed cert is generated on every call (dev
/// only — operators must set `tls:` for production).
pub fn server_config(
    tls: Option<&TlsConfig>,
) -> Result<(quinn::ServerConfig, CertificateDer<'static>)> {
    let (cert_der, key_der) = match tls {
        Some(tc) => load_pem_cert_and_key(&tc.cert, &tc.key)?,
        None => generate_self_signed()?,
    };

    let mut rustls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)?;
    // Server advertises both PROTEUS and HTTP/3. Post-handshake the
    // bin dispatches on the negotiated ALPN (M13 decoy).
    rustls_cfg.alpn_protocols = vec![ALPN.to_vec(), b"h3".to_vec()];

    let mut qcfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg)?,
    ));
    qcfg.transport_config(Arc::new(default_transport_config()));
    Ok((qcfg, cert_der))
}

/// Build a Quinn client config. `pin_sha256_hex` is lowercase hex of the
/// SHA-256 over the server cert DER; empty = accept any (v0.3 lab only).
pub fn client_config(pin_sha256_hex: &str) -> Result<quinn::ClientConfig> {
    let verifier: Arc<dyn ServerCertVerifier> = if pin_sha256_hex.trim().is_empty() {
        Arc::new(AcceptAnyCert)
    } else {
        let want = hex::decode(pin_sha256_hex.trim()).context("cert_sha256 must be hex")?;
        if want.len() != 32 {
            bail!(
                "cert_sha256 must be 32 bytes (got {} bytes; need lowercase hex SHA-256)",
                want.len()
            );
        }
        Arc::new(PinnedSha256 { want })
    };

    let mut rustls_cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    rustls_cfg.alpn_protocols = vec![ALPN.to_vec()];

    let mut ccfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)?,
    ));
    ccfg.transport_config(Arc::new(default_transport_config()));
    Ok(ccfg)
}

/// Lowercase hex SHA-256 of a certificate DER. For logging and pinning.
pub fn cert_sha256_hex(cert: &CertificateDer<'_>) -> String {
    let mut h = Sha256::new();
    h.update(cert.as_ref());
    hex::encode(h.finalize())
}

fn generate_self_signed() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into();
    Ok((cert_der, key_der))
}

/// Load a PEM cert chain + private key from disk. Returns the leaf
/// cert (first in the chain) plus the parsed key. Accepts PKCS#8,
/// PKCS#1, and SEC1 key formats — rustls-pemfile detects automatically.
fn load_pem_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let cert_file =
        File::open(cert_path).with_context(|| format!("open cert {}", cert_path.display()))?;
    let mut rd = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut rd)
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("parse cert PEM {}", cert_path.display()))?;
    let cert_der = certs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no certificates found in {}", cert_path.display()))?;

    let key_file =
        File::open(key_path).with_context(|| format!("open key {}", key_path.display()))?;
    let mut rd = BufReader::new(key_file);
    let key_der = rustls_pemfile::private_key(&mut rd)
        .with_context(|| format!("parse key PEM {}", key_path.display()))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path.display()))?;

    Ok((cert_der, key_der))
}

const SUPPORTED_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
];

#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SUPPORTED_SCHEMES.to_vec()
    }
}

#[derive(Debug)]
struct PinnedSha256 {
    want: Vec<u8>,
}

impl ServerCertVerifier for PinnedSha256 {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut h = Sha256::new();
        h.update(end_entity.as_ref());
        let got = h.finalize().to_vec();
        if got == self.want {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "cert pin mismatch: got {}, want {}",
                hex::encode(&got),
                hex::encode(&self.want)
            )))
        }
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SUPPORTED_SCHEMES.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn server_config_with_self_signed() {
        install_crypto_provider();
        let (_cfg, cert) = server_config(None).unwrap();
        assert!(cert.as_ref().len() > 50);
        let fp = cert_sha256_hex(&cert);
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn client_config_accepts_empty_pin() {
        install_crypto_provider();
        client_config("").unwrap();
        client_config("   ").unwrap();
    }

    #[test]
    fn client_config_rejects_short_pin() {
        install_crypto_provider();
        let err = client_config("abcd").unwrap_err();
        assert!(err.to_string().contains("32 bytes"), "got: {err}");
    }

    #[test]
    fn client_config_rejects_non_hex_pin() {
        install_crypto_provider();
        let err = client_config(
            "not-hex-at-all-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        )
        .unwrap_err();
        assert!(err.to_string().contains("hex"), "got: {err}");
    }

    /// Helper: write a fresh self-signed cert + key pair as PEM to
    /// `dir`. Returns the two paths.
    fn write_self_signed_pem(dir: &Path) -> (PathBuf, PathBuf) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();
        (cert_path, key_path)
    }

    #[test]
    fn server_config_loads_pem_cert_and_key() {
        install_crypto_provider();
        let dir = tempdir().unwrap();
        let (cert_path, key_path) = write_self_signed_pem(dir.path());
        let tls = TlsConfig {
            cert: cert_path,
            key: key_path,
        };
        let (_cfg, cert) = server_config(Some(&tls)).unwrap();
        assert!(cert.as_ref().len() > 50);
        let fp = cert_sha256_hex(&cert);
        assert_eq!(fp.len(), 64);
    }

    #[test]
    fn server_config_pem_missing_cert_errors() {
        install_crypto_provider();
        let dir = tempdir().unwrap();
        let (_, key_path) = write_self_signed_pem(dir.path());
        let tls = TlsConfig {
            cert: dir.path().join("does-not-exist.pem"),
            key: key_path,
        };
        let err = server_config(Some(&tls)).unwrap_err();
        assert!(err.to_string().contains("open cert"), "got: {err}");
    }

    #[test]
    fn server_config_pem_missing_key_errors() {
        install_crypto_provider();
        let dir = tempdir().unwrap();
        let (cert_path, _) = write_self_signed_pem(dir.path());
        let tls = TlsConfig {
            cert: cert_path,
            key: dir.path().join("does-not-exist.pem"),
        };
        let err = server_config(Some(&tls)).unwrap_err();
        assert!(err.to_string().contains("open key"), "got: {err}");
    }

    #[test]
    fn server_config_pem_garbage_cert_errors() {
        install_crypto_provider();
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("garbage.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, b"not a pem cert").unwrap();
        std::fs::write(&key_path, b"not a pem key").unwrap();
        let tls = TlsConfig {
            cert: cert_path,
            key: key_path,
        };
        let err = server_config(Some(&tls)).unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("certif") || msg.contains("no certificates"),
            "got: {err}"
        );
    }
}
