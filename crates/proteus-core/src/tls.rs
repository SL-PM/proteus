//! Shared TLS / QUIC config helpers for server and client.
//!
//! v0.3 baseline:
//! - Server cert: self-signed (SAN `localhost`), generated fresh on
//!   startup. PEM loading from `[tls]` config lands in M6; in M3 the
//!   section is parsed but ignored (with a warning to stderr).
//! - Client verifier: `cert_sha256` hex from config pins the leaf cert.
//!   Empty pin = accept any (lab only).
//! - ALPN: `proteus/0.3`. The decoy path (M13) will distinguish via `h3`.

use std::sync::Arc;

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

/// Default transport config for both server and client. Caps the QUIC
/// idle timeout at 30 seconds so a stalled connection cannot hold a
/// server slot forever (M18 hardening — slow-loris bound).
pub fn default_transport_config() -> quinn::TransportConfig {
    let mut tc = quinn::TransportConfig::default();
    tc.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
        30_000,
    ))));
    tc
}

/// Build a Quinn server config. Returns the chosen leaf cert too, so the
/// caller can print its SHA-256 for clients to pin.
pub fn server_config(
    tls: Option<&TlsConfig>,
) -> Result<(quinn::ServerConfig, CertificateDer<'static>)> {
    if tls.is_some() {
        eprintln!(
            "warning: M3 ignores the [tls] config section; \
             using a generated self-signed cert. PEM loading lands in M6."
        );
    }
    let (cert_der, key_der) = generate_self_signed()?;

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
}
