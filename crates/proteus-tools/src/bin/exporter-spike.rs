//! M5 spike: prove Quinn 0.11 + rustls 0.23 expose RFC 5705 exporter
//! keying material on both client and server, and that both sides derive
//! the same 32 bytes for `EXPORTER-PROTEUS-v0.3`.
//!
//! Throwaway. Removed once M6 implements the real auth path on the same
//! API. See `docs/ROADMAP-v0.3.md` §M5.
//!
//! Run: `cargo run --bin exporter-spike`
//! Expected: two identical hex strings on stdout, then `MATCH`.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};

const ALPN: &[u8] = b"proteus/0.3-spike";
const EXPORTER_LABEL: &[u8] = b"EXPORTER-PROTEUS-v0.3";
const EXPORTER_LEN: usize = 32;
const SERVER_NAME: &str = "localhost";

#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

fn make_server_config() -> Result<ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())?;
    rustls_config.alpn_protocols = vec![ALPN.to_vec()];

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)?,
    ));
    Ok(server_config)
}

fn make_client_config() -> Result<ClientConfig> {
    let mut rustls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    rustls_config.alpn_protocols = vec![ALPN.to_vec()];

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)?,
    ));
    Ok(client_config)
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("crypto provider install");

    let server_endpoint = Endpoint::server(make_server_config()?, "127.0.0.1:0".parse()?)?;
    let server_addr = server_endpoint.local_addr()?;
    println!("server bound to {server_addr}");

    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .context("server: no incoming connection")?;
        let conn = incoming.await.context("server: handshake failed")?;
        let mut out = [0u8; EXPORTER_LEN];
        conn.export_keying_material(&mut out, EXPORTER_LABEL, b"")
            .map_err(|e| anyhow::anyhow!("server export failed: {e:?}"))?;
        println!("server exporter: {}", hex::encode(out));
        conn.close(0u32.into(), b"done");
        server_endpoint.wait_idle().await;
        Ok::<_, anyhow::Error>(out)
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    client_endpoint.set_default_client_config(make_client_config()?);

    let conn = client_endpoint
        .connect(server_addr, SERVER_NAME)?
        .await
        .context("client: handshake failed")?;

    let mut client_out = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut client_out, EXPORTER_LABEL, b"")
        .map_err(|e| anyhow::anyhow!("client export failed: {e:?}"))?;
    println!("client exporter: {}", hex::encode(client_out));

    conn.close(0u32.into(), b"done");
    client_endpoint.wait_idle().await;

    let server_out = server_task.await??;

    println!("---");
    if server_out == client_out {
        println!("MATCH: both sides derived identical exporter bytes.");
        Ok(())
    } else {
        anyhow::bail!("MISMATCH: server and client exporters differ");
    }
}
