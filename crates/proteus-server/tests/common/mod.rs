//! Shared helpers for proteus-server integration tests.
//!
//! Each `tests/*.rs` file is its own integration-test binary; they
//! pull this in via `mod common;`. Helpers cover:
//! - Building a `ServerConfig` programmatically (no YAML files needed)
//! - Generating a fresh Ed25519 keypair for the test client
//! - Starting a `Server` on `127.0.0.1:0` in a background tokio task
//! - Driving a minimal PROTEUS client through the auth handshake on
//!   a freshly built `quinn::Endpoint`.
//!
//! All helpers are async or pure — no global state, no env vars.

#![allow(dead_code)] // not every test uses every helper

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{SigningKey, VerifyingKey};
use proteus_core::{
    aead::{self, ProxyStreamAead},
    auth::{AuthRequest, AuthResponse, EXPORTER_LABEL, EXPORTER_LEN},
    config::{IdlePaddingConfig, ListenConfig, PaddingConfig, PolicyConfig, ServerConfig},
    frame::{Frame, FrameType, read_frame, read_frame_aead, write_frame, write_frame_aead},
    proxy::ProxyOpen,
    tls,
};
use proteus_server::Server;
use rand::rngs::OsRng;

/// Test fixture: a started server plus the cert pin + ed25519 client
/// keypair the test needs to talk to it.
pub struct TestServer {
    pub addr: SocketAddr,
    pub cert_sha256: String,
    pub client_id: String,
    pub signing_key: SigningKey,
    pub metrics: Arc<proteus_core::metrics::Metrics>,
    _join: tokio::task::JoinHandle<Result<()>>,
}

impl TestServer {
    /// Start a `proteus-server` listening on an ephemeral port. The
    /// server is configured with a single client (`client_id`) whose
    /// freshly-generated keypair is returned for the test to sign
    /// with. Policy is wide open. Decoy is the embedded default.
    pub async fn start(client_id: &str) -> Result<Self> {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let vk = sk.verifying_key();

        let mut clients = HashMap::new();
        clients.insert(client_id.to_string(), B64.encode(vk.to_bytes()));

        let cfg = ServerConfig {
            listen: ListenConfig {
                addr: "127.0.0.1:0".parse().unwrap(),
            },
            tls: None,
            clients: Some(clients),
            policy: Some(PolicyConfig {
                block_private_ranges: false,
                allowed_ports: vec![],
                denied_ports: vec![],
                allow_udp: true,
            }),
            decoy: None,
            padding: PaddingConfig::default(),
            idle_padding: IdlePaddingConfig::default(),
            log_level: "info".to_string(),
        };

        let server = Server::bind(cfg).context("Server::bind")?;
        let addr = server.local_addr();
        let cert_sha256 = server.cert_sha256_hex().to_string();
        let metrics = server.metrics();

        // Drive the accept loop in the background. The handle is
        // dropped when `TestServer` drops, taking the server with it
        // (quinn::Endpoint is itself drop-on-drop).
        let join = tokio::spawn(server.run());

        Ok(Self {
            addr,
            cert_sha256,
            client_id: client_id.to_string(),
            signing_key: sk,
            metrics,
            _join: join,
        })
    }
}

/// Build a Quinn client endpoint bound to an ephemeral port. Caller
/// dials with the pinned cert hash from `TestServer::cert_sha256`.
pub fn make_client_endpoint(cert_sha256: &str) -> Result<quinn::Endpoint> {
    tls::install_crypto_provider();
    let qcfg = tls::client_config(cert_sha256)?;
    let local: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut endpoint = quinn::Endpoint::client(local).context("bind client UDP")?;
    endpoint.set_default_client_config(qcfg);
    Ok(endpoint)
}

/// One full PROTEUS auth handshake on a fresh control bidi stream.
/// Returns the AEAD session key for any subsequent proxy streams.
pub async fn run_auth(
    conn: &quinn::Connection,
    client_id: &str,
    sk: &SigningKey,
) -> Result<[u8; aead::KEY_LEN]> {
    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await.context("open ctrl bi")?;
    let mut exporter = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|e| anyhow::anyhow!("exporter: {e:?}"))?;
    let req = AuthRequest::sign(client_id, sk, &exporter)?;
    write_frame(
        &mut ctrl_send,
        &Frame::new(FrameType::AuthRequest, req.encode()?)?,
    )
    .await
    .context("write AUTH_REQUEST")?;
    let resp_frame = read_frame(&mut ctrl_recv)
        .await
        .context("read AUTH_RESPONSE")?;
    if resp_frame.frame_type != FrameType::AuthResponse {
        bail!("expected AuthResponse, got {:?}", resp_frame.frame_type);
    }
    let resp = AuthResponse::decode(&resp_frame.payload)?;
    if resp.status != 0 {
        bail!("auth rejected by server (status={})", resp.status);
    }
    let key = aead::InnerAead::derive_key(&exporter, &req.nonce).context("derive session key")?;
    Ok(key)
}

/// Open a TCP proxy stream and exchange PROXY_OPEN + PROXY_ACCEPT.
/// Returns the QUIC stream halves + AEAD pair for the caller to
/// drive DATA frames on.
pub async fn open_tcp_proxy(
    conn: &quinn::Connection,
    session_key: &[u8; aead::KEY_LEN],
    host: &str,
    port: u16,
) -> Result<(quinn::SendStream, quinn::RecvStream, ProxyStreamAead, u64)> {
    let (mut q_send, mut q_recv) = conn.open_bi().await.context("open proxy bi")?;
    let stream_id = q_send.id().index();
    let mut sa = ProxyStreamAead::for_client(session_key, stream_id);

    let open = ProxyOpen::new_tcp(host, port);
    let open_frame = Frame {
        frame_type: FrameType::ProxyOpen,
        flags: 0,
        stream_id,
        payload: open.encode()?,
    };
    write_frame_aead(&mut q_send, &open_frame, &mut sa.send)
        .await
        .context("write PROXY_OPEN")?;

    let resp = read_frame_aead(&mut q_recv, &mut sa.recv)
        .await
        .context("read PROXY_ACCEPT/REJECT")?;
    if resp.frame_type != FrameType::ProxyAccept {
        bail!("expected PROXY_ACCEPT, got {:?}", resp.frame_type);
    }
    Ok((q_send, q_recv, sa, stream_id))
}

/// Poll a condition (typically a metrics counter) until it becomes
/// true or the timeout elapses. Useful for "wait for the server to
/// have observed the auth attempt" without timing-dependent sleeps.
pub async fn poll_until<F: FnMut() -> bool>(
    mut cond: F,
    timeout: Duration,
    poll_interval: Duration,
) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        tokio::time::sleep(poll_interval).await;
    }
    cond()
}

/// Unused-import quieting: ensures `VerifyingKey` import is observed
/// by lints in tests that only need the type via `signing_key`.
#[allow(dead_code)]
pub fn _force_vk_import(vk: &VerifyingKey) -> [u8; 32] {
    vk.to_bytes()
}
