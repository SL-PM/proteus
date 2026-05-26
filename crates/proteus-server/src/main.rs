//! PROTEUS server (v0.3 research prototype).
//!
//! M6: bind UDP, accept QUIC. For each connection:
//!   1. accept control stream (first bidi)
//!   2. read AUTH_REQUEST frame, verify Ed25519 signature against the
//!      TLS exporter material per spec v0.2 §7.3 + §8
//!   3. on success: send AUTH_RESPONSE(status=0), then accept a second
//!      bidi for the existing M4-style framed PING/PONG demo
//!   4. on failure: close with `H3_GENERAL_PROTOCOL_ERROR` (spec §8.4)
//!
//! Replay protection (M7), real proxying (M8+), policy (M12), and decoy
//! (M13) are still missing.

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::Parser;
use proteus_core::{
    auth::{
        AuthRequest, AuthResponse, ClientRegistry, EXPORTER_LABEL, EXPORTER_LEN, STATUS_AUTH_FAILED,
    },
    config::ServerConfig,
    frame::{Frame, FrameType, read_frame, write_frame},
    tls,
};

/// QUIC application close code on auth failure — same family as
/// `H3_GENERAL_PROTOCOL_ERROR` per spec v0.2 §8.4.
const AUTH_FAIL_CLOSE_CODE: u32 = 0x0101;

#[derive(Parser, Debug)]
#[command(
    name = "proteus-server",
    version,
    about = "PROTEUS server (v0.3 research prototype)",
    long_about = "v0.3 research prototype — DPI-detectable by design. \
                  Do not deploy. See docs/THREAT-MODEL-v0.3.md."
)]
struct Cli {
    /// Path to YAML config file.
    #[arg(short, long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = ServerConfig::from_yaml_file(&cli.config)?;

    tls::install_crypto_provider();
    let (qcfg, cert) = tls::server_config(cfg.tls.as_ref())?;
    let endpoint = quinn::Endpoint::server(qcfg, cfg.listen.addr)
        .with_context(|| format!("bind {}", cfg.listen.addr))?;

    let registry = Arc::new(ClientRegistry::from_config_map(cfg.clients.as_ref())?);

    println!("proteus-server v{}", env!("CARGO_PKG_VERSION"));
    println!("listening on: {}", endpoint.local_addr()?);
    println!("cert sha256:  {}", tls::cert_sha256_hex(&cert));
    println!("clients:      {}", registry.len());
    if registry.is_empty() {
        eprintln!("warning: no clients configured; all auth attempts will be rejected");
    }
    println!();
    println!("M6: exporter-bound Ed25519 auth + framed PING/PONG. Ctrl-C to stop.");

    while let Some(incoming) = endpoint.accept().await {
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(incoming, registry).await {
                eprintln!("conn error: {e:#}");
            }
        });
    }
    Ok(())
}

async fn handle_conn(incoming: quinn::Incoming, registry: Arc<ClientRegistry>) -> Result<()> {
    let conn = incoming.await.context("handshake")?;
    let peer = conn.remote_address();
    println!("accepted {peer}");

    // ----- M6 auth on the control stream (first bidi) -----
    let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await.context("accept_bi ctrl")?;
    let auth_frame = read_frame(&mut ctrl_recv)
        .await
        .context("read AUTH_REQUEST frame")?;
    if auth_frame.frame_type != FrameType::AuthRequest {
        eprintln!(
            "{peer}: expected AuthRequest, got {:?}",
            auth_frame.frame_type
        );
        conn.close(AUTH_FAIL_CLOSE_CODE.into(), b"");
        return Ok(());
    }
    let req = match AuthRequest::decode(&auth_frame.payload) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{peer}: malformed AUTH_REQUEST: {e:#}");
            conn.close(AUTH_FAIL_CLOSE_CODE.into(), b"");
            return Ok(());
        }
    };

    let mut exporter = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|e| anyhow::anyhow!("exporter: {e:?}"))?;

    match registry.verify(&req, &exporter) {
        Ok(client_id) => {
            let resp = AuthResponse::ok().encode()?;
            let resp_frame = Frame::new(FrameType::AuthResponse, resp)?;
            write_frame(&mut ctrl_send, &resp_frame)
                .await
                .context("write AUTH_RESPONSE")?;
            println!("{peer}: auth OK as {client_id}");
        }
        Err(e) => {
            // Log the *reason* internally; the wire close stays generic.
            eprintln!("{peer}: auth FAIL ({}): {e:#}", req.client_id);
            // Best-effort AUTH_RESPONSE(err) before the close — even
            // though spec §8.4 says the close is sufficient, having the
            // response makes the client error path nicer in dev. Wire
            // does not leak a PROTEUS reason string (spec §7.3).
            let err_resp = AuthResponse::err(STATUS_AUTH_FAILED).encode()?;
            let err_frame = Frame::new(FrameType::AuthResponse, err_resp)?;
            let _ = write_frame(&mut ctrl_send, &err_frame).await;
            conn.close(AUTH_FAIL_CLOSE_CODE.into(), b"");
            return Ok(());
        }
    }

    // ----- M4-style framed PING/PONG on a second bidi -----
    let (mut data_send, mut data_recv) = conn.accept_bi().await.context("accept_bi data")?;
    let ping = read_frame(&mut data_recv).await.context("read PING")?;
    if ping.frame_type != FrameType::Ping {
        bail!("{peer}: expected Ping, got {:?}", ping.frame_type);
    }
    let pong = Frame::new(FrameType::Pong, Bytes::new())?;
    write_frame(&mut data_send, &pong)
        .await
        .context("write PONG")?;
    data_send.finish().context("finish data send")?;
    println!("framed ping/pong with {peer} OK");

    let _ = conn.closed().await;
    Ok(())
}
