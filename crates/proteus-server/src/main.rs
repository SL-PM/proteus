//! PROTEUS server (v0.3 research prototype).
//!
//! M7: M6 auth + per-client `(client_id, nonce)` replay cache. The
//! cache TTL is 300s per spec v0.2 §8.3; a background sweeper drops
//! expired entries every 60s.
//!
//! For each connection:
//!   1. accept control stream (first bidi)
//!   2. read AUTH_REQUEST, verify Ed25519 signature against the TLS
//!      exporter, check the replay cache
//!   3. on success: send AUTH_RESPONSE(status=0), accept a second bidi
//!      for the M4-style framed PING/PONG demo
//!   4. on failure (bad sig OR replay): close with
//!      `H3_GENERAL_PROTOCOL_ERROR` (spec §8.4)
//!
//! Real proxying (M8+), policy (M12), and decoy (M13) still missing.

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::Parser;
use proteus_core::{
    auth::{
        AuthRequest, AuthResponse, ClientRegistry, EXPORTER_LABEL, EXPORTER_LEN, STATUS_AUTH_FAILED,
    },
    config::ServerConfig,
    frame::{Frame, FrameType, read_frame, write_frame},
    replay::ReplayCache,
    tls,
};

/// QUIC application close code on auth failure — same family as
/// `H3_GENERAL_PROTOCOL_ERROR` per spec v0.2 §8.4.
const AUTH_FAIL_CLOSE_CODE: u32 = 0x0101;

/// Per spec v0.2 §8.3.
const REPLAY_TTL: Duration = Duration::from_secs(300);

/// How often to sweep expired entries from the replay cache.
const REPLAY_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

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
    let replay = Arc::new(ReplayCache::new(REPLAY_TTL));

    println!("proteus-server v{}", env!("CARGO_PKG_VERSION"));
    println!("listening on: {}", endpoint.local_addr()?);
    println!("cert sha256:  {}", tls::cert_sha256_hex(&cert));
    println!("clients:      {}", registry.len());
    println!("replay ttl:   {}s", REPLAY_TTL.as_secs());
    if registry.is_empty() {
        eprintln!("warning: no clients configured; all auth attempts will be rejected");
    }
    println!();
    println!("M7: exporter-bound Ed25519 auth + replay cache + framed PING/PONG. Ctrl-C to stop.");

    spawn_replay_sweeper(replay.clone());

    while let Some(incoming) = endpoint.accept().await {
        let registry = registry.clone();
        let replay = replay.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(incoming, registry, replay).await {
                eprintln!("conn error: {e:#}");
            }
        });
    }
    Ok(())
}

fn spawn_replay_sweeper(replay: Arc<ReplayCache>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(REPLAY_SWEEP_INTERVAL);
        // Skip the immediate fire so we don't log on startup.
        tick.tick().await;
        loop {
            tick.tick().await;
            let dropped = replay.sweep();
            if dropped > 0 {
                eprintln!(
                    "replay-cache: swept {dropped} expired entries (now {})",
                    replay.len()
                );
            }
        }
    });
}

async fn handle_conn(
    incoming: quinn::Incoming,
    registry: Arc<ClientRegistry>,
    replay: Arc<ReplayCache>,
) -> Result<()> {
    let conn = incoming.await.context("handshake")?;
    let peer = conn.remote_address();
    println!("accepted {peer}");

    // ----- auth on the control stream (first bidi) -----
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

    // Step 1: signature verification.
    let client_id = match registry.verify(&req, &exporter) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("{peer}: auth FAIL ({}): {e:#}", req.client_id);
            reject(&mut ctrl_send, &conn).await;
            return Ok(());
        }
    };

    // Step 2: replay check. Same on-wire close as a bad signature so a
    // passive observer can't distinguish.
    if let Err(e) = replay.check_and_record(&client_id, &req.nonce) {
        eprintln!("{peer}: REPLAY rejected for {client_id}: {e:#}");
        reject(&mut ctrl_send, &conn).await;
        return Ok(());
    }

    // Both checks passed — send the success response.
    let resp_frame = Frame::new(FrameType::AuthResponse, AuthResponse::ok().encode()?)?;
    write_frame(&mut ctrl_send, &resp_frame)
        .await
        .context("write AUTH_RESPONSE")?;
    println!("{peer}: auth OK as {client_id}");

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

/// Best-effort generic rejection: send AUTH_RESPONSE(err) then close
/// the connection. The on-wire close code is intentionally the same
/// for all rejection reasons (spec §8.4).
async fn reject(ctrl_send: &mut quinn::SendStream, conn: &quinn::Connection) {
    if let Ok(bytes) = AuthResponse::err(STATUS_AUTH_FAILED).encode()
        && let Ok(frame) = Frame::new(FrameType::AuthResponse, bytes)
    {
        let _ = write_frame(ctrl_send, &frame).await;
    }
    conn.close(AUTH_FAIL_CLOSE_CODE.into(), b"");
}
