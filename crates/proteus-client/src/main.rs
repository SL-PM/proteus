//! PROTEUS client (v0.3 research prototype).
//!
//! M6: dial QUIC, on the first bidi (control stream) send an Ed25519
//! AUTH_REQUEST signed over `"PROTEUS-v0.3-auth" || exporter || nonce`
//! per spec v0.2 §7.3 + §8. On AUTH_RESPONSE(status=0), open a second
//! bidi and run the M4 framed PING/PONG demo. On rejection, exit with
//! an error.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::Parser;
use proteus_core::{
    auth::{AuthRequest, AuthResponse, EXPORTER_LABEL, EXPORTER_LEN, load_signing_key},
    config::ClientConfig,
    frame::{Frame, FrameType, read_frame, write_frame},
    tls,
};

#[derive(Parser, Debug)]
#[command(
    name = "proteus-client",
    version,
    about = "PROTEUS client (v0.3 research prototype)",
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
    let cfg = ClientConfig::from_yaml_file(&cli.config)?;
    let sk = load_signing_key(&cfg.identity.private_key)?;

    tls::install_crypto_provider();
    let qcfg = tls::client_config(&cfg.server.cert_sha256)?;

    let local: SocketAddr = "0.0.0.0:0".parse()?;
    let mut endpoint = quinn::Endpoint::client(local).context("bind client UDP")?;
    endpoint.set_default_client_config(qcfg);

    println!("proteus-client v{}", env!("CARGO_PKG_VERSION"));
    println!("dialing {} (sni={})", cfg.server.addr, cfg.server.sni);

    let conn = endpoint
        .connect(cfg.server.addr, &cfg.server.sni)
        .context("connect setup")?
        .await
        .context("handshake")?;
    println!("connected; remote={}", conn.remote_address());

    // ----- M6 auth on the control stream -----
    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await.context("open ctrl bi")?;

    let mut exporter = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|e| anyhow::anyhow!("exporter: {e:?}"))?;

    let req = AuthRequest::sign(&cfg.identity.client_id, &sk, &exporter)?;
    let req_bytes = req.encode()?;
    let req_frame = Frame::new(FrameType::AuthRequest, req_bytes)?;
    write_frame(&mut ctrl_send, &req_frame)
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
    println!("auth OK as {}", cfg.identity.client_id);

    // ----- framed PING/PONG on a second bidi -----
    let (mut data_send, mut data_recv) = conn.open_bi().await.context("open data bi")?;
    let ping = Frame::new(FrameType::Ping, Bytes::new())?;
    write_frame(&mut data_send, &ping)
        .await
        .context("write PING")?;
    data_send.finish().context("finish data send")?;

    let pong = read_frame(&mut data_recv).await.context("read PONG")?;
    if pong.frame_type != FrameType::Pong {
        bail!("expected Pong, got {:?}", pong.frame_type);
    }
    println!("framed ping/pong OK");

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}
