//! PROTEUS server (v0.3 research prototype).
//!
//! M4: bind UDP, accept QUIC connections, expect a single PROTEUS PING
//! frame on the first bidi stream of each connection, reply PONG. No
//! auth, no policy, no decoy yet — those land in M6/M12/M13.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::Parser;
use proteus_core::{
    config::ServerConfig,
    frame::{Frame, FrameType, read_frame, write_frame},
    tls,
};

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

    println!("proteus-server v{}", env!("CARGO_PKG_VERSION"));
    println!("listening on: {}", endpoint.local_addr()?);
    println!("cert sha256:  {}", tls::cert_sha256_hex(&cert));
    println!();
    println!("M4: framed PING/PONG over QUIC. No auth/policy/decoy yet. Ctrl-C to stop.");

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Err(e) = handle_conn(incoming).await {
                eprintln!("conn error: {e:#}");
            }
        });
    }
    Ok(())
}

async fn handle_conn(incoming: quinn::Incoming) -> Result<()> {
    let conn = incoming.await.context("handshake")?;
    let peer = conn.remote_address();
    println!("accepted {peer}");

    let (mut send, mut recv) = conn.accept_bi().await.context("accept_bi")?;
    let ping = read_frame(&mut recv).await.context("read PING")?;
    if ping.frame_type != FrameType::Ping {
        bail!("{peer}: expected Ping, got {:?}", ping.frame_type);
    }

    let pong = Frame::new(FrameType::Pong, Bytes::new())?;
    write_frame(&mut send, &pong).await.context("write PONG")?;
    send.finish().context("finish send")?;
    println!("framed ping/pong with {peer} OK");

    // Wait for client to close before dropping the connection.
    let _ = conn.closed().await;
    Ok(())
}
