//! PROTEUS client (v0.3 research prototype).
//!
//! M4: dial the server over QUIC, open one bidi stream, send a PROTEUS
//! PING frame, expect a PONG, close cleanly. No auth, no SOCKS5 yet —
//! those land in M6/M9.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::Parser;
use proteus_core::{
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

    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;
    let ping = Frame::new(FrameType::Ping, Bytes::new())?;
    write_frame(&mut send, &ping).await.context("write PING")?;
    send.finish().context("finish send")?;

    let pong = read_frame(&mut recv).await.context("read PONG")?;
    if pong.frame_type != FrameType::Pong {
        bail!("expected Pong, got {:?}", pong.frame_type);
    }
    println!("framed ping/pong OK");

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}
