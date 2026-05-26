//! PROTEUS client (v0.3 research prototype).
//!
//! M3: dial the server over QUIC, open one bidi stream, send `ping`,
//! expect `pong`, close cleanly. No auth, no SOCKS5 yet — those land
//! in M6/M9.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use proteus_core::{config::ClientConfig, tls};

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
    send.write_all(b"ping").await.context("write ping")?;
    send.finish().context("finish send")?;

    let mut buf = [0u8; 4];
    recv.read_exact(&mut buf).await.context("read pong")?;
    if &buf == b"pong" {
        println!("ping/pong OK");
    } else {
        anyhow::bail!("expected b\"pong\", got {:?}", &buf);
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}
