//! PROTEUS server (v0.3 research prototype).
//!
//! M3: bind UDP, accept QUIC connections, expect a single bidi stream
//! per connection carrying the bytes `ping`, reply `pong`. No auth,
//! no policy, no decoy yet — those land in M6/M12/M13.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use proteus_core::{config::ServerConfig, tls};

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
    println!("M3: plain QUIC ping/pong. No auth/policy/decoy yet. Ctrl-C to stop.");

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
    let mut buf = [0u8; 4];
    recv.read_exact(&mut buf).await.context("read ping")?;
    if &buf != b"ping" {
        anyhow::bail!("{peer}: expected b\"ping\", got {:?}", &buf);
    }
    send.write_all(b"pong").await.context("write pong")?;
    send.finish().context("finish send")?;
    println!("ping/pong with {peer} OK");

    // Wait for client to close before we drop the connection.
    let _ = conn.closed().await;
    Ok(())
}
