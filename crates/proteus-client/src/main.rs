//! PROTEUS client CLI (v0.3 research prototype) — thin wrapper over
//! [`proteus_client_core`] (v0.6 refactor). The connect/auth/SOCKS5
//! engine + live stats live in the library so the Tauri GUI shares it.
//!
//! Dials QUIC, authenticates once, runs a SOCKS5 CONNECT listener, and
//! prints periodic link stats (up/down throughput + ping) until Ctrl-C.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use proteus_core::config::ClientConfig;

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
    let cfg = ClientConfig::from_yaml_file(&cli.config).context("load client config")?;

    let client = proteus_client_core::connect(cfg).await?;
    println!("connected — SOCKS5 CONNECT on {}", client.socks5_addr());
    println!("(Ctrl-C to stop)");

    // Periodic link stats until Ctrl-C.
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    tick.tick().await; // skip immediate
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\nstopping…");
                client.stop().await;
                return Ok(());
            }
            _ = tick.tick() => {
                let s = client.stats();
                if !s.connected {
                    eprintln!("connection closed by server");
                    return Ok(());
                }
                println!(
                    "↑ {:.1} KB/s   ↓ {:.1} KB/s   ping {:.0} ms   (total ↑ {} / ↓ {} bytes)",
                    s.up_bps / 1024.0,
                    s.down_bps / 1024.0,
                    s.ping_ms,
                    s.up_bytes,
                    s.down_bytes,
                );
            }
        }
    }
}
