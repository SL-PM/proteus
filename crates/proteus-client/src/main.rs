//! PROTEUS client (v0.3 research prototype).
//!
//! M1: load YAML config, print parsed values, exit. M3 wires the QUIC
//! dial; M6 wires auth; M9 wires the SOCKS5 listener.

use std::path::PathBuf;

use anyhow::Result;
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = ClientConfig::from_yaml_file(&cli.config)?;

    println!("proteus-client v{}", env!("CARGO_PKG_VERSION"));
    println!("config:        {}", cli.config.display());
    println!("server.addr:   {}", cfg.server.addr);
    println!("server.sni:    {}", cfg.server.sni);
    println!(
        "server.pin:    {}",
        if cfg.server.cert_sha256.is_empty() {
            "<accept-any>  (v0.3 lab — set cert_sha256 to pin)".to_string()
        } else {
            cfg.server.cert_sha256
        }
    );
    println!("client_id:     {}", cfg.identity.client_id);
    println!("private_key:   {}", cfg.identity.private_key.display());
    println!("socks5.listen: {}", cfg.socks5.listen);
    println!("log_level:     {}", cfg.log_level);
    println!();
    println!("M1 stub — config parsed OK. No dial yet (lands in M3).");

    Ok(())
}
