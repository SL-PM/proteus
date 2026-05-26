//! PROTEUS server (v0.3 research prototype).
//!
//! M1: load YAML config, print parsed values, exit. M3 wires the QUIC
//! listener; M6 wires auth; M12 wires policy; M13 wires the decoy.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use proteus_core::config::ServerConfig;

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

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = ServerConfig::from_yaml_file(&cli.config)?;

    println!("proteus-server v{}", env!("CARGO_PKG_VERSION"));
    println!("config:     {}", cli.config.display());
    println!("listen:     {}", cfg.listen.addr);
    println!("log_level:  {}", cfg.log_level);
    println!("tls:        {}", section_status(cfg.tls.is_some(), "M6"));
    println!(
        "clients:    {}",
        section_status(cfg.clients.is_some(), "M2/M6")
    );
    println!(
        "policy:     {}",
        section_status(cfg.policy.is_some(), "M12")
    );
    println!("decoy:      {}", section_status(cfg.decoy.is_some(), "M13"));
    println!();
    println!("M1 stub — config parsed OK. No listener yet (lands in M3).");

    Ok(())
}

fn section_status(present: bool, milestone: &str) -> String {
    if present {
        format!("present (activated in {milestone})")
    } else {
        format!("absent  (activated in {milestone})")
    }
}
