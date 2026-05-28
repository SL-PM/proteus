//! PROTEUS server CLI (v0.3 research prototype) — thin wrapper over
//! `proteus_server::Server` (M9.4 refactor). All connection/auth/proxy
//! logic lives in the library crate so integration tests can spin up
//! the server in-process.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use proteus_core::config::ServerConfig;
use proteus_server::{
    METRICS_SNAPSHOT_INTERVAL, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW, REPLAY_TTL, Server,
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
    let cfg = ServerConfig::from_yaml_file(&cli.config).context("load server config")?;
    let server = Server::bind(cfg.clone()).await?;

    println!("proteus-server v{}", env!("CARGO_PKG_VERSION"));
    println!("listening on: {}", server.local_addr());
    println!("cert sha256:  {}", server.cert_sha256_hex());
    println!("clients:      {}", server.clients_len());
    println!("replay ttl:   {}s", REPLAY_TTL.as_secs());
    println!(
        "policy:       {}",
        if server.policy_enabled() {
            "enabled"
        } else {
            "disabled (no `policy:` section in config)"
        }
    );
    println!(
        "metrics:      snapshot every {}s to stderr",
        METRICS_SNAPSHOT_INTERVAL.as_secs()
    );
    println!(
        "rate limit:   {} auth attempts per {}s per peer IP",
        RATE_LIMIT_MAX,
        RATE_LIMIT_WINDOW.as_secs()
    );
    println!(
        "decoy body:   {} ({} bytes)",
        if server.decoy_is_file_backed(&cfg) {
            "file"
        } else {
            "embedded default (nginx welcome)"
        },
        server.decoy_body_len()
    );
    println!(
        "decoy hdrs:   {}",
        match server.decoy_headers_count() {
            Some(n) => format!("mirrored from snapshot ({n} headers)"),
            None => "hardcoded nginx-style (3 headers + fresh Date)".to_string(),
        }
    );
    println!(
        "padding:      {}",
        match server.padding_buckets() {
            Some(b) => format!("on, buckets {b:?}"),
            None => "off (v0.4-compatible wire)".to_string(),
        }
    );
    println!(
        "idle padding: {}",
        match server.idle_padding_summary() {
            Some((secs, bucket)) => format!("on, PING every {secs}s padded to {bucket}B"),
            None => "off".to_string(),
        }
    );
    println!(
        "timing jitter: {}",
        match server.jitter_summary() {
            Some((min, max, 0)) => format!("on, {min}–{max}ms delay per proxy-stream frame"),
            Some((min, max, burst)) =>
                format!("on, {min}–{max}ms delay, token-bucket burst {burst}"),
            None => "off".to_string(),
        }
    );
    if server.clients_len() == 0 {
        eprintln!("warning: no clients configured; all auth attempts will be rejected");
    }
    println!();
    println!("auth + replay + policy + TCP/UDP proxy + metrics. Ctrl-C to stop.");

    server.run().await
}
