//! `proteus-tools` — PROTEUS utility CLI (v0.3 research prototype).
//!
//! Subcommands:
//! - `keygen`    Generate an Ed25519 keypair for a named client (M2).
//! - `udp-test`  One-shot UDP proxy echo through a running server (M10).
//!
//! Throwaway/spike binaries (e.g. `exporter-spike`) live under
//! `src/bin/` and are invoked with `cargo run --bin <name>`.

mod keygen;
mod udp_test;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "proteus-tools",
    version,
    about = "PROTEUS utility CLI (v0.3 research prototype)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate an Ed25519 keypair for a named client.
    Keygen(keygen::Args),
    /// One-shot UDP proxy echo through a running PROTEUS server.
    UdpTest(udp_test::Args),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen(args) => keygen::run(args),
        Command::UdpTest(args) => udp_test::run(args).await,
    }
}
