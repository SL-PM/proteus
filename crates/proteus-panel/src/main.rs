//! `proteus-panel` — management portal for PROTEUS (v0.6 "Control").
//!
//! Thin CLI over the `proteus_panel` library. Subcommands:
//! - `serve`      run the panel HTTP server (default).
//! - `set-admin`  create/replace the admin password (reads it from stdin).
//!
//! The management API, admin web UI, QR/subscription, quotas and
//! commerce land incrementally — see `docs/PROTEUS-v0.6-control-plan.md`.

use axum::{Router, routing::get};
use clap::{Parser, Subcommand};
use proteus_panel::{auth, db};

/// Default bind address for the panel. HTTPS/TLS termination (on the
/// firewall-opened 443/8443) is wired in a later milestone; for now it
/// binds plain HTTP on 8443 for local/dev verification.
const DEFAULT_BIND: &str = "0.0.0.0:8443";

#[derive(Parser, Debug)]
#[command(
    name = "proteus-panel",
    version,
    about = "PROTEUS Control — management portal"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the panel HTTP server (default).
    Serve,
    /// Create or replace the admin credential. Password is read from
    /// stdin (so it never appears in shell history or `ps`):
    ///   echo -n 's3cret' | proteus-panel set-admin admin
    SetAdmin {
        /// Admin username.
        username: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let db_path = std::env::var("PROTEUS_PANEL_DB").unwrap_or_else(|_| "proteus-panel.db".into());
    let store = db::Db::open(&db_path).await?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::SetAdmin { username } => set_admin(&store, &username).await,
        Command::Serve => serve(store, &db_path).await,
    }
}

/// Read a password from stdin, hash it (argon2id), and store it.
async fn set_admin(store: &db::Db, username: &str) -> anyhow::Result<()> {
    use std::io::Read;
    let mut pw = String::new();
    std::io::stdin()
        .read_to_string(&mut pw)
        .map_err(|e| anyhow::anyhow!("read password from stdin: {e}"))?;
    let pw = pw.trim_end_matches(['\n', '\r']);
    if pw.is_empty() {
        anyhow::bail!("empty password on stdin");
    }
    let hash = auth::hash_password(pw)?;
    store.set_admin(username, &hash).await?;
    println!(
        "admin '{username}' set ({} admin(s) total).",
        store.admin_count().await?
    );
    Ok(())
}

/// Run the panel HTTP server.
async fn serve(store: db::Db, db_path: &str) -> anyhow::Result<()> {
    let n_clients = store.count().await?;
    let n_admins = store.admin_count().await?;

    let app = Router::new()
        .route("/health", get(health))
        .route("/", get(index));

    let bind = std::env::var("PROTEUS_PANEL_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("proteus-panel v{} (M2.6)", env!("CARGO_PKG_VERSION"));
    println!("db:           {db_path} ({n_clients} clients, {n_admins} admins)");
    if n_admins == 0 {
        eprintln!("warning: no admin configured — run `proteus-panel set-admin <user>`");
    }
    println!("listening on: http://{bind}");
    println!("routes: GET /health, GET /");
    // `store` becomes axum state for the management API in the next M2.6 step.
    axum::serve(listener, app).await?;
    Ok(())
}

/// Liveness probe.
async fn health() -> &'static str {
    "ok"
}

/// Placeholder root until the admin UI lands (M4.6).
async fn index() -> &'static str {
    "PROTEUS Control — management portal. See docs/PROTEUS-v0.6-control-plan.md"
}
