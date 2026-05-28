//! `proteus-panel` — management portal for PROTEUS (v0.6 "Control").
//!
//! M0.6 scaffold: a minimal axum app with a `/health` endpoint, to
//! prove the crate builds and serves. The real surface — SQLite-backed
//! client store (M1.6), management API + admin auth (M2.6), DB-backed
//! server registry (M3.6), admin web UI + QR/subscription (M4.6–M5.6),
//! then quotas (Phase 2) and commerce (Phase 3) — lands incrementally.
//!
//! Design + roadmap: `docs/PROTEUS-v0.6-control-plan.md`.

use axum::{Router, routing::get};
use proteus_panel::db;

/// Default bind address for the panel. HTTPS/TLS termination (on the
/// firewall-opened 443/8443) is wired in a later milestone; for now the
/// scaffold binds plain HTTP on 8443 for local/dev verification.
const DEFAULT_BIND: &str = "0.0.0.0:8443";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // M1.6: open the SQLite client store at startup. Path is
    // configurable; defaults to a file in the working directory.
    let db_path = std::env::var("PROTEUS_PANEL_DB").unwrap_or_else(|_| "proteus-panel.db".into());
    let store = db::Db::open(&db_path).await?;
    let n_clients = store.count().await?;

    let app = Router::new()
        .route("/health", get(health))
        .route("/", get(index));

    let bind = std::env::var("PROTEUS_PANEL_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("proteus-panel v{} (M1.6)", env!("CARGO_PKG_VERSION"));
    println!("db:           {db_path} ({n_clients} clients)");
    println!("listening on: http://{bind}");
    println!("routes: GET /health, GET /");
    // `store` becomes axum state for the management API in M2.6.
    axum::serve(listener, app).await?;
    Ok(())
}

/// Liveness probe — returns 200 with a tiny body.
async fn health() -> &'static str {
    "ok"
}

/// Placeholder root until the admin UI lands (M4.6).
async fn index() -> &'static str {
    "PROTEUS Control — management portal (scaffold). See docs/PROTEUS-v0.6-control-plan.md"
}
