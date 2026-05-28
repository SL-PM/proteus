//! Read-only view of the proteus-panel SQLite client store (v0.6 M3.6).
//!
//! The panel owns writes; the server only *reads* the set of currently
//! usable clients and rebuilds its [`ClientRegistry`] from it on a
//! timer (hot-reload). "Usable" = enabled, not past `expires_at`, and
//! under `quota_bytes` — so disabling, expiring, or exhausting a client
//! in the panel takes effect on the next reload without a restart.
//!
//! The `clients` table schema lives in `proteus-panel::db`; we depend on
//! just three columns here. Kept as a small read-only query rather than
//! a shared crate to avoid pulling axum/argon2 into the server.

use std::{collections::HashMap, str::FromStr};

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

/// Read-only handle to the panel's SQLite client store.
pub struct ClientDb {
    pool: SqlitePool,
}

impl ClientDb {
    /// Open the existing panel DB read-only. Errors if the file is
    /// missing (the panel must have created it first).
    pub async fn open(path: &str) -> Result<Self> {
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{path}"))
            .with_context(|| format!("parse sqlite path {path}"))?
            .read_only(true);
        let pool = SqlitePoolOptions::new()
            .connect_with(opts)
            .await
            .with_context(|| format!("open client db {path} (does the panel exist?)"))?;
        Ok(Self { pool })
    }

    /// Load `client_id -> pubkey_b64` for every currently-usable client.
    pub async fn load_active(&self) -> Result<HashMap<String, String>> {
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT id, pubkey_b64 FROM clients \
             WHERE enabled = 1 \
               AND (expires_at IS NULL OR expires_at > datetime('now')) \
               AND (quota_bytes IS NULL OR used_bytes < quota_bytes)",
        )
        .fetch_all(&self.pool)
        .await
        .context("load active clients")?;
        Ok(rows.into_iter().collect())
    }
}
