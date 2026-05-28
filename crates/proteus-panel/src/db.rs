//! SQLite client store (v0.6 M1.6).
//!
//! Replaces PROTEUS's static `clients:` YAML map with a dynamic,
//! quota-aware store. The schema carries `quota_bytes` / `used_bytes` /
//! `expires_at` from day one so Phase-2 enforcement (M6.6/M7.6) and
//! Phase-3 commerce don't need a migration.
//!
//! Uses sqlx's runtime query API (not the compile-time `query!` macros),
//! so no `DATABASE_URL` is required at build time.

use std::str::FromStr;

use anyhow::{Context, Result};
use sqlx::{
    FromRow,
    sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions},
};

/// One managed PROTEUS client (= one sellable access).
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct Client {
    /// PROTEUS `client_id`.
    pub id: String,
    /// Human-facing note ("alice", "kunde-42").
    pub label: String,
    /// Standard-base64 Ed25519 public key (as in the server `clients:` map).
    pub pubkey_b64: String,
    /// Whether the client may authenticate.
    pub enabled: bool,
    /// Traffic cap in bytes; `None` = unlimited.
    pub quota_bytes: Option<i64>,
    /// Bytes used so far (maintained by the server's accounting, M6.6).
    pub used_bytes: i64,
    /// RFC3339/ISO8601 expiry; `None` = never expires.
    pub expires_at: Option<String>,
    /// Creation timestamp (SQLite `datetime('now')`).
    pub created_at: String,
}

impl Client {
    /// True if the client is currently usable: enabled, within quota,
    /// and not past expiry. (Expiry is compared lexically on ISO8601,
    /// which is correct for `datetime('now')`-formatted UTC strings.)
    pub fn is_active(&self, now_iso: &str) -> bool {
        if !self.enabled {
            return false;
        }
        if let Some(q) = self.quota_bytes
            && self.used_bytes >= q
        {
            return false;
        }
        if let Some(exp) = &self.expires_at
            && now_iso >= exp.as_str()
        {
            return false;
        }
        true
    }
}

const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS clients (
    id          TEXT PRIMARY KEY,
    label       TEXT    NOT NULL DEFAULT '',
    pubkey_b64  TEXT    NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    quota_bytes INTEGER,
    used_bytes  INTEGER NOT NULL DEFAULT 0,
    expires_at  TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);";

/// Admin credentials for the management panel (M2.6). Single-admin to
/// start; multi-admin / roles can be layered on later.
const SCHEMA_ADMINS: &str = "\
CREATE TABLE IF NOT EXISTS admins (
    username    TEXT PRIMARY KEY,
    argon2_hash TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);";

/// Handle to the SQLite-backed client store.
#[derive(Clone)]
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    /// Open (creating if missing) the SQLite database at `path` and
    /// apply the schema. Pass `":memory:"` is NOT supported across a
    /// pool — use [`Db::open_temp`] in tests instead.
    pub async fn open(path: &str) -> Result<Self> {
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{path}"))
            .with_context(|| format!("parse sqlite path {path}"))?
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .connect_with(opts)
            .await
            .with_context(|| format!("open sqlite db {path}"))?;
        sqlx::query(SCHEMA)
            .execute(&pool)
            .await
            .context("apply clients schema")?;
        sqlx::query(SCHEMA_ADMINS)
            .execute(&pool)
            .await
            .context("apply admins schema")?;
        Ok(Self { pool })
    }

    /// Add a client. `quota_bytes`/`expires_at` may be `None`. Errors on
    /// duplicate `id` (PRIMARY KEY).
    pub async fn add_client(
        &self,
        id: &str,
        label: &str,
        pubkey_b64: &str,
        quota_bytes: Option<i64>,
        expires_at: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO clients (id, label, pubkey_b64, quota_bytes, expires_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(label)
        .bind(pubkey_b64)
        .bind(quota_bytes)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .with_context(|| format!("add client {id}"))?;
        Ok(())
    }

    /// All clients, newest last.
    pub async fn list_clients(&self) -> Result<Vec<Client>> {
        let rows = sqlx::query_as::<_, Client>(
            "SELECT id, label, pubkey_b64, enabled, quota_bytes, used_bytes, expires_at, created_at \
             FROM clients ORDER BY created_at, id",
        )
        .fetch_all(&self.pool)
        .await
        .context("list clients")?;
        Ok(rows)
    }

    /// One client by id, or `None`.
    pub async fn get_client(&self, id: &str) -> Result<Option<Client>> {
        let row = sqlx::query_as::<_, Client>(
            "SELECT id, label, pubkey_b64, enabled, quota_bytes, used_bytes, expires_at, created_at \
             FROM clients WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .with_context(|| format!("get client {id}"))?;
        Ok(row)
    }

    /// Enable/disable a client. Returns `true` if a row was updated.
    pub async fn set_enabled(&self, id: &str, enabled: bool) -> Result<bool> {
        let r = sqlx::query("UPDATE clients SET enabled = ? WHERE id = ?")
            .bind(enabled)
            .bind(id)
            .execute(&self.pool)
            .await
            .with_context(|| format!("set_enabled {id}"))?;
        Ok(r.rows_affected() > 0)
    }

    /// Set (or clear with `None`) the quota. Returns `true` if updated.
    pub async fn set_quota(&self, id: &str, quota_bytes: Option<i64>) -> Result<bool> {
        let r = sqlx::query("UPDATE clients SET quota_bytes = ? WHERE id = ?")
            .bind(quota_bytes)
            .bind(id)
            .execute(&self.pool)
            .await
            .with_context(|| format!("set_quota {id}"))?;
        Ok(r.rows_affected() > 0)
    }

    /// Add `delta` bytes to a client's usage counter (called by the
    /// server's accounting in M6.6). Returns `true` if updated.
    pub async fn add_usage(&self, id: &str, delta: i64) -> Result<bool> {
        let r = sqlx::query("UPDATE clients SET used_bytes = used_bytes + ? WHERE id = ?")
            .bind(delta)
            .bind(id)
            .execute(&self.pool)
            .await
            .with_context(|| format!("add_usage {id}"))?;
        Ok(r.rows_affected() > 0)
    }

    /// Delete a client. Returns `true` if a row was removed.
    pub async fn delete_client(&self, id: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM clients WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .with_context(|| format!("delete client {id}"))?;
        Ok(r.rows_affected() > 0)
    }

    /// Number of clients.
    pub async fn count(&self) -> Result<i64> {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM clients")
            .fetch_one(&self.pool)
            .await
            .context("count clients")?;
        Ok(n)
    }

    /// Create or replace the admin credential (stores an argon2 hash).
    pub async fn set_admin(&self, username: &str, argon2_hash: &str) -> Result<()> {
        sqlx::query("INSERT OR REPLACE INTO admins (username, argon2_hash) VALUES (?, ?)")
            .bind(username)
            .bind(argon2_hash)
            .execute(&self.pool)
            .await
            .with_context(|| format!("set_admin {username}"))?;
        Ok(())
    }

    /// Fetch an admin's stored argon2 hash, or `None` if no such admin.
    pub async fn get_admin_hash(&self, username: &str) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT argon2_hash FROM admins WHERE username = ?")
                .bind(username)
                .fetch_optional(&self.pool)
                .await
                .with_context(|| format!("get_admin_hash {username}"))?;
        Ok(row.map(|(h,)| h))
    }

    /// Number of configured admins.
    pub async fn admin_count(&self) -> Result<i64> {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM admins")
            .fetch_one(&self.pool)
            .await
            .context("count admins")?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each test gets a private on-disk SQLite file in a tempdir (an
    /// in-memory DB would be per-connection across the pool).
    async fn temp_db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let db = Db::open(path.to_str().unwrap()).await.unwrap();
        (dir, db)
    }

    #[tokio::test]
    async fn add_list_get_roundtrip() {
        let (_d, db) = temp_db().await;
        assert_eq!(db.count().await.unwrap(), 0);
        db.add_client("alice", "Alice", "PUBKEY_A", Some(15_000_000_000), None)
            .await
            .unwrap();
        db.add_client("bob", "Bob", "PUBKEY_B", None, Some("2030-01-01 00:00:00"))
            .await
            .unwrap();
        assert_eq!(db.count().await.unwrap(), 2);

        let all = db.list_clients().await.unwrap();
        assert_eq!(all.len(), 2);

        let a = db.get_client("alice").await.unwrap().unwrap();
        assert_eq!(a.label, "Alice");
        assert_eq!(a.pubkey_b64, "PUBKEY_A");
        assert!(a.enabled); // defaults to enabled
        assert_eq!(a.quota_bytes, Some(15_000_000_000));
        assert_eq!(a.used_bytes, 0);
        assert!(a.expires_at.is_none());
        assert!(!a.created_at.is_empty());

        assert!(db.get_client("nobody").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn duplicate_id_errors() {
        let (_d, db) = temp_db().await;
        db.add_client("x", "", "K", None, None).await.unwrap();
        let err = db.add_client("x", "", "K2", None, None).await.unwrap_err();
        assert!(err.to_string().contains("add client x"), "got: {err:#}");
    }

    #[tokio::test]
    async fn enable_quota_usage_delete() {
        let (_d, db) = temp_db().await;
        db.add_client("c", "C", "K", None, None).await.unwrap();

        assert!(db.set_enabled("c", false).await.unwrap());
        assert!(!db.get_client("c").await.unwrap().unwrap().enabled);

        assert!(db.set_quota("c", Some(1000)).await.unwrap());
        assert_eq!(
            db.get_client("c").await.unwrap().unwrap().quota_bytes,
            Some(1000)
        );

        assert!(db.add_usage("c", 400).await.unwrap());
        assert!(db.add_usage("c", 350).await.unwrap());
        assert_eq!(db.get_client("c").await.unwrap().unwrap().used_bytes, 750);

        // Updates on a missing id report false (no row).
        assert!(!db.set_enabled("ghost", true).await.unwrap());
        assert!(!db.add_usage("ghost", 1).await.unwrap());

        assert!(db.delete_client("c").await.unwrap());
        assert!(!db.delete_client("c").await.unwrap()); // already gone
        assert_eq!(db.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn admin_set_get_upsert() {
        let (_d, db) = temp_db().await;
        assert_eq!(db.admin_count().await.unwrap(), 0);
        assert!(db.get_admin_hash("admin").await.unwrap().is_none());

        db.set_admin("admin", "$argon2id$hash1").await.unwrap();
        assert_eq!(db.admin_count().await.unwrap(), 1);
        assert_eq!(
            db.get_admin_hash("admin").await.unwrap().as_deref(),
            Some("$argon2id$hash1")
        );

        // set_admin is an upsert — replaces, doesn't add a second row.
        db.set_admin("admin", "$argon2id$hash2").await.unwrap();
        assert_eq!(db.admin_count().await.unwrap(), 1);
        assert_eq!(
            db.get_admin_hash("admin").await.unwrap().as_deref(),
            Some("$argon2id$hash2")
        );
    }

    #[test]
    fn is_active_logic() {
        let base = Client {
            id: "c".into(),
            label: String::new(),
            pubkey_b64: "K".into(),
            enabled: true,
            quota_bytes: None,
            used_bytes: 0,
            expires_at: None,
            created_at: "2026-01-01 00:00:00".into(),
        };
        let now = "2026-05-28 00:00:00";

        assert!(base.is_active(now));

        let disabled = Client {
            enabled: false,
            ..base.clone()
        };
        assert!(!disabled.is_active(now));

        let over_quota = Client {
            quota_bytes: Some(100),
            used_bytes: 100,
            ..base.clone()
        };
        assert!(!over_quota.is_active(now));
        let under_quota = Client {
            quota_bytes: Some(100),
            used_bytes: 99,
            ..base.clone()
        };
        assert!(under_quota.is_active(now));

        let expired = Client {
            expires_at: Some("2026-01-01 00:00:00".into()),
            ..base.clone()
        };
        assert!(!expired.is_active(now));
        let not_yet = Client {
            expires_at: Some("2030-01-01 00:00:00".into()),
            ..base.clone()
        };
        assert!(not_yet.is_active(now));
    }
}
