//! M3.6 — server reads its client registry from the panel SQLite store.
//!
//! Seeds a panel DB with the real schema (via `proteus_panel::db::Db`),
//! starts a `proteus-server` pointed at it through `clients_db`, and
//! checks that a DB-backed client authenticates — and that a disabled
//! one does not. Proves the panel↔server loop without touching the
//! static `clients:` map.

mod common;

use std::collections::HashMap;

use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use common::{make_client_endpoint, run_auth};
use ed25519_dalek::SigningKey;
use proteus_core::config::{ListenConfig, PolicyConfig, ServerConfig};
use proteus_panel::db::Db as PanelDb;
use proteus_server::Server;
use rand::rngs::OsRng;

/// A fresh keypair: returns the signing key + its base64 public key.
fn keypair() -> (SigningKey, String) {
    let sk = SigningKey::generate(&mut OsRng);
    let pub_b64 = B64.encode(sk.verifying_key().to_bytes());
    (sk, pub_b64)
}

/// Build a wide-open server config that sources clients from `db_path`
/// and has no static `clients:` map.
fn db_backed_config(db_path: &str) -> ServerConfig {
    ServerConfig {
        listen: ListenConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        },
        tls: None,
        clients: None,
        clients_db: Some(db_path.into()),
        policy: Some(PolicyConfig {
            block_private_ranges: false,
            allowed_ports: vec![],
            denied_ports: vec![],
            allow_udp: true,
        }),
        decoy: None,
        padding: Default::default(),
        idle_padding: Default::default(),
        timing_jitter: Default::default(),
        profile_padding: Default::default(),
        log_level: "info".to_string(),
    }
}

#[tokio::test]
async fn authenticates_a_db_backed_client() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("clients.db");
    let db_path_str = db_path.to_str().unwrap().to_string();

    // Seed an active client via the real panel store.
    let pdb = PanelDb::open(&db_path_str).await?;
    let (sk, pub_b64) = keypair();
    pdb.add_client("dbalice", "DB Alice", &pub_b64, Some(15_000_000_000), None)
        .await?;
    drop(pdb); // release the writer; the server opens it read-only

    let server = Server::bind(db_backed_config(&db_path_str)).await?;
    let addr = server.local_addr();
    let cert = server.cert_sha256_hex().to_string();
    assert_eq!(
        server.clients_len(),
        1,
        "registry should load the DB client"
    );
    tokio::spawn(server.run());

    let endpoint = make_client_endpoint(&cert)?;
    let conn = endpoint.connect(addr, "localhost")?.await?;
    // Auth with the DB-backed keypair must succeed.
    run_auth(&conn, "dbalice", &sk).await?;

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn rejects_a_disabled_db_client() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("clients.db");
    let db_path_str = db_path.to_str().unwrap().to_string();

    let pdb = PanelDb::open(&db_path_str).await?;
    let (sk, pub_b64) = keypair();
    pdb.add_client("dbbob", "DB Bob", &pub_b64, None, None)
        .await?;
    pdb.set_enabled("dbbob", false).await?; // disabled → not active
    drop(pdb);

    let server = Server::bind(db_backed_config(&db_path_str)).await?;
    let addr = server.local_addr();
    let cert = server.cert_sha256_hex().to_string();
    assert_eq!(
        server.clients_len(),
        0,
        "disabled client must not be in the registry"
    );
    tokio::spawn(server.run());

    let endpoint = make_client_endpoint(&cert)?;
    let conn = endpoint.connect(addr, "localhost")?.await?;
    // Auth must fail: the disabled client isn't in the registry.
    let r = run_auth(&conn, "dbbob", &sk).await;
    assert!(r.is_err(), "disabled DB client must not authenticate");

    endpoint.wait_idle().await;
    Ok(())
}

/// Sanity: a static-only deployment (no clients_db) still works — the
/// registry just isn't reloaded. (Guards the ArcSwap refactor.)
#[tokio::test]
async fn static_only_registry_still_works() -> Result<()> {
    let (sk, pub_b64) = keypair();
    let mut clients = HashMap::new();
    clients.insert("staticalice".to_string(), pub_b64);

    let cfg = ServerConfig {
        listen: ListenConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        },
        tls: None,
        clients: Some(clients),
        clients_db: None,
        policy: None,
        decoy: None,
        padding: Default::default(),
        idle_padding: Default::default(),
        timing_jitter: Default::default(),
        profile_padding: Default::default(),
        log_level: "info".to_string(),
    };
    let server = Server::bind(cfg).await?;
    let addr = server.local_addr();
    let cert = server.cert_sha256_hex().to_string();
    tokio::spawn(server.run());

    let endpoint = make_client_endpoint(&cert)?;
    let conn = endpoint.connect(addr, "localhost")?.await?;
    run_auth(&conn, "staticalice", &sk).await?;

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}
