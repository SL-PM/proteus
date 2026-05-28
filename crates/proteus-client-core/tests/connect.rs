//! Integration test: the client core connects to an in-process PROTEUS
//! server, authenticates, binds SOCKS5, and reports live stats.

use std::{collections::HashMap, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::SigningKey;
use proteus_core::config::{
    ClientConfig, ClientIdentity, ListenConfig, PolicyConfig, ServerConfig, ServerEndpoint,
    Socks5Config,
};
use proteus_core::subscription::Subscription;
use proteus_server::Server;
use rand::rngs::OsRng;

#[tokio::test]
async fn connect_authenticates_and_reports_stats() {
    // Keypair for client "alice".
    let sk = SigningKey::generate(&mut OsRng);
    let pub_b64 = B64.encode(sk.verifying_key().to_bytes());
    let priv_b64 = B64.encode(sk.to_bytes());

    // Private key on disk (the client loads it from a path).
    let dir = tempfile::tempdir().unwrap();
    let keyfile = dir.path().join("alice.key");
    std::fs::write(&keyfile, priv_b64).unwrap();

    // In-process server with alice in the static map.
    let mut clients = HashMap::new();
    clients.insert("alice".to_string(), pub_b64);
    let scfg = ServerConfig {
        listen: ListenConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        },
        tls: None,
        clients: Some(clients),
        clients_db: None,
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
    };
    let server = Server::bind(scfg).await.unwrap();
    let addr = server.local_addr();
    let cert = server.cert_sha256_hex().to_string();
    tokio::spawn(server.run());

    // Client config pointing at it.
    let ccfg = ClientConfig {
        server: ServerEndpoint {
            addr,
            sni: "localhost".to_string(),
            cert_sha256: cert,
        },
        identity: ClientIdentity {
            client_id: "alice".to_string(),
            private_key: keyfile,
        },
        socks5: Socks5Config {
            listen: "127.0.0.1:0".parse().unwrap(),
        },
        padding: Default::default(),
        timing_jitter: Default::default(),
        profile_padding: Default::default(),
        log_level: "info".to_string(),
    };

    let client = proteus_client_core::connect(ccfg)
        .await
        .expect("connect + auth should succeed");

    // SOCKS5 listener bound to a real ephemeral port.
    assert_ne!(client.socks5_addr().port(), 0);

    // Let the link settle so quinn has an RTT estimate.
    tokio::time::sleep(Duration::from_millis(250)).await;

    let s = client.stats();
    assert!(s.connected, "should report connected");
    // The QUIC handshake + auth already moved bytes both ways.
    assert!(s.up_bytes > 0, "expected upstream bytes from handshake");
    assert!(s.down_bytes > 0, "expected downstream bytes from handshake");
    assert!(
        s.ping_ms >= 0.0 && s.ping_ms < 10_000.0,
        "sane ping: {}",
        s.ping_ms
    );

    client.stop().await;
}

#[tokio::test]
async fn connect_fails_with_wrong_key() {
    // Server knows alice's pubkey, but the client signs with a different key.
    let server_sk = SigningKey::generate(&mut OsRng);
    let pub_b64 = B64.encode(server_sk.verifying_key().to_bytes());

    let wrong_sk = SigningKey::generate(&mut OsRng);
    let dir = tempfile::tempdir().unwrap();
    let keyfile = dir.path().join("wrong.key");
    std::fs::write(&keyfile, B64.encode(wrong_sk.to_bytes())).unwrap();

    let mut clients = HashMap::new();
    clients.insert("alice".to_string(), pub_b64);
    let scfg = ServerConfig {
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
    let server = Server::bind(scfg).await.unwrap();
    let addr = server.local_addr();
    let cert = server.cert_sha256_hex().to_string();
    tokio::spawn(server.run());

    let ccfg = ClientConfig {
        server: ServerEndpoint {
            addr,
            sni: "localhost".to_string(),
            cert_sha256: cert,
        },
        identity: ClientIdentity {
            client_id: "alice".to_string(),
            private_key: keyfile,
        },
        socks5: Socks5Config {
            listen: "127.0.0.1:0".parse().unwrap(),
        },
        padding: Default::default(),
        timing_jitter: Default::default(),
        profile_padding: Default::default(),
        log_level: "info".to_string(),
    };

    assert!(
        proteus_client_core::connect(ccfg).await.is_err(),
        "wrong key must fail auth"
    );
}

#[tokio::test]
async fn connect_from_subscription_blob() {
    // Keypair + server (alice).
    let sk = SigningKey::generate(&mut OsRng);
    let pub_b64 = B64.encode(sk.verifying_key().to_bytes());
    let priv_b64 = B64.encode(sk.to_bytes());

    let mut clients = HashMap::new();
    clients.insert("alice".to_string(), pub_b64);
    let scfg = ServerConfig {
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
    let server = Server::bind(scfg).await.unwrap();
    let addr = server.local_addr();
    let cert = server.cert_sha256_hex().to_string();
    tokio::spawn(server.run());

    // Build the subscription blob the panel would hand out, encode it.
    let sub = Subscription {
        server_addr: addr.to_string(),
        sni: "localhost".to_string(),
        cert_sha256: cert,
        client_id: "alice".to_string(),
        private_key_b64: priv_b64,
        label: "kunde-1".to_string(),
    };
    let url = sub.to_url();

    // One-click import → connect.
    let client = proteus_client_core::connect_subscription(&url, "127.0.0.1:0".parse().unwrap())
        .await
        .expect("connect from subscription should succeed");
    assert!(client.stats().connected);
    assert_ne!(client.socks5_addr().port(), 0);
    client.stop().await;
}
