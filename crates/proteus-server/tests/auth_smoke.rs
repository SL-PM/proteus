//! End-to-end auth smoke test against an in-process server.
//!
//! Exercises the M9.4 library refactor: bind a server on 127.0.0.1:0,
//! generate a client keypair, run the full AUTH_REQUEST/AUTH_RESPONSE
//! handshake, and assert the server-side metrics counters moved.
//!
//! This is the foundation the M6.4 (0-RTT) and M7.4 (migration)
//! integration tests build on. If it breaks, the refactor itself is
//! wrong; everything else is a more specific scenario.

mod common;

use std::time::Duration;

use anyhow::Result;
use common::{TestServer, make_client_endpoint, run_auth};

#[tokio::test]
async fn auth_succeeds_with_valid_keypair() -> Result<()> {
    let server = TestServer::start("alice").await?;

    let endpoint = make_client_endpoint(&server.cert_sha256)?;
    let conn = endpoint.connect(server.addr, "localhost")?.await?;
    let _session_key = run_auth(&conn, &server.client_id, &server.signing_key).await?;

    // Server records auth_success between writing AUTH_RESPONSE and
    // entering the proxy-stream accept loop. Brief poll to absorb the
    // scheduling gap.
    common::poll_until(
        || {
            let s = server.metrics.snapshot();
            s.auth_attempts == 1 && s.auth_success == 1 && s.auth_failed == 0
        },
        Duration::from_secs(2),
        Duration::from_millis(20),
    )
    .await;

    let s = server.metrics.snapshot();
    assert_eq!(s.auth_attempts, 1, "snapshot: {s}");
    assert_eq!(s.auth_success, 1, "snapshot: {s}");
    assert_eq!(s.auth_failed, 0, "snapshot: {s}");

    conn.close(0u32.into(), b"test done");
    endpoint.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn auth_fails_with_wrong_keypair() -> Result<()> {
    let server = TestServer::start("alice").await?;

    // Build a *different* signing key than the one alice registered.
    let mut csprng = rand::rngs::OsRng;
    let wrong_sk = ed25519_dalek::SigningKey::generate(&mut csprng);

    let endpoint = make_client_endpoint(&server.cert_sha256)?;
    let conn = endpoint.connect(server.addr, "localhost")?.await?;
    // Server may either:
    //   (a) write an AUTH_RESPONSE(status=1) then close → client sees
    //       "auth rejected by server (status=1)"
    //   (b) flush the close before the AUTH_RESPONSE → client sees a
    //       Quinn read error
    // Both prove the server refused — the assertion on metrics below
    // is what actually pins the contract.
    let r = run_auth(&conn, &server.client_id, &wrong_sk).await;
    assert!(r.is_err(), "auth with wrong key must fail");

    common::poll_until(
        || {
            let s = server.metrics.snapshot();
            s.auth_attempts == 1 && s.auth_success == 0 && s.auth_failed == 1
        },
        Duration::from_secs(2),
        Duration::from_millis(20),
    )
    .await;

    let s = server.metrics.snapshot();
    assert_eq!(s.auth_failed, 1, "snapshot: {s}");
    assert_eq!(s.auth_success, 0, "snapshot: {s}");

    conn.close(0u32.into(), b"test done");
    endpoint.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn two_back_to_back_auths_count_independently() -> Result<()> {
    let server = TestServer::start("alice").await?;
    let endpoint = make_client_endpoint(&server.cert_sha256)?;

    let conn1 = endpoint.connect(server.addr, "localhost")?.await?;
    run_auth(&conn1, &server.client_id, &server.signing_key).await?;
    conn1.close(0u32.into(), b"");

    let conn2 = endpoint.connect(server.addr, "localhost")?.await?;
    run_auth(&conn2, &server.client_id, &server.signing_key).await?;

    common::poll_until(
        || {
            let s = server.metrics.snapshot();
            s.auth_attempts == 2 && s.auth_success == 2
        },
        Duration::from_secs(2),
        Duration::from_millis(20),
    )
    .await;

    let s = server.metrics.snapshot();
    assert_eq!(s.auth_attempts, 2, "snapshot: {s}");
    assert_eq!(s.auth_success, 2, "snapshot: {s}");
    assert_eq!(s.auth_failed, 0, "snapshot: {s}");
    assert_eq!(
        s.replay_rejected, 0,
        "fresh nonces must not hit replay cache: {s}"
    );

    conn2.close(0u32.into(), b"");
    endpoint.wait_idle().await;
    Ok(())
}
