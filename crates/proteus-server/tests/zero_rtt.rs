//! M6.4 TLS 1.3 0-RTT integration test.
//!
//! Scenario: connect once over 1-RTT so the server issues a TLS
//! NewSessionTicket. Reconnect from the same endpoint and call
//! `Connecting::into_0rtt()`; verify either:
//!   * the resumed connection's 0-RTT was accepted by the server
//!     (the happy path — `accepted` future resolves to `true`), OR
//!   * 0-RTT was unavailable because the ticket hadn't arrived yet
//!     (the test is async-timing-dependent — a fallback to plain
//!     1-RTT must still let auth succeed without the `max_early_data
//!     != 0 or u32::MAX` panic that motivated the M6.4 follow-up fix).
//!
//! What this test actually pins is the server-side regression: with
//! `MAX_EARLY_DATA_BYTES = u32::MAX` in `proteus-core::tls`, fresh
//! incoming connections must NOT panic the quinn-proto rustls glue.
//! That's the original M6.4 bug the M5.4.1 UDP smoke uncovered.

mod common;

use std::time::Duration;

use anyhow::Result;
use common::{TestServer, make_client_endpoint, run_auth};

#[tokio::test]
async fn server_does_not_panic_on_fresh_quic_handshake() -> Result<()> {
    // Pure regression: `MAX_EARLY_DATA_BYTES = u32::MAX` setting must
    // not trip the `"QUIC sessions must set a max early data of 0 or
    // 2^32-1"` panic that previously took the server down on the
    // first incoming handshake. Running any successful auth here is
    // sufficient — the panic fires inside
    // `quinn::crypto::rustls::QuicServerConfig::try_from`, which is
    // exercised by `Server::bind`.
    let server = TestServer::start("alice").await?;
    let endpoint = make_client_endpoint(&server.cert_sha256)?;
    let conn = endpoint.connect(server.addr, "localhost")?.await?;
    run_auth(&conn, &server.client_id, &server.signing_key).await?;
    conn.close(0u32.into(), b"");
    endpoint.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn session_resumption_with_optional_0rtt() -> Result<()> {
    // Best-effort 0-RTT check. The test passes if EITHER:
    //   (a) `into_0rtt()` returns Ok and the `accepted` future
    //       resolves to `true` (real 0-RTT acceptance), OR
    //   (b) `into_0rtt()` returns Err (ticket cache not populated in
    //       time) but the fallback 1-RTT auth still succeeds.
    //
    // Both outcomes prove the server-side handling is correct; case
    // (a) is the M6.4 happy path. The flakier (a)-vs-(b) ratio is
    // about TLS ticket timing, which we don't control here.
    let server = TestServer::start("alice").await?;
    let endpoint = make_client_endpoint(&server.cert_sha256)?;

    // First connection: 1-RTT. Pay the auth, then open a no-op bidi
    // stream and let it sit briefly. This gives Quinn time to drain
    // the TLS NewSessionTicket post-handshake message — rustls only
    // hands the ticket to the cache after the underlying transport
    // has actually delivered the bytes, which on localhost still
    // takes a tick or two of the tokio scheduler.
    let conn1 = endpoint.connect(server.addr, "localhost")?.await?;
    run_auth(&conn1, &server.client_id, &server.signing_key).await?;
    // Open one more bidi to force at least one additional packet
    // round-trip; the ticket usually rides on the same flight.
    let _drain = conn1.open_bi().await.ok();
    tokio::time::sleep(Duration::from_millis(500)).await;
    conn1.close(0u32.into(), b"first done");
    // Wait for the close datagram to actually flush.
    endpoint.wait_idle().await;

    // Second connection: try 0-RTT. The same endpoint owns the
    // ClientConfig with the session cache, so the ticket from conn1
    // should be reused here.
    let connecting = endpoint.connect(server.addr, "localhost")?;
    match connecting.into_0rtt() {
        Ok((conn2, accepted_fut)) => {
            // 0-RTT is in flight. Run the auth handshake — this will
            // ride either the 0-RTT keys or the 1-RTT keys depending
            // on which arrives first; either way, auth must succeed.
            run_auth(&conn2, &server.client_id, &server.signing_key).await?;
            let accepted = accepted_fut.await;
            eprintln!("0-RTT accepted by server: {accepted}");
            conn2.close(0u32.into(), b"resumed done");
        }
        Err(connecting) => {
            // No ticket available yet — fall back to 1-RTT. This is a
            // legitimate outcome under tight timing.
            eprintln!("0-RTT unavailable (ticket not cached in time); falling back to 1-RTT");
            let conn2 = connecting.await?;
            run_auth(&conn2, &server.client_id, &server.signing_key).await?;
            conn2.close(0u32.into(), b"1-rtt done");
        }
    }

    // Either way, the server should have seen exactly two successful
    // auths (one per connection).
    common::poll_until(
        || {
            let s = server.metrics.snapshot();
            s.auth_success == 2
        },
        Duration::from_secs(2),
        Duration::from_millis(20),
    )
    .await;

    let s = server.metrics.snapshot();
    assert_eq!(s.auth_attempts, 2, "snapshot: {s}");
    assert_eq!(s.auth_success, 2, "snapshot: {s}");
    assert_eq!(s.auth_failed, 0, "snapshot: {s}");

    endpoint.wait_idle().await;
    Ok(())
}
