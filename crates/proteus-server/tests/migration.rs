//! M7.4 connection-migration integration test.
//!
//! Scenario: client authenticates from local UDP port A, then rebinds
//! its endpoint to port B and exercises the connection from the new
//! 5-tuple. Quinn's PATH_CHALLENGE/PATH_RESPONSE machinery handles
//! the actual migration; PROTEUS's contribution is that auth state
//! survives because it's keyed on `client_id`, not on 5-tuple.
//!
//! What this test pins:
//! 1. After `endpoint.rebind(new_socket)`, the existing connection
//!    keeps working — a new bidi stream can be opened and a PROTEUS
//!    proxy handshake completes.
//! 2. The server still sees exactly one auth_attempt + one
//!    auth_success (i.e. it did NOT treat the migrated path as a
//!    fresh connection that needed re-authentication).
//! 3. The TCP proxy bridge survives the migration: a request sent
//!    after the rebind round-trips through a real localhost TCP
//!    echo server.

mod common;

use std::time::Duration;

use anyhow::Result;
use common::{TestServer, make_client_endpoint, open_tcp_proxy, run_auth};
use proteus_core::frame::{Frame, FrameType, read_frame_aead, write_frame_aead};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// Spawn a one-shot TCP echo on 127.0.0.1:0. Returns the listen port.
/// The echo reads up to `BUF_SIZE` bytes, writes them back, then closes.
async fn spawn_tcp_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn connection_survives_path_migration() -> Result<()> {
    let server = TestServer::start("alice").await?;
    let echo_port = spawn_tcp_echo().await;

    // ----- pre-migration: auth on path A -----
    let endpoint = make_client_endpoint(&server.cert_sha256)?;
    let path_a_local = endpoint.local_addr()?;
    let conn = endpoint.connect(server.addr, "localhost")?.await?;
    let session_key = run_auth(&conn, &server.client_id, &server.signing_key).await?;

    // Server should record exactly one auth_attempt + one auth_success.
    common::poll_until(
        || {
            let s = server.metrics.snapshot();
            s.auth_attempts == 1 && s.auth_success == 1
        },
        Duration::from_secs(2),
        Duration::from_millis(20),
    )
    .await;

    // ----- trigger migration: rebind the endpoint to a fresh UDP socket -----
    let new_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let path_b_local = new_socket.local_addr()?;
    assert_ne!(
        path_a_local.port(),
        path_b_local.port(),
        "rebind must produce a different local port"
    );
    endpoint.rebind(new_socket)?;

    // Push a small amount of work through the connection so Quinn
    // actually exercises the new path. Opening a fresh proxy stream
    // is the most natural way — it forces packets to flow on the
    // migrated 5-tuple, which is when PATH_CHALLENGE/RESPONSE fires.
    let (mut q_send, mut q_recv, mut sa, stream_id) =
        open_tcp_proxy(&conn, &session_key, "127.0.0.1", echo_port).await?;

    // Send a payload through the proxy, expect it echoed back.
    let payload = b"migrated-hello".to_vec();
    let data = Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id,
        payload: bytes::Bytes::from(payload.clone()),
    };
    write_frame_aead(&mut q_send, &data, &mut sa.send).await?;

    let echo = tokio::time::timeout(
        Duration::from_secs(3),
        read_frame_aead(&mut q_recv, &mut sa.recv),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timeout waiting for echoed DATA on migrated path"))??;
    assert_eq!(echo.frame_type, FrameType::Data);
    assert_eq!(echo.payload.as_ref(), payload.as_slice());

    // ----- post-migration: auth state must NOT have been re-paid -----
    // If the server treated the migrated 5-tuple as a new connection
    // it would log a second auth_attempt. PROTEUS's contract says no.
    common::poll_until(
        || {
            let s = server.metrics.snapshot();
            // proxy_tcp_opened increments after PROXY_ACCEPT; that's
            // our signal the migrated path actually drove a stream.
            s.proxy_tcp_opened >= 1
        },
        Duration::from_secs(2),
        Duration::from_millis(20),
    )
    .await;

    let s = server.metrics.snapshot();
    assert_eq!(
        s.auth_attempts, 1,
        "migrated path must NOT have triggered re-auth: {s}"
    );
    assert_eq!(s.auth_success, 1, "exactly one successful auth: {s}");
    assert_eq!(s.proxy_tcp_opened, 1, "one TCP proxy on migrated path: {s}");

    drop(q_send);
    drop(q_recv);
    conn.close(0u32.into(), b"test done");
    endpoint.wait_idle().await;
    Ok(())
}
