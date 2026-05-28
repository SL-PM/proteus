//! v0.5-rc.2 M8.5: timing-jitter integration test.
//!
//! The M6.5 unit tests prove the `Jitter` sampler returns in-range
//! durations. This test proves the *wired-up* delay (M7.5) behaves
//! correctly end-to-end:
//!
//! 1. **Correctness under jitter** — with server-side jitter enabled,
//!    a payload sent through the SOCKS-equivalent proxy stream is
//!    echoed back intact. This is the load-bearing assertion: it
//!    proves the `tokio::time::sleep` injected before each DATA send
//!    does not corrupt the stream, desync the per-stream AEAD nonce
//!    counters, or drop bytes.
//! 2. **Jitter is actually applied** — with a *constant* delay
//!    (min == max), the server→client echo cannot arrive faster than
//!    that delay. A coarse lower-bound timing assertion confirms the
//!    sleep is on the path (machine scheduling only ever adds time,
//!    so this is not flaky).
//!
//! Jitter is server-side here (the test drives client frames manually
//! rather than through the client bridge, so only the server's
//! echo→client send path is jittered — which is exactly the path the
//! test reads from).

mod common;

use std::time::{Duration, Instant};

use anyhow::Result;
use common::{TestServer, make_client_endpoint, open_tcp_proxy, run_auth};
use proteus_core::frame::{Frame, FrameType, read_frame_aead, write_frame_aead};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// One-shot TCP echo on 127.0.0.1:0. Returns the listen port.
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
async fn data_round_trips_with_jitter_enabled() -> Result<()> {
    // Constant 20 ms delay (min == max) makes the lower-bound timing
    // assertion deterministic without depending on RNG draws.
    const DELAY_MS: u64 = 20;
    let server = TestServer::start_jittered("alice", DELAY_MS, DELAY_MS).await?;
    let echo_port = spawn_tcp_echo().await;

    let endpoint = make_client_endpoint(&server.cert_sha256)?;
    let conn = endpoint.connect(server.addr, "localhost")?.await?;
    let session_key = run_auth(&conn, &server.client_id, &server.signing_key).await?;

    let (mut q_send, mut q_recv, mut sa, stream_id) =
        open_tcp_proxy(&conn, &session_key, "127.0.0.1", echo_port).await?;

    // A payload large enough to be unambiguous but single-frame.
    let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let data = Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id,
        payload: bytes::Bytes::from(payload.clone()),
    };

    let start = Instant::now();
    write_frame_aead(&mut q_send, &data, &mut sa.send).await?;

    let echo = tokio::time::timeout(
        Duration::from_secs(5),
        read_frame_aead(&mut q_recv, &mut sa.recv),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timeout waiting for jittered echo"))??;
    let elapsed = start.elapsed();

    // (1) Correctness: the jittered send path must not corrupt or drop.
    assert_eq!(echo.frame_type, FrameType::Data);
    assert_eq!(
        echo.payload.as_ref(),
        payload.as_slice(),
        "payload corrupted through jittered send path"
    );

    // (2) The server→client echo frame is delayed by the constant
    // jitter. Allow generous slack below the nominal 20 ms to absorb
    // timer granularity, but it must be clearly non-zero.
    assert!(
        elapsed >= Duration::from_millis(15),
        "echo arrived in {elapsed:?}, faster than the {DELAY_MS}ms jitter — \
         delay not on the path?"
    );

    conn.close(0u32.into(), b"test done");
    endpoint.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn larger_transfer_survives_jitter() -> Result<()> {
    // Several frames in a row with a small random jitter range — proves
    // multi-frame ordering + AEAD-counter sync hold under jitter.
    let server = TestServer::start_jittered("alice", 0, 5).await?;
    let echo_port = spawn_tcp_echo().await;

    let endpoint = make_client_endpoint(&server.cert_sha256)?;
    let conn = endpoint.connect(server.addr, "localhost")?.await?;
    let session_key = run_auth(&conn, &server.client_id, &server.signing_key).await?;
    let (mut q_send, mut q_recv, mut sa, stream_id) =
        open_tcp_proxy(&conn, &session_key, "127.0.0.1", echo_port).await?;

    // Send 5 distinct frames; collect 5 echoes back. Each echo frame
    // passes through the server's jittered send loop.
    let mut expected = Vec::new();
    for i in 0..5u8 {
        let payload = vec![i; 200 + i as usize];
        expected.push(payload.clone());
        let f = Frame {
            frame_type: FrameType::Data,
            flags: 0,
            stream_id,
            payload: bytes::Bytes::from(payload),
        };
        write_frame_aead(&mut q_send, &f, &mut sa.send).await?;
    }

    // Reassemble echoed bytes until we've seen everything we sent.
    let total_expected: usize = expected.iter().map(|p| p.len()).sum();
    let mut got = Vec::new();
    while got.len() < total_expected {
        let echo = tokio::time::timeout(
            Duration::from_secs(5),
            read_frame_aead(&mut q_recv, &mut sa.recv),
        )
        .await
        .map_err(|_| anyhow::anyhow!("timeout reassembling jittered echoes"))??;
        if echo.frame_type == FrameType::Data {
            got.extend_from_slice(&echo.payload);
        }
    }

    let flat: Vec<u8> = expected.into_iter().flatten().collect();
    assert_eq!(got, flat, "byte stream corrupted/reordered under jitter");

    conn.close(0u32.into(), b"test done");
    endpoint.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn token_bucket_burst_does_not_serialize() -> Result<()> {
    // M9.5: with a large per-frame delay (100ms) BUT a burst allowance
    // bigger than the traffic, the token bucket lets every echo frame
    // through for free — so the exchange finishes far faster than the
    // per-frame-jitter worst case (which would be ~delay × frames).
    // burst = 50 >> the handful of server→client frames we generate.
    let server = TestServer::start_jittered_burst("alice", 100, 100, 50).await?;
    let echo_port = spawn_tcp_echo().await;

    let endpoint = make_client_endpoint(&server.cert_sha256)?;
    let conn = endpoint.connect(server.addr, "localhost")?.await?;
    let session_key = run_auth(&conn, &server.client_id, &server.signing_key).await?;
    let (mut q_send, mut q_recv, mut sa, stream_id) =
        open_tcp_proxy(&conn, &session_key, "127.0.0.1", echo_port).await?;

    let payload: Vec<u8> = (0..800u32).map(|i| (i % 251) as u8).collect();
    let data = Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id,
        payload: bytes::Bytes::from(payload.clone()),
    };

    let start = Instant::now();
    write_frame_aead(&mut q_send, &data, &mut sa.send).await?;
    let echo = tokio::time::timeout(
        Duration::from_secs(5),
        read_frame_aead(&mut q_recv, &mut sa.recv),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timeout waiting for burst-paced echo"))??;
    let elapsed = start.elapsed();

    // Correctness under pacing.
    assert_eq!(echo.frame_type, FrameType::Data);
    assert_eq!(echo.payload.as_ref(), payload.as_slice());

    // The single echo frame rode a free burst token → no 100ms delay.
    // Generous bound (well under the 100ms per-frame delay) keeps this
    // non-flaky while still proving the burst bypassed pacing.
    assert!(
        elapsed < Duration::from_millis(80),
        "burst-token send took {elapsed:?}; expected ~free (≪100ms delay)"
    );

    conn.close(0u32.into(), b"test done");
    endpoint.wait_idle().await;
    Ok(())
}
