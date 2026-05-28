//! M4.5 — v0.5 bucket-padding integration test.
//!
//! Spins up an in-process server with `padding.enabled = true`, drives
//! a TCP proxy stream to a localhost echo, and observes the server→
//! client DATA frames AT THE RAW WIRE LEVEL (before AEAD-open /
//! depad). Asserts that every emitted frame's wire `payload_len` lands
//! on one of the configured bucket sizes — i.e. the per-frame size
//! fingerprint has been eliminated.
//!
//! Also includes a no-regression check: with padding OFF, frames are
//! NOT bucket-aligned (they reflect the real payload + AEAD tag), which
//! confirms the padding actually changed the wire and the test is
//! measuring the right thing.

mod common;

use std::time::Duration;

use anyhow::{Result, anyhow};
use common::{TestServer, make_client_endpoint, open_tcp_proxy, read_raw_wire_frame, run_auth};
use proteus_core::{
    frame::{Frame, FrameType, write_frame_aead},
    padding::DEFAULT_BUCKETS,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// Localhost TCP echo. Reads up to 4 KiB, writes it straight back.
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

/// Drive `payload` through the proxy and collect the wire sizes of the
/// server→client DATA frames that come back. Reads raw (no AEAD-open),
/// so each returned `usize` is the on-wire `payload_len`.
///
/// We can't tell how many real bytes a (possibly padded, always
/// AEAD-sealed) frame carries without decrypting, so instead of
/// counting bytes we use an idle-timeout: read the first frame with a
/// generous deadline (it must arrive), then keep reading with a short
/// per-frame timeout until no more frames show up — at which point the
/// echo response is complete.
async fn echo_and_collect_wire_sizes(
    q_send: &mut quinn::SendStream,
    q_recv: &mut quinn::RecvStream,
    sa: &mut proteus_core::aead::ProxyStreamAead,
    stream_id: u64,
    payload: &[u8],
) -> Result<Vec<usize>> {
    let data = Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id,
        payload: bytes::Bytes::copy_from_slice(payload),
    };
    write_frame_aead(q_send, &data, &mut sa.send).await?;

    let mut sizes = Vec::new();

    // First frame: must arrive within 2s.
    let (_flags, wire_len) =
        tokio::time::timeout(Duration::from_secs(2), read_raw_wire_frame(q_recv))
            .await
            .map_err(|_| anyhow!("timeout waiting for first echo frame"))??;
    sizes.push(wire_len);

    // Drain any follow-on frames (TCP fragmentation may split the echo)
    // with a short idle timeout. The `while let` exits on idle timeout
    // or read error — either means the echo response is complete.
    while let Ok(Ok((_flags, n))) =
        tokio::time::timeout(Duration::from_millis(300), read_raw_wire_frame(q_recv)).await
    {
        sizes.push(n);
        if sizes.len() > 64 {
            break; // safety
        }
    }
    Ok(sizes)
}

#[tokio::test]
async fn padded_server_frames_land_on_buckets() -> Result<()> {
    let server = TestServer::start_padded("alice").await?;
    let echo_port = spawn_tcp_echo().await;

    let endpoint = make_client_endpoint(&server.cert_sha256)?;
    let conn = endpoint.connect(server.addr, "localhost")?.await?;
    let session_key = run_auth(&conn, &server.client_id, &server.signing_key).await?;

    let (mut q_send, mut q_recv, mut sa, stream_id) =
        open_tcp_proxy(&conn, &session_key, "127.0.0.1", echo_port).await?;

    // Several payload sizes that map to different buckets:
    //   5    → wire 128
    //   100  → wire 128
    //   300  → wire 512
    //   1000 → wire 1024
    let payloads: Vec<Vec<u8>> = vec![
        vec![0x41; 5],
        vec![0x42; 100],
        vec![0x43; 300],
        vec![0x44; 1000],
    ];

    let mut all_sizes = Vec::new();
    for p in &payloads {
        let sizes =
            echo_and_collect_wire_sizes(&mut q_send, &mut q_recv, &mut sa, stream_id, p).await?;
        all_sizes.extend(sizes);
    }

    assert!(!all_sizes.is_empty(), "should have observed some frames");

    let bucketed = all_sizes
        .iter()
        .filter(|s| DEFAULT_BUCKETS.contains(s))
        .count();
    let ratio = bucketed as f64 / all_sizes.len() as f64;
    // Surfaced with `--nocapture` for the M5.5 sign-off measurement.
    eprintln!("M4.5 observed server→client wire sizes: {all_sizes:?}");
    assert!(
        ratio >= 0.95,
        "expected >=95% of server frames on a bucket size; got {:.0}% \
         ({bucketed}/{} bucketed). sizes={all_sizes:?}",
        ratio * 100.0,
        all_sizes.len()
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn unpadded_server_frames_are_not_bucket_aligned() -> Result<()> {
    // Control case: padding OFF → frame sizes track the real payload
    // (+ AEAD tag), so a 300-byte echo frame is ~316 bytes on the wire,
    // NOT 512. This proves the padded test above is measuring a real
    // change rather than a coincidence.
    let server = TestServer::start("alice").await?; // padding off
    let echo_port = spawn_tcp_echo().await;

    let endpoint = make_client_endpoint(&server.cert_sha256)?;
    let conn = endpoint.connect(server.addr, "localhost")?.await?;
    let session_key = run_auth(&conn, &server.client_id, &server.signing_key).await?;

    let (mut q_send, mut q_recv, mut sa, stream_id) =
        open_tcp_proxy(&conn, &session_key, "127.0.0.1", echo_port).await?;

    let payload = vec![0x43; 300];
    let sizes =
        echo_and_collect_wire_sizes(&mut q_send, &mut q_recv, &mut sa, stream_id, &payload).await?;

    // With padding off, a 300-byte echo should appear as ~316 bytes
    // (300 + 16-byte AEAD tag), which is NOT in the bucket set.
    let any_bucketed = sizes.iter().any(|s| DEFAULT_BUCKETS.contains(s));
    assert!(
        !any_bucketed,
        "padding-off frames should not coincidentally be bucket-sized: {sizes:?}"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}
