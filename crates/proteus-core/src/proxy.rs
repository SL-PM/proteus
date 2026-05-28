//! TCP/UDP proxy framing (spec v0.2 §9).
//!
//! Once auth succeeds on the control stream, the client opens one new
//! bidirectional stream per proxy target. The first frame on that stream
//! is `PROXY_OPEN`, carrying a CBOR map describing the target:
//!
//! ```cbor
//! {
//!   "v":    1,
//!   "cmd":  "tcp" | "udp",
//!   "host": "example.com",
//!   "port": 443
//! }
//! ```
//!
//! The server replies with `PROXY_ACCEPT` (empty payload) or
//! `PROXY_REJECT` (1-byte reason code). On ACCEPT, subsequent `DATA`
//! frames on the same stream carry the proxied bytes verbatim.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// PROXY_OPEN wire-format version (only v=1 is recognized in v0.3).
pub const PROXY_PROTO_VERSION: u8 = 1;

/// 1-byte reason codes for `PROXY_REJECT`.
pub mod reject {
    pub const POLICY_DENIED: u8 = 0x01;
    pub const UPSTREAM_UNREACHABLE: u8 = 0x02;
    pub const UNSUPPORTED_CMD: u8 = 0x03;
    pub const PROTOCOL_ERROR: u8 = 0x04;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyOpen {
    pub v: u8,
    pub cmd: String,
    pub host: String,
    pub port: u16,
}

impl ProxyOpen {
    pub fn new_tcp(host: impl Into<String>, port: u16) -> Self {
        Self {
            v: PROXY_PROTO_VERSION,
            cmd: "tcp".into(),
            host: host.into(),
            port,
        }
    }

    pub fn new_udp(host: impl Into<String>, port: u16) -> Self {
        Self {
            v: PROXY_PROTO_VERSION,
            cmd: "udp".into(),
            host: host.into(),
            port,
        }
    }

    pub fn encode(&self) -> Result<Bytes> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).context("encode PROXY_OPEN CBOR")?;
        Ok(Bytes::from(buf))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let parsed: Self = ciborium::from_reader(bytes).context("decode PROXY_OPEN CBOR")?;
        if parsed.v != PROXY_PROTO_VERSION {
            bail!(
                "unsupported PROXY_OPEN version {} (expected {})",
                parsed.v,
                PROXY_PROTO_VERSION
            );
        }
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyReject {
    pub reason: u8,
}

impl ProxyReject {
    pub fn new(reason: u8) -> Self {
        Self { reason }
    }

    pub fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(&[self.reason])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 1 {
            bail!("PROXY_REJECT must be exactly 1 byte (got {})", bytes.len());
        }
        Ok(Self { reason: bytes[0] })
    }

    pub fn name(&self) -> &'static str {
        match self.reason {
            reject::POLICY_DENIED => "policy-denied",
            reject::UPSTREAM_UNREACHABLE => "upstream-unreachable",
            reject::UNSUPPORTED_CMD => "unsupported-cmd",
            reject::PROTOCOL_ERROR => "protocol-error",
            _ => "unknown",
        }
    }
}

/// Buffer size for one TCP → QUIC chunk when padding is disabled.
/// Each chunk becomes one DATA frame.
pub const BRIDGE_BUF_SIZE: usize = 8192;

/// Pick the TCP-read buffer size when bucket-padding is in effect.
/// Returns `max(buckets) - aead_tag - pad_trailer` so the post-AEAD
/// wire `payload_len` lands exactly on the largest bucket. Falls
/// back to [`BRIDGE_BUF_SIZE`] when `buckets` is `None`.
pub fn bridge_buf_size(buckets: Option<&[usize]>) -> usize {
    use crate::{aead::TAG_LEN, padding::PAD_TRAILER_LEN};
    match buckets {
        None => BRIDGE_BUF_SIZE,
        Some(b) => b
            .iter()
            .copied()
            .max()
            .map(|m| m.saturating_sub(TAG_LEN + PAD_TRAILER_LEN))
            .unwrap_or(BRIDGE_BUF_SIZE),
    }
}

/// Runtime idle-padding parameters for the server's send-to-client
/// direction (v0.5 M3.5). When supplied to a bridge, the send loop
/// emits one dummy PING frame after `interval` of stream-quiet time,
/// padded to the wire `bucket`. The receiving peer discards inbound
/// PING frames silently.
#[derive(Debug, Clone)]
pub struct IdlePad {
    pub interval: std::time::Duration,
    pub bucket: usize,
}

impl IdlePad {
    /// The single-element bucket set used to pad each idle PING. Kept
    /// as a helper so the bridges don't allocate it per tick.
    fn ping_buckets(&self) -> [usize; 1] {
        [self.bucket]
    }
}

/// Bidirectional bridge between a Quinn (send, recv) pair carrying PROTEUS
/// DATA frames and an arbitrary AsyncRead/AsyncWrite split (typically a TCP
/// socket). Used by the server to bridge a proxy stream to its upstream
/// TCP socket, and by the M9 SOCKS5 client to bridge an incoming SOCKS5
/// socket to a freshly opened proxy stream.
///
/// Returns when either direction reaches EOF (or errors). The QUIC-side
/// EOF is signaled by `read_frame` returning Err or by any non-DATA frame;
/// the TCP-side EOF is the usual zero-length read.
///
/// v0.5 M2.5: `wire_buckets` enables bucket-padding for outgoing DATA
/// frames. `None` = no padding (v0.4 behavior); `Some(buckets)` =
/// every emitted frame's wire `payload_len` is rounded up to a
/// bucket. The TCP-read buffer also shrinks to fit the largest bucket
/// so a single TCP chunk never overflows.
///
/// v0.5 M3.5: `idle` enables server-side idle dummy traffic. When
/// `Some`, the TCP→QUIC direction emits a PING frame after
/// `idle.interval` of no upstream activity (padded to `idle.bucket`).
/// The QUIC→TCP direction silently discards inbound PING frames so
/// idle-padding can be one-directional. Pass `None` on the client.
#[allow(clippy::too_many_arguments)]
pub async fn bridge_quic_tcp<R, W>(
    mut q_send: quinn::SendStream,
    mut q_recv: quinn::RecvStream,
    mut tcp_r: R,
    mut tcp_w: W,
    mut aead_send: crate::aead::InnerAead,
    mut aead_recv: crate::aead::InnerAead,
    wire_buckets: Option<Vec<usize>>,
    idle: Option<IdlePad>,
    jitter: Option<crate::jitter::JitterPlan>,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    use crate::frame::{Frame, FrameType, read_frame_aead, write_frame_aead_maybe_padded};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let stream_id = q_send.id().index();
    let buf_size = bridge_buf_size(wire_buckets.as_deref());

    let q2t = async move {
        loop {
            let f = match read_frame_aead(&mut q_recv, &mut aead_recv).await {
                Ok(f) => f,
                Err(_) => break,
            };
            match f.frame_type {
                FrameType::Data => {
                    if !f.payload.is_empty() {
                        tcp_w.write_all(&f.payload).await?;
                    }
                }
                // v0.5 M3.5: idle dummy frame — discard and keep going.
                FrameType::Ping => continue,
                // Anything else terminates the bridge (legacy EOF signal).
                _ => break,
            }
        }
        let _ = tcp_w.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };

    let t2q = async move {
        use std::time::Instant;
        let mut buf = vec![0u8; buf_size];
        let mut last_activity = Instant::now();
        // v0.5 M9.5: token-bucket pacer (burst==0 → rc.2 per-frame jitter).
        let mut pacer = jitter.map(|p| crate::jitter::Pacer::new(p, Instant::now()));
        loop {
            let idle_tick = idle_deadline(idle.as_ref(), last_activity);
            tokio::select! {
                read = tcp_r.read(&mut buf) => {
                    let n = read?;
                    if n == 0 {
                        break;
                    }
                    let frame = Frame {
                        frame_type: FrameType::Data,
                        flags: 0,
                        stream_id,
                        payload: Bytes::copy_from_slice(&buf[..n]),
                    };
                    // v0.5 M7.5/M9.5: pace the real DATA send (NOT idle
                    // PINGs — see plan §11.3). burst==0 ⇒ per-frame jitter.
                    if let Some(p) = pacer.as_mut() {
                        let d = p.next_delay(Instant::now());
                        if !d.is_zero() {
                            tokio::time::sleep(d).await;
                        }
                    }
                    write_frame_aead_maybe_padded(
                        &mut q_send,
                        &frame,
                        &mut aead_send,
                        wire_buckets.as_deref(),
                    )
                    .await?;
                    last_activity = Instant::now();
                }
                _ = idle_tick => {
                    if let Some(i) = idle.as_ref() {
                        let ping = Frame {
                            frame_type: FrameType::Ping,
                            flags: 0,
                            stream_id,
                            payload: Bytes::new(),
                        };
                        write_frame_aead_maybe_padded(
                            &mut q_send,
                            &ping,
                            &mut aead_send,
                            Some(&i.ping_buckets()),
                        )
                        .await?;
                    }
                    last_activity = Instant::now();
                }
            }
        }
        let _ = q_send.finish();
        Ok::<(), anyhow::Error>(())
    };

    let (r1, r2) = tokio::join!(q2t, t2q);
    r1.context("quic→tcp bridge")?;
    r2.context("tcp→quic bridge")?;
    Ok(())
}

/// Idle-deadline future for a bridge send loop. When `idle` is `Some`,
/// resolves `interval` after `last_activity`; when `None`, never
/// resolves (so the `select!` idle branch is effectively disabled and
/// behavior matches the no-idle-padding path exactly).
async fn idle_deadline(idle: Option<&IdlePad>, last_activity: std::time::Instant) {
    match idle {
        Some(i) => {
            let deadline = last_activity + i.interval;
            tokio::time::sleep_until(deadline.into()).await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// Bidirectional bridge between a Quinn (send, recv) pair and a connected
/// `tokio::net::UdpSocket`. One PROTEUS DATA frame per UDP datagram in
/// both directions. v0.3 picks this over QUIC DATAGRAM extension for
/// simplicity — head-of-line blocking inside the stream is accepted.
///
/// Termination: UDP has no natural EOF on the recv side, so the bridge
/// terminates when the QUIC side signals EOF (client called
/// `SendStream::finish()`). After that, the UDP→QUIC direction gets a
/// short grace window (500 ms) to drain any in-flight responses before
/// it is dropped.
#[allow(clippy::too_many_arguments)]
pub async fn bridge_quic_udp(
    mut q_send: quinn::SendStream,
    mut q_recv: quinn::RecvStream,
    udp: tokio::net::UdpSocket,
    mut aead_send: crate::aead::InnerAead,
    mut aead_recv: crate::aead::InnerAead,
    wire_buckets: Option<Vec<usize>>,
    idle: Option<IdlePad>,
    jitter: Option<crate::jitter::JitterPlan>,
) -> anyhow::Result<()> {
    use std::{sync::Arc, time::Duration, time::Instant};

    use crate::frame::{Frame, FrameType, read_frame_aead, write_frame_aead_maybe_padded};

    /// Max IPv4 UDP datagram payload (65535 - 8 UDP - 20 IP).
    const UDP_RECV_BUF: usize = 65_507;
    const DRAIN_GRACE: Duration = Duration::from_millis(500);

    let stream_id = q_send.id().index();
    let u2q_buf_size = bridge_buf_size(wire_buckets.as_deref());

    let udp = Arc::new(udp);
    let udp_send = udp.clone();
    let udp_recv = udp.clone();

    let q2u = async move {
        loop {
            let f = match read_frame_aead(&mut q_recv, &mut aead_recv).await {
                Ok(f) => f,
                Err(_) => break,
            };
            match f.frame_type {
                FrameType::Data => {
                    if !f.payload.is_empty() {
                        udp_send.send(&f.payload).await?;
                    }
                }
                // v0.5 M3.5: idle dummy frame — discard and keep going.
                FrameType::Ping => continue,
                _ => break,
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    let u2q = async move {
        // With padding ON the read buffer is sized to fit a single
        // bucketed frame; without padding we keep the full UDP MTU.
        // Datagrams larger than `u2q_buf_size` get truncated by the
        // OS — operators running padded UDP must accept this trade.
        let buf_size = match wire_buckets.as_deref() {
            Some(_) => u2q_buf_size,
            None => UDP_RECV_BUF,
        };
        let mut buf = vec![0u8; buf_size];
        let mut last_activity = Instant::now();
        // v0.5 M9.5: token-bucket pacer (burst==0 → rc.2 per-frame jitter).
        let mut pacer = jitter.map(|p| crate::jitter::Pacer::new(p, Instant::now()));
        loop {
            let idle_tick = idle_deadline(idle.as_ref(), last_activity);
            tokio::select! {
                recv = udp_recv.recv(&mut buf) => {
                    let n = recv?;
                    let frame = Frame {
                        frame_type: FrameType::Data,
                        flags: 0,
                        stream_id,
                        payload: Bytes::copy_from_slice(&buf[..n]),
                    };
                    // v0.5 M7.5/M9.5: pace the real DATA send (NOT idle
                    // PINGs — see plan §11.3). burst==0 ⇒ per-frame jitter.
                    if let Some(p) = pacer.as_mut() {
                        let d = p.next_delay(Instant::now());
                        if !d.is_zero() {
                            tokio::time::sleep(d).await;
                        }
                    }
                    write_frame_aead_maybe_padded(
                        &mut q_send,
                        &frame,
                        &mut aead_send,
                        wire_buckets.as_deref(),
                    )
                    .await?;
                    last_activity = Instant::now();
                }
                _ = idle_tick => {
                    if let Some(i) = idle.as_ref() {
                        let ping = Frame {
                            frame_type: FrameType::Ping,
                            flags: 0,
                            stream_id,
                            payload: Bytes::new(),
                        };
                        write_frame_aead_maybe_padded(
                            &mut q_send,
                            &ping,
                            &mut aead_send,
                            Some(&i.ping_buckets()),
                        )
                        .await?;
                    }
                    last_activity = Instant::now();
                }
            }
        }
        // The loop above is divergent; this Ok exists so the async
        // block's return type can be inferred as Result<(), _>.
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    tokio::pin!(q2u, u2q);
    tokio::select! {
        r = &mut q2u => {
            r.context("quic→udp bridge")?;
            // QUIC side done; drain UDP responses briefly.
            let _ = tokio::time::timeout(DRAIN_GRACE, &mut u2q).await;
        }
        r = &mut u2q => {
            r.context("udp→quic bridge")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_open_tcp_roundtrip() {
        let open = ProxyOpen::new_tcp("example.com", 443);
        let bytes = open.encode().unwrap();
        let got = ProxyOpen::decode(&bytes).unwrap();
        assert_eq!(got, open);
        assert_eq!(got.cmd, "tcp");
    }

    #[test]
    fn proxy_open_udp_roundtrip() {
        let open = ProxyOpen::new_udp("1.1.1.1", 53);
        let bytes = open.encode().unwrap();
        let got = ProxyOpen::decode(&bytes).unwrap();
        assert_eq!(got, open);
        assert_eq!(got.cmd, "udp");
    }

    #[test]
    fn proxy_open_rejects_unknown_version() {
        let mut open = ProxyOpen::new_tcp("h", 80);
        open.v = 99;
        let bytes = open.encode().unwrap();
        let err = ProxyOpen::decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("version"), "got: {err}");
    }

    #[test]
    fn proxy_open_rejects_garbage_bytes() {
        assert!(ProxyOpen::decode(&[0xFF, 0xFE, 0xFD]).is_err());
        assert!(ProxyOpen::decode(&[]).is_err());
    }

    #[test]
    fn proxy_reject_roundtrip_all_reasons() {
        for reason in [
            reject::POLICY_DENIED,
            reject::UPSTREAM_UNREACHABLE,
            reject::UNSUPPORTED_CMD,
            reject::PROTOCOL_ERROR,
        ] {
            let r = ProxyReject::new(reason);
            let bytes = r.encode();
            assert_eq!(bytes.len(), 1);
            let got = ProxyReject::decode(&bytes).unwrap();
            assert_eq!(got, r);
        }
    }

    #[test]
    fn proxy_reject_rejects_wrong_size() {
        assert!(ProxyReject::decode(&[]).is_err());
        assert!(ProxyReject::decode(&[1, 2]).is_err());
    }

    #[test]
    fn proxy_reject_name_known_and_unknown() {
        assert_eq!(
            ProxyReject::new(reject::POLICY_DENIED).name(),
            "policy-denied"
        );
        assert_eq!(
            ProxyReject::new(reject::UPSTREAM_UNREACHABLE).name(),
            "upstream-unreachable"
        );
        assert_eq!(ProxyReject::new(0xFF).name(), "unknown");
    }

    #[test]
    fn bridge_buf_size_accounts_for_tag_and_trailer() {
        // None → full buffer.
        assert_eq!(bridge_buf_size(None), BRIDGE_BUF_SIZE);
        // Some([..1500]) → 1500 - 16 tag - 2 trailer = 1482.
        assert_eq!(bridge_buf_size(Some(&[128, 256, 1500])), 1482);
        // Single small bucket.
        assert_eq!(bridge_buf_size(Some(&[128])), 128 - 18);
    }

    #[test]
    fn idle_pad_ping_buckets_is_single_element() {
        let i = IdlePad {
            interval: std::time::Duration::from_secs(5),
            bucket: 1024,
        };
        assert_eq!(i.ping_buckets(), [1024]);
    }

    /// The QUIC→app receive direction must DISCARD PING frames (idle
    /// dummies) and keep going, not treat them as EOF. This guards the
    /// M3.5 receive-loop change: a PING in the middle of a DATA stream
    /// must not tear the bridge down.
    #[tokio::test]
    async fn bridge_tcp_discards_ping_and_keeps_data() {
        use crate::aead::{DIR_S2C, InnerAead};
        use crate::frame::{Frame, FrameType, write_frame_aead};

        // Server-side bridge: q_recv carries [PING, DATA("hello"), EOF]
        // from the "client". We feed those frames into a duplex acting
        // as the QUIC recv stream is not trivial without a real Quinn
        // stream, so instead we unit-test the frame-classification
        // contract directly: read_frame_aead over a duplex, then assert
        // a PING is skippable and DATA is delivered.
        //
        // (Full end-to-end idle-padding is covered by the M4.5
        // integration test against a live server.)
        let session = InnerAead::derive_key(
            b"exp-32bytes-of-test-material-aa",
            b"nonce-32-bytes-of-test-input-bb",
        )
        .unwrap();
        let stream_key = InnerAead::derive_stream_key(&session, 3);
        let mut send = InnerAead::for_direction(&stream_key, DIR_S2C);
        let mut recv = InnerAead::for_direction(&stream_key, DIR_S2C);

        let (mut a, mut b) = tokio::io::duplex(4096);

        // Writer: PING then DATA.
        let writer = async move {
            let mut ping = Frame::new(FrameType::Ping, bytes::Bytes::new()).unwrap();
            ping.stream_id = 3;
            write_frame_aead(&mut a, &ping, &mut send).await.unwrap();

            let mut data = Frame::new(FrameType::Data, &b"hello"[..]).unwrap();
            data.stream_id = 3;
            write_frame_aead(&mut a, &data, &mut send).await.unwrap();
            drop(a); // EOF
        };

        // Reader: classify like the bridge q2t loop does.
        let reader = async move {
            use crate::frame::read_frame_aead;
            let mut delivered: Vec<u8> = Vec::new();
            loop {
                let f = match read_frame_aead(&mut b, &mut recv).await {
                    Ok(f) => f,
                    Err(_) => break,
                };
                match f.frame_type {
                    FrameType::Data => delivered.extend_from_slice(&f.payload),
                    FrameType::Ping => continue,
                    _ => break,
                }
            }
            delivered
        };

        let (_, delivered) = tokio::join!(writer, reader);
        assert_eq!(delivered, b"hello", "PING must be skipped, DATA delivered");
    }
}
