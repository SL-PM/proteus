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

/// Buffer size for one TCP → QUIC chunk; each chunk becomes one DATA frame.
pub const BRIDGE_BUF_SIZE: usize = 8192;

/// Bidirectional bridge between a Quinn (send, recv) pair carrying PROTEUS
/// DATA frames and an arbitrary AsyncRead/AsyncWrite split (typically a TCP
/// socket). Used by the server to bridge a proxy stream to its upstream
/// TCP socket, and by the M9 SOCKS5 client to bridge an incoming SOCKS5
/// socket to a freshly opened proxy stream.
///
/// Returns when either direction reaches EOF (or errors). The QUIC-side
/// EOF is signaled by `read_frame` returning Err or by any non-DATA frame;
/// the TCP-side EOF is the usual zero-length read.
pub async fn bridge_quic_tcp<R, W>(
    mut q_send: quinn::SendStream,
    mut q_recv: quinn::RecvStream,
    mut tcp_r: R,
    mut tcp_w: W,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    use crate::frame::{Frame, FrameType, read_frame, write_frame};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let q2t = async move {
        loop {
            let f = match read_frame(&mut q_recv).await {
                Ok(f) => f,
                Err(_) => break,
            };
            if f.frame_type != FrameType::Data {
                break;
            }
            if !f.payload.is_empty() {
                tcp_w.write_all(&f.payload).await?;
            }
        }
        let _ = tcp_w.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };

    let t2q = async move {
        let mut buf = vec![0u8; BRIDGE_BUF_SIZE];
        loop {
            let n = tcp_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let frame = Frame::new(FrameType::Data, Bytes::copy_from_slice(&buf[..n]))?;
            write_frame(&mut q_send, &frame).await?;
        }
        let _ = q_send.finish();
        Ok::<(), anyhow::Error>(())
    };

    let (r1, r2) = tokio::join!(q2t, t2q);
    r1.context("quic→tcp bridge")?;
    r2.context("tcp→quic bridge")?;
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
}
