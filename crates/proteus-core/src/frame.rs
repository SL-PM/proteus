//! PROTEUS frame envelope (spec v0.2 §7.2).
//!
//! Wire format, all multi-byte fields big-endian:
//!
//! ```text
//! +--------+--------+----------------+--------------+----------+
//! | 2 B    | 2 B    | 8 B            | 4 B          | N B      |
//! +--------+--------+----------------+--------------+----------+
//! | type   | flags  | stream_id      | payload_len  | payload  |
//! +--------+--------+----------------+--------------+----------+
//! ```
//!
//! v0.3 hard-rejects `payload_len > 65_535`. Frame type space is fixed
//! by [`FrameType`].

use anyhow::{Result, bail};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Size of the fixed PROTEUS frame header in bytes.
pub const HEADER_LEN: usize = 16;

/// Maximum payload size accepted in v0.3.
pub const MAX_PAYLOAD_LEN: usize = 65_535;

/// Frame type discriminants per spec v0.2 §7.2.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    AuthRequest = 0x0001,
    AuthResponse = 0x0002,
    ProxyOpen = 0x0010,
    ProxyAccept = 0x0011,
    ProxyReject = 0x0012,
    Data = 0x0020,
    Ping = 0x0030,
    Pong = 0x0031,
}

impl FrameType {
    pub fn from_u16(v: u16) -> Result<Self> {
        Ok(match v {
            0x0001 => Self::AuthRequest,
            0x0002 => Self::AuthResponse,
            0x0010 => Self::ProxyOpen,
            0x0011 => Self::ProxyAccept,
            0x0012 => Self::ProxyReject,
            0x0020 => Self::Data,
            0x0030 => Self::Ping,
            0x0031 => Self::Pong,
            _ => bail!("unknown frame type 0x{v:04x}"),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub frame_type: FrameType,
    pub flags: u16,
    pub stream_id: u64,
    pub payload: Bytes,
}

impl Frame {
    /// Build a frame with default flags = 0, stream_id = 0.
    pub fn new(frame_type: FrameType, payload: impl Into<Bytes>) -> Result<Self> {
        let payload = payload.into();
        if payload.len() > MAX_PAYLOAD_LEN {
            bail!("payload {} > max {}", payload.len(), MAX_PAYLOAD_LEN);
        }
        Ok(Self {
            frame_type,
            flags: 0,
            stream_id: 0,
            payload,
        })
    }

    /// Encode the full frame (header + payload) into one contiguous buffer.
    pub fn encode(&self) -> Result<Bytes> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            bail!("payload {} > max {}", self.payload.len(), MAX_PAYLOAD_LEN);
        }
        let mut buf = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        buf.put_u16(self.frame_type as u16);
        buf.put_u16(self.flags);
        buf.put_u64(self.stream_id);
        buf.put_u32(self.payload.len() as u32);
        buf.extend_from_slice(&self.payload);
        Ok(buf.freeze())
    }

    /// Decode from a self-contained byte slice (header + full payload).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            bail!("frame too short: {} < {}", bytes.len(), HEADER_LEN);
        }
        let mut header = &bytes[..HEADER_LEN];
        let frame_type = FrameType::from_u16(header.get_u16())?;
        let flags = header.get_u16();
        let stream_id = header.get_u64();
        let payload_len = header.get_u32() as usize;
        if payload_len > MAX_PAYLOAD_LEN {
            bail!("payload_len {} > max {}", payload_len, MAX_PAYLOAD_LEN);
        }
        let rest = &bytes[HEADER_LEN..];
        if rest.len() < payload_len {
            bail!("payload short: have {}, need {}", rest.len(), payload_len);
        }
        Ok(Self {
            frame_type,
            flags,
            stream_id,
            payload: Bytes::copy_from_slice(&rest[..payload_len]),
        })
    }
}

/// Read one frame from any `AsyncRead`. Reads exactly the header, then
/// exactly the announced payload length.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let mut h = &header[..];
    let frame_type = FrameType::from_u16(h.get_u16())?;
    let flags = h.get_u16();
    let stream_id = h.get_u64();
    let payload_len = h.get_u32() as usize;
    if payload_len > MAX_PAYLOAD_LEN {
        bail!("payload_len {} > max {}", payload_len, MAX_PAYLOAD_LEN);
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    Ok(Frame {
        frame_type,
        flags,
        stream_id,
        payload: Bytes::from(payload),
    })
}

/// Write one frame to any `AsyncWrite`. Single `write_all` per frame
/// keeps the wire boundaries clean for packet capture.
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> Result<()> {
    let bytes = frame.encode()?;
    writer.write_all(&bytes).await?;
    Ok(())
}

// ----------- tests -----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_type_roundtrip_all_known() {
        for v in [
            0x0001u16, 0x0002, 0x0010, 0x0011, 0x0012, 0x0020, 0x0030, 0x0031,
        ] {
            let ft = FrameType::from_u16(v).unwrap();
            assert_eq!(ft as u16, v);
        }
    }

    #[test]
    fn frame_type_unknown_errors() {
        assert!(FrameType::from_u16(0xFFFF).is_err());
        assert!(FrameType::from_u16(0x0042).is_err());
    }

    #[test]
    fn encode_decode_roundtrip_empty_payload() {
        let f = Frame::new(FrameType::Ping, Bytes::new()).unwrap();
        let bytes = f.encode().unwrap();
        assert_eq!(bytes.len(), HEADER_LEN);
        let got = Frame::decode(&bytes).unwrap();
        assert_eq!(got, f);
    }

    #[test]
    fn encode_decode_roundtrip_with_payload() {
        let mut f = Frame::new(FrameType::Data, &b"hello world"[..]).unwrap();
        f.flags = 0xABCD;
        f.stream_id = 0x0123_4567_89AB_CDEF;
        let bytes = f.encode().unwrap();
        let got = Frame::decode(&bytes).unwrap();
        assert_eq!(got, f);
    }

    #[test]
    fn encode_decode_roundtrip_max_payload() {
        let payload = vec![0xAAu8; MAX_PAYLOAD_LEN];
        let f = Frame::new(FrameType::Data, payload.clone()).unwrap();
        let bytes = f.encode().unwrap();
        assert_eq!(bytes.len(), HEADER_LEN + MAX_PAYLOAD_LEN);
        let got = Frame::decode(&bytes).unwrap();
        assert_eq!(got.payload.as_ref(), payload.as_slice());
    }

    #[test]
    fn construction_rejects_oversized_payload() {
        let payload = vec![0u8; MAX_PAYLOAD_LEN + 1];
        let err = Frame::new(FrameType::Data, payload).unwrap_err();
        assert!(err.to_string().contains("max"), "got: {err}");
    }

    #[test]
    fn decode_rejects_oversized_payload_len_field() {
        let mut bytes = BytesMut::with_capacity(HEADER_LEN);
        bytes.put_u16(FrameType::Data as u16);
        bytes.put_u16(0);
        bytes.put_u64(0);
        bytes.put_u32(u32::MAX);
        let err = Frame::decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("payload_len"), "got: {err}");
    }

    #[test]
    fn decode_rejects_truncated_header() {
        let err = Frame::decode(&[0u8; HEADER_LEN - 1]).unwrap_err();
        assert!(err.to_string().contains("too short"), "got: {err}");
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        let mut bytes = BytesMut::with_capacity(HEADER_LEN);
        bytes.put_u16(FrameType::Data as u16);
        bytes.put_u16(0);
        bytes.put_u64(0);
        bytes.put_u32(10);
        let err = Frame::decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("payload short"), "got: {err}");
    }

    #[tokio::test]
    async fn async_roundtrip_over_duplex() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let f = Frame::new(FrameType::Ping, &b"hello"[..]).unwrap();
        let (w, r) = tokio::join!(write_frame(&mut a, &f), read_frame(&mut b));
        w.unwrap();
        let got = r.unwrap();
        assert_eq!(got, f);
    }

    #[test]
    fn decode_never_panics_on_random_input() {
        // M18.1 fuzz: feed Frame::decode random byte slices at several
        // sizes and verify it never panics. Err is fine, Ok is fine —
        // anything but a panic.
        use rand::{RngCore, SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(0xCAFE_BABE_DEAD_BEEF);
        for size in [0usize, 1, 5, 15, 16, 17, 32, 64, 256, 1024, 4096] {
            for _ in 0..200 {
                let mut buf = vec![0u8; size];
                rng.fill_bytes(&mut buf);
                let _ = Frame::decode(&buf);
            }
        }
    }
}
