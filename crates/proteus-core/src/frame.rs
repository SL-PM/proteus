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

/// Frame-flag bit set on padded frames (v0.5 M1.5). When this bit is
/// present in `flags`, the last 2 bytes of `payload` are
/// `padding_len: u16` (big-endian) — the number of padding bytes
/// (zeros) that immediately precede the trailer. Real payload is
/// `payload[.. payload_len - 2 - padding_len]`. Padding is opaque
/// to layers above [`crate::frame`]: the wire reader strips it
/// before the frame reaches application code.
///
/// See [`crate::padding`] for the bucket-rounding helpers that
/// choose `padding_len` for a given bucket size, and for the
/// `pad_frame` / `depad_frame_payload` round-trip helpers.
pub const FLAG_PADDED: u16 = 0x0001;

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

/// Inner-AEAD wire wrapping (M5.4.1).
///
/// Returns the 12-byte AAD for a frame's AEAD seal/open: 2 bytes
/// frame_type + 2 bytes flags + 8 bytes stream_id. `payload_len` is
/// intentionally NOT included — its value depends on the sealed size
/// (a chicken-and-egg dependency on the AEAD output). Excluding it
/// costs nothing for security: the AEAD tag covers the payload bytes
/// anyway, and the other three fields bind the frame to its routing
/// context.
pub fn aad_for_frame_header(frame_type: FrameType, flags: u16, stream_id: u64) -> [u8; 12] {
    let mut aad = [0u8; 12];
    aad[0..2].copy_from_slice(&(frame_type as u16).to_be_bytes());
    aad[2..4].copy_from_slice(&flags.to_be_bytes());
    aad[4..12].copy_from_slice(&stream_id.to_be_bytes());
    aad
}

/// Write a frame whose payload is AEAD-sealed with `aead` (M5.4.1).
/// The on-wire `payload_len` field reflects the sealed (ciphertext +
/// 16-byte tag) size. Counter advances by 1.
pub async fn write_frame_aead<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
    aead: &mut crate::aead::InnerAead,
) -> Result<()> {
    let aad = aad_for_frame_header(frame.frame_type, frame.flags, frame.stream_id);
    let sealed = aead.seal(&frame.payload, &aad)?;
    let wrapped = Frame {
        frame_type: frame.frame_type,
        flags: frame.flags,
        stream_id: frame.stream_id,
        payload: sealed,
    };
    write_frame(writer, &wrapped).await
}

/// Read a frame whose payload was AEAD-sealed by the peer (M5.4.1).
/// Returns the frame with the plaintext payload. Counter advances by 1.
///
/// v0.5 M1.5+: if [`FLAG_PADDED`] is set on the incoming wire frame,
/// the padding lives INSIDE the AEAD-sealed block. We open the
/// ciphertext first (AAD covers the WIRE flags, including the PADDED
/// bit), then strip the padding before returning. The flag is cleared
/// on the returned frame so callers see a v0.4-shape result.
pub async fn read_frame_aead<R: AsyncRead + Unpin>(
    reader: &mut R,
    aead: &mut crate::aead::InnerAead,
) -> Result<Frame> {
    let raw = read_raw_frame(reader).await?;
    let aad = aad_for_frame_header(raw.frame_type, raw.flags, raw.stream_id);
    let plaintext = aead.open(&raw.payload, &aad)?;
    let mut decoded = Frame {
        frame_type: raw.frame_type,
        flags: raw.flags,
        stream_id: raw.stream_id,
        payload: plaintext,
    };
    crate::padding::take_depadded_payload(&mut decoded)?;
    Ok(decoded)
}

/// Read one frame from any `AsyncRead`. Reads exactly the header, then
/// exactly the announced payload length.
///
/// v0.5 M1.5+: if [`FLAG_PADDED`] is set on the wire, the trailing
/// padding bytes are stripped before returning and the flag is cleared.
/// Callers see a v0.4-shape frame regardless of wire-side padding.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame> {
    let mut decoded = read_raw_frame(reader).await?;
    crate::padding::take_depadded_payload(&mut decoded)?;
    Ok(decoded)
}

/// Internal: read a frame off the wire WITHOUT touching any padding.
/// Used by both `read_frame` and `read_frame_aead`; the latter must
/// see the still-padded payload as AEAD ciphertext input before
/// depadding can happen.
async fn read_raw_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame> {
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

/// v0.5 M2.5: write a frame, optionally bucket-padding it first.
///
/// `wire_buckets` describes the desired *on-wire* `payload_len` bucket
/// set. When `None`, behaves exactly like [`write_frame`] (v0.4
/// compatibility). When `Some`, the frame's `payload` is padded to
/// the smallest fitting wire bucket and [`FLAG_PADDED`] is set
/// before the encode.
///
/// Errors if no bucket fits the real payload — caller must split
/// (the proxy bridges do this naturally by reading less per turn
/// when padding is enabled).
pub async fn write_frame_maybe_padded<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
    wire_buckets: Option<&[usize]>,
) -> Result<()> {
    match wire_buckets {
        None => write_frame(writer, frame).await,
        Some(buckets) => {
            // Plain (non-AEAD) frame: wire payload == post-pad payload,
            // so wire bucket == padded bucket directly.
            let padded = crate::padding::pad_frame(frame.clone(), buckets)?;
            write_frame(writer, &padded).await
        }
    }
}

/// v0.5 M2.5: AEAD-seal and write a frame, optionally bucket-padding
/// the plaintext first so the WIRE `payload_len` lands on a bucket.
///
/// Because AEAD adds [`crate::aead::TAG_LEN`] (16) bytes of tag, the
/// pre-AEAD plaintext is padded to (`bucket` − 16) bytes for each
/// caller-supplied wire bucket. The padded plaintext is then sealed,
/// and the resulting wire `payload_len` equals the chosen bucket
/// exactly.
///
/// `wire_buckets` controls the on-wire payload-size distribution. Use
/// e.g. `Some(&[128, 256, 512, 1024, 1500])` for the v0.5 default.
/// `None` = no padding, behaves exactly like [`write_frame_aead`].
pub async fn write_frame_aead_maybe_padded<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
    aead: &mut crate::aead::InnerAead,
    wire_buckets: Option<&[usize]>,
) -> Result<()> {
    match wire_buckets {
        None => write_frame_aead(writer, frame, aead).await,
        Some(buckets) => {
            // AEAD adds TAG_LEN bytes between pad-output and wire.
            // Pad the plaintext to (wire_bucket - TAG_LEN); after seal
            // the wire payload_len equals wire_bucket.
            let tag = crate::aead::TAG_LEN;
            let inner_buckets: Vec<usize> = buckets.iter().map(|b| b.saturating_sub(tag)).collect();
            let padded = crate::padding::pad_frame(frame.clone(), &inner_buckets)?;
            write_frame_aead(writer, &padded, aead).await
        }
    }
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

    #[tokio::test]
    async fn aead_frame_roundtrip_over_duplex() {
        use crate::aead::{DIR_C2S, InnerAead};
        let session = InnerAead::derive_key(
            b"exp-32bytes-of-test-material-aa",
            b"nonce-32-bytes-of-test-input-bb",
        )
        .unwrap();
        let stream_key = InnerAead::derive_stream_key(&session, 0x1234_5678);
        let mut send = InnerAead::for_direction(&stream_key, DIR_C2S);
        let mut recv = InnerAead::for_direction(&stream_key, DIR_C2S);

        let (mut a, mut b) = tokio::io::duplex(256);
        let mut f = Frame::new(FrameType::Data, &b"hello-aead"[..]).unwrap();
        f.stream_id = 0x1234_5678;

        let (w, r) = tokio::join!(
            write_frame_aead(&mut a, &f, &mut send),
            read_frame_aead(&mut b, &mut recv)
        );
        w.unwrap();
        let got = r.unwrap();
        assert_eq!(got.payload.as_ref(), b"hello-aead");
        assert_eq!(got.stream_id, 0x1234_5678);
    }

    #[tokio::test]
    async fn aead_frame_aad_binds_stream_id() {
        // Sender seals with stream_id=A. Receiver opens with stream_id=B
        // (changed in flight) — AAD mismatch → AEAD fails.
        use crate::aead::{DIR_C2S, InnerAead};
        let session = InnerAead::derive_key(
            b"exp-32bytes-of-test-material-aa",
            b"nonce-32-bytes-of-test-input-bb",
        )
        .unwrap();
        let stream_key = InnerAead::derive_stream_key(&session, 1);
        let mut send = InnerAead::for_direction(&stream_key, DIR_C2S);

        let mut f = Frame::new(FrameType::Data, &b"x"[..]).unwrap();
        f.stream_id = 1;
        let sealed_bytes = send
            .seal(&f.payload, &aad_for_frame_header(f.frame_type, f.flags, 1))
            .unwrap();

        // Try to open with stream_id=2 in the AAD.
        let mut recv = InnerAead::for_direction(&stream_key, DIR_C2S);
        let result = recv.open(
            &sealed_bytes,
            &aad_for_frame_header(f.frame_type, f.flags, 2),
        );
        assert!(result.is_err(), "AAD with different stream_id must reject");
    }

    #[test]
    fn aad_for_frame_header_encodes_be() {
        let aad = aad_for_frame_header(FrameType::Data, 0xABCD, 0x0123_4567_89AB_CDEF);
        assert_eq!(&aad[0..2], &(FrameType::Data as u16).to_be_bytes());
        assert_eq!(&aad[2..4], &0xABCD_u16.to_be_bytes());
        assert_eq!(&aad[4..12], &0x0123_4567_89AB_CDEF_u64.to_be_bytes());
    }

    #[tokio::test]
    async fn padded_plain_frame_wire_payload_lands_on_bucket() {
        // 50-byte real → smallest bucket fitting (50 + 2 trailer) = 128.
        // Wire payload_len = 128 exactly.
        let f = Frame::new(FrameType::Data, vec![0xAA; 50]).unwrap();
        let buckets = crate::padding::DEFAULT_BUCKETS;

        let (mut a, mut b) = tokio::io::duplex(2048);
        let (w, r) = tokio::join!(
            write_frame_maybe_padded(&mut a, &f, Some(buckets)),
            // Peek at the raw wire bytes via read_raw_frame (skip auto-depad)
            // to assert on the wire-level payload_len. We do this by reading
            // the header manually.
            async {
                let mut header = [0u8; HEADER_LEN];
                tokio::io::AsyncReadExt::read_exact(&mut b, &mut header)
                    .await
                    .unwrap();
                let payload_len = u32::from_be_bytes(header[12..16].try_into().unwrap());
                let flags = u16::from_be_bytes(header[2..4].try_into().unwrap());
                let mut body = vec![0u8; payload_len as usize];
                tokio::io::AsyncReadExt::read_exact(&mut b, &mut body)
                    .await
                    .unwrap();
                (payload_len, flags, body)
            }
        );
        w.unwrap();
        let (payload_len, flags, _body) = r;
        assert_eq!(payload_len, 128, "wire payload must equal bucket size");
        assert!(
            flags & FLAG_PADDED != 0,
            "PADDED flag must be set on the wire"
        );
    }

    #[tokio::test]
    async fn padded_plain_frame_round_trips_and_auto_depads() {
        // write_frame_maybe_padded pads + writes; read_frame auto-depads.
        // Application code sees the original real payload.
        let f = Frame::new(FrameType::Data, &b"hello"[..]).unwrap();
        let buckets = crate::padding::DEFAULT_BUCKETS;

        let (mut a, mut b) = tokio::io::duplex(2048);
        let (w, r) = tokio::join!(
            write_frame_maybe_padded(&mut a, &f, Some(buckets)),
            read_frame(&mut b)
        );
        w.unwrap();
        let got = r.unwrap();
        assert_eq!(got.payload.as_ref(), b"hello");
        assert_eq!(got.flags, 0, "depad must clear the PADDED flag");
    }

    #[tokio::test]
    async fn padded_aead_frame_wire_lands_on_bucket_after_tag() {
        // With AEAD adding 16-byte tag, plaintext is padded to (bucket - 16)
        // so wire `payload_len` lands exactly on `bucket`.
        use crate::aead::{DIR_C2S, InnerAead};
        let session = InnerAead::derive_key(
            b"exp-32bytes-of-test-material-aa",
            b"nonce-32-bytes-of-test-input-bb",
        )
        .unwrap();
        let stream_key = InnerAead::derive_stream_key(&session, 7);
        let mut send = InnerAead::for_direction(&stream_key, DIR_C2S);

        let buckets = crate::padding::DEFAULT_BUCKETS;
        let mut f = Frame::new(FrameType::Data, &b"hello-aead-padded"[..]).unwrap();
        f.stream_id = 7;

        let (mut a, mut b) = tokio::io::duplex(2048);
        let (w, r) = tokio::join!(
            write_frame_aead_maybe_padded(&mut a, &f, &mut send, Some(buckets)),
            async {
                let mut header = [0u8; HEADER_LEN];
                tokio::io::AsyncReadExt::read_exact(&mut b, &mut header)
                    .await
                    .unwrap();
                let payload_len = u32::from_be_bytes(header[12..16].try_into().unwrap());
                let mut body = vec![0u8; payload_len as usize];
                tokio::io::AsyncReadExt::read_exact(&mut b, &mut body)
                    .await
                    .unwrap();
                payload_len
            }
        );
        w.unwrap();
        let payload_len = r;
        // 17-byte real + 2 trailer = 19 inner; smallest inner-bucket >= 19
        // from { 112, 240, 496, 1008, 1484 } is 112. So wire = 128.
        assert_eq!(payload_len, 128, "wire bucket alignment");
    }

    #[tokio::test]
    async fn padded_aead_frame_round_trips_with_auto_depad() {
        use crate::aead::{DIR_C2S, InnerAead};
        let session = InnerAead::derive_key(
            b"exp-32bytes-of-test-material-aa",
            b"nonce-32-bytes-of-test-input-bb",
        )
        .unwrap();
        let stream_key = InnerAead::derive_stream_key(&session, 9);
        let mut send = InnerAead::for_direction(&stream_key, DIR_C2S);
        let mut recv = InnerAead::for_direction(&stream_key, DIR_C2S);

        let buckets = crate::padding::DEFAULT_BUCKETS;
        let mut f = Frame::new(FrameType::Data, &b"roundtrip"[..]).unwrap();
        f.stream_id = 9;

        let (mut a, mut b) = tokio::io::duplex(2048);
        let (w, r) = tokio::join!(
            write_frame_aead_maybe_padded(&mut a, &f, &mut send, Some(buckets)),
            read_frame_aead(&mut b, &mut recv)
        );
        w.unwrap();
        let got = r.unwrap();
        assert_eq!(got.payload.as_ref(), b"roundtrip");
        assert_eq!(got.flags, 0, "PADDED flag must be cleared after depad");
        assert_eq!(got.stream_id, 9);
    }

    #[tokio::test]
    async fn maybe_padded_with_none_matches_plain_write() {
        // wire_buckets=None must produce byte-identical wire output to
        // plain write_frame — proves v0.4 compatibility.
        let f = Frame::new(FrameType::Data, &b"unpadded"[..]).unwrap();

        let (mut a1, mut b1) = tokio::io::duplex(256);
        let (mut a2, mut b2) = tokio::io::duplex(256);
        let (w1, w2) = tokio::join!(
            write_frame_maybe_padded(&mut a1, &f, None),
            write_frame(&mut a2, &f)
        );
        w1.unwrap();
        w2.unwrap();

        let mut buf1 = vec![0u8; HEADER_LEN + f.payload.len()];
        let mut buf2 = vec![0u8; HEADER_LEN + f.payload.len()];
        tokio::io::AsyncReadExt::read_exact(&mut b1, &mut buf1)
            .await
            .unwrap();
        tokio::io::AsyncReadExt::read_exact(&mut b2, &mut buf2)
            .await
            .unwrap();
        assert_eq!(buf1, buf2, "None bucket must match plain write");
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
