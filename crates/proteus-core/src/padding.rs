//! Bucket-padding for PROTEUS frames (v0.5 M1.5).
//!
//! Reduces the per-frame wire-size fingerprint by rounding every
//! emitted frame's payload up to one of a small set of fixed bucket
//! sizes. Receivers strip the padding transparently before the
//! payload reaches application code.
//!
//! Design lives in [`docs/PROTEUS-v0.5-plan.md`](../../../docs/PROTEUS-v0.5-plan.md)
//! §4. Summary:
//!
//! * Bucket set is configurable; default is `[128, 256, 512, 1024, 1500]`.
//! * A new flag bit ([`crate::frame::FLAG_PADDED`]) signals the
//!   trailer convention: the last 2 bytes of `payload` are
//!   `padding_len: u16` big-endian — bytes of zero padding NOT
//!   counting the 2-byte trailer itself.
//! * Real payload = `payload[.. payload_len - 2 - padding_len]`.
//! * Padding bytes are zeroed for determinism; they live inside the
//!   AEAD-sealed block for proxy-stream frames (M5.4.1) so an
//!   on-wire observer sees only the bucket size.
//!
//! The minimum padding overhead is the 2-byte trailer; a frame whose
//! real payload exactly equals (bucket − 2) gets a 2-byte overhead
//! and zero padding bytes. The maximum is (bucket − 2) bytes of
//! padding for a near-empty real payload that fits in the smallest
//! bucket.

use anyhow::{Result, bail};
use bytes::{BufMut, Bytes, BytesMut};

use crate::frame::{FLAG_PADDED, Frame};

/// Default bucket set in bytes. Five sizes covers the practical
/// distribution well — small enough for a single AUTH_REQUEST (128),
/// large enough for a near-MTU DATA frame (1500).
pub const DEFAULT_BUCKETS: &[usize] = &[128, 256, 512, 1024, 1500];

/// Overhead in bytes contributed by the padded-trailer convention,
/// on top of any zero-padding bytes themselves. Two bytes for
/// `padding_len: u16`.
pub const PAD_TRAILER_LEN: usize = 2;

/// Pick the smallest bucket large enough to hold a real payload of
/// `real_len` bytes plus the [`PAD_TRAILER_LEN`]-byte trailer.
///
/// Returns `None` if `real_len + PAD_TRAILER_LEN` exceeds the largest
/// bucket — the caller must either split the payload (the M5.4.1
/// TCP bridge does this naturally for large DATA frames) or fall
/// back to an un-padded encode.
///
/// `buckets` must be non-empty. If it isn't sorted ascending, the
/// function still works but returns the *first* bucket large enough
/// in iteration order; callers passing custom bucket sets should
/// sort them themselves.
pub fn pick_bucket(real_len: usize, buckets: &[usize]) -> Option<usize> {
    let need = real_len.checked_add(PAD_TRAILER_LEN)?;
    buckets.iter().copied().find(|&b| b >= need)
}

/// Pad `real` to exactly `target_bucket` bytes by appending zeros
/// followed by the 2-byte `padding_len` trailer. Returns the padded
/// buffer ready to be stored as a [`Frame`]'s payload.
///
/// Errors if `real.len() + PAD_TRAILER_LEN > target_bucket` (would
/// overflow the bucket) or if `target_bucket > MAX_PAYLOAD_LEN`.
pub fn pad_payload(real: &[u8], target_bucket: usize) -> Result<Bytes> {
    if target_bucket > crate::frame::MAX_PAYLOAD_LEN {
        bail!(
            "padding bucket {} exceeds MAX_PAYLOAD_LEN {}",
            target_bucket,
            crate::frame::MAX_PAYLOAD_LEN
        );
    }
    let real_len = real.len();
    let need = real_len
        .checked_add(PAD_TRAILER_LEN)
        .ok_or_else(|| anyhow::anyhow!("real_len overflow"))?;
    if need > target_bucket {
        bail!(
            "real payload {} + trailer {} > bucket {}",
            real_len,
            PAD_TRAILER_LEN,
            target_bucket
        );
    }
    let pad_len = target_bucket - need; // bytes of zero padding (not counting trailer)
    let mut buf = BytesMut::with_capacity(target_bucket);
    buf.extend_from_slice(real);
    buf.resize(real_len + pad_len, 0u8);
    // pad_len fits in u16 because target_bucket <= MAX_PAYLOAD_LEN < u16::MAX
    // is NOT actually true (MAX_PAYLOAD_LEN = 65535 > i16::MAX), but pad_len
    // is always < target_bucket <= 65535 = u16::MAX, so the cast is safe.
    buf.put_u16(pad_len as u16);
    debug_assert_eq!(buf.len(), target_bucket);
    Ok(buf.freeze())
}

/// Recover the real payload from a padded buffer. Reads the last
/// 2 bytes as `padding_len: u16` big-endian, then returns the slice
/// `[.. len - 2 - padding_len]`.
///
/// Errors on:
/// * payload shorter than the 2-byte trailer
/// * `padding_len` larger than the remaining bytes (corrupt /
///   adversarial input)
pub fn unpad_payload(padded: &[u8]) -> Result<&[u8]> {
    if padded.len() < PAD_TRAILER_LEN {
        bail!(
            "padded payload {} < trailer size {}",
            padded.len(),
            PAD_TRAILER_LEN
        );
    }
    let split = padded.len() - PAD_TRAILER_LEN;
    let pad_len = u16::from_be_bytes([padded[split], padded[split + 1]]) as usize;
    if pad_len > split {
        bail!(
            "padding_len {} exceeds available bytes {} (corrupt frame)",
            pad_len,
            split
        );
    }
    Ok(&padded[..split - pad_len])
}

/// Pad an entire [`Frame`] to the smallest configured bucket large
/// enough for its real payload. Returns the modified frame with the
/// [`FLAG_PADDED`] bit set and the padded payload installed.
///
/// Errors if the real payload doesn't fit in any bucket — caller
/// must split first.
///
/// Idempotency: if the frame is already padded (PADDED bit set),
/// this function does NOT re-pad. Returns the input unchanged. This
/// matters for layering: a DATA frame that was bucket-padded by
/// the bridge must not be re-padded by the AEAD-wrap layer.
pub fn pad_frame(frame: Frame, buckets: &[usize]) -> Result<Frame> {
    if frame.flags & FLAG_PADDED != 0 {
        return Ok(frame);
    }
    let bucket = pick_bucket(frame.payload.len(), buckets).ok_or_else(|| {
        anyhow::anyhow!(
            "no bucket fits payload of {} bytes (largest = {:?})",
            frame.payload.len(),
            buckets.iter().max()
        )
    })?;
    let padded = pad_payload(&frame.payload, bucket)?;
    Ok(Frame {
        frame_type: frame.frame_type,
        flags: frame.flags | FLAG_PADDED,
        stream_id: frame.stream_id,
        payload: padded,
    })
}

/// Inverse of [`pad_frame`]. If [`FLAG_PADDED`] is set, returns a
/// borrowed slice of the *real* payload; otherwise returns the
/// payload verbatim. Does NOT clear the flag — the caller may want
/// to inspect both. For typical receive paths use
/// [`take_depadded_payload`] which clears the flag and yields an
/// owned [`Bytes`].
pub fn depadded_payload(frame: &Frame) -> Result<&[u8]> {
    if frame.flags & FLAG_PADDED == 0 {
        return Ok(&frame.payload);
    }
    unpad_payload(&frame.payload)
}

/// Mutate `frame` in place: if [`FLAG_PADDED`] is set, replace
/// `payload` with the unpadded slice and clear the flag. Idempotent
/// on already-unpadded frames.
///
/// This is the function receive paths call before handing the
/// frame to application code. After this call, downstream sees
/// a v0.4-shape frame: `flags == 0`, `payload == real bytes`.
pub fn take_depadded_payload(frame: &mut Frame) -> Result<()> {
    if frame.flags & FLAG_PADDED == 0 {
        return Ok(());
    }
    let real = unpad_payload(&frame.payload)?;
    let real_owned = Bytes::copy_from_slice(real);
    frame.payload = real_owned;
    frame.flags &= !FLAG_PADDED;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameType;

    #[test]
    fn pick_bucket_picks_smallest_fit() {
        assert_eq!(pick_bucket(0, DEFAULT_BUCKETS), Some(128));
        assert_eq!(pick_bucket(50, DEFAULT_BUCKETS), Some(128));
        // 126 + 2 trailer = 128 → fits exactly in 128.
        assert_eq!(pick_bucket(126, DEFAULT_BUCKETS), Some(128));
        // 127 + 2 = 129 → bumps to next bucket.
        assert_eq!(pick_bucket(127, DEFAULT_BUCKETS), Some(256));
        assert_eq!(pick_bucket(200, DEFAULT_BUCKETS), Some(256));
        assert_eq!(pick_bucket(1000, DEFAULT_BUCKETS), Some(1024));
        assert_eq!(pick_bucket(1498, DEFAULT_BUCKETS), Some(1500));
        // 1499 + 2 = 1501 → no bucket fits.
        assert_eq!(pick_bucket(1499, DEFAULT_BUCKETS), None);
        assert_eq!(pick_bucket(10_000, DEFAULT_BUCKETS), None);
    }

    #[test]
    fn pick_bucket_handles_custom_set() {
        let custom = &[64, 192, 600];
        assert_eq!(pick_bucket(0, custom), Some(64));
        assert_eq!(pick_bucket(62, custom), Some(64)); // exact fit
        assert_eq!(pick_bucket(63, custom), Some(192));
        assert_eq!(pick_bucket(598, custom), Some(600)); // exact fit
        assert_eq!(pick_bucket(599, custom), None);
    }

    #[test]
    fn pad_then_unpad_roundtrip_various_sizes() {
        for &real_len in &[0usize, 1, 17, 50, 126, 200, 1022] {
            let real = vec![0x42u8; real_len];
            let bucket = pick_bucket(real_len, DEFAULT_BUCKETS).unwrap();
            let padded = pad_payload(&real, bucket).unwrap();
            assert_eq!(padded.len(), bucket, "real_len={real_len}");
            let recovered = unpad_payload(&padded).unwrap();
            assert_eq!(recovered, real.as_slice(), "real_len={real_len}");
        }
    }

    #[test]
    fn pad_payload_exact_fit_has_zero_padding_bytes() {
        // real_len = bucket - 2 → no zero bytes, just trailer
        let real = vec![0x99u8; 126];
        let padded = pad_payload(&real, 128).unwrap();
        assert_eq!(padded.len(), 128);
        // Last 2 bytes = padding_len = 0.
        assert_eq!(&padded[126..128], &[0, 0]);
        // First 126 bytes are the real payload verbatim.
        assert_eq!(&padded[..126], real.as_slice());
        let recovered = unpad_payload(&padded).unwrap();
        assert_eq!(recovered, real.as_slice());
    }

    #[test]
    fn pad_payload_empty_real_has_full_padding() {
        let padded = pad_payload(&[], 128).unwrap();
        assert_eq!(padded.len(), 128);
        // padding_len = 128 - 2 = 126; encoded big-endian.
        assert_eq!(&padded[126..128], &[0x00, 0x7E]);
        // Bytes 0..126 are all zero (padding).
        assert!(padded[..126].iter().all(|&b| b == 0));
        let recovered = unpad_payload(&padded).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn pad_payload_rejects_too_big_for_bucket() {
        let real = vec![0u8; 127];
        let err = pad_payload(&real, 128).unwrap_err();
        assert!(err.to_string().contains("bucket"), "got: {err}");
    }

    #[test]
    fn pad_payload_rejects_bucket_above_max_payload() {
        let too_big = crate::frame::MAX_PAYLOAD_LEN + 1;
        let err = pad_payload(&[], too_big).unwrap_err();
        assert!(err.to_string().contains("MAX_PAYLOAD_LEN"), "got: {err}");
    }

    #[test]
    fn unpad_payload_rejects_short_input() {
        assert!(unpad_payload(&[]).is_err());
        assert!(unpad_payload(&[0]).is_err());
    }

    #[test]
    fn unpad_payload_rejects_corrupt_padding_len() {
        // Total length 10; pad_len encoded as 100 (way bigger than possible).
        let mut bad = vec![0u8; 8];
        bad.extend_from_slice(&[0, 100]); // trailer = 100
        let err = unpad_payload(&bad).unwrap_err();
        assert!(err.to_string().contains("padding_len"), "got: {err}");
    }

    #[test]
    fn pad_frame_sets_flag_and_round_trips() {
        let f = Frame::new(FrameType::Data, &b"hello"[..]).unwrap();
        let padded = pad_frame(f.clone(), DEFAULT_BUCKETS).unwrap();
        assert_eq!(padded.flags & FLAG_PADDED, FLAG_PADDED);
        assert_eq!(padded.payload.len(), 128);
        assert_eq!(padded.frame_type, f.frame_type);
        assert_eq!(padded.stream_id, f.stream_id);

        let real = depadded_payload(&padded).unwrap();
        assert_eq!(real, b"hello");

        let mut taken = padded.clone();
        take_depadded_payload(&mut taken).unwrap();
        assert_eq!(taken.flags & FLAG_PADDED, 0);
        assert_eq!(taken.payload.as_ref(), b"hello");
    }

    #[test]
    fn pad_frame_is_idempotent_on_already_padded() {
        let f = Frame::new(FrameType::Data, &b"hi"[..]).unwrap();
        let once = pad_frame(f, DEFAULT_BUCKETS).unwrap();
        let bucket_after_once = once.payload.len();
        let twice = pad_frame(once.clone(), DEFAULT_BUCKETS).unwrap();
        assert_eq!(twice.flags, once.flags);
        assert_eq!(twice.payload.len(), bucket_after_once);
        assert_eq!(twice.payload.as_ref(), once.payload.as_ref());
    }

    #[test]
    fn depadded_payload_passthrough_when_flag_clear() {
        let f = Frame::new(FrameType::Data, &b"raw"[..]).unwrap();
        assert_eq!(f.flags, 0);
        let real = depadded_payload(&f).unwrap();
        assert_eq!(real, b"raw");
    }

    #[test]
    fn take_depadded_payload_no_op_when_flag_clear() {
        let mut f = Frame::new(FrameType::Data, &b"raw"[..]).unwrap();
        take_depadded_payload(&mut f).unwrap();
        assert_eq!(f.flags, 0);
        assert_eq!(f.payload.as_ref(), b"raw");
    }

    #[test]
    fn pad_frame_errors_when_no_bucket_fits() {
        let big = vec![0u8; 1499];
        let f = Frame::new(FrameType::Data, big).unwrap();
        let err = pad_frame(f, DEFAULT_BUCKETS).unwrap_err();
        assert!(err.to_string().contains("no bucket fits"), "got: {err}");
    }

    /// Every bucket size in the default set must round-trip with
    /// a real payload that exactly fits — this catches off-by-ones
    /// in the trailer math at every level.
    #[test]
    fn every_default_bucket_round_trips_at_exact_fit() {
        for &bucket in DEFAULT_BUCKETS {
            let real = vec![0xAAu8; bucket - PAD_TRAILER_LEN];
            let padded = pad_payload(&real, bucket).unwrap();
            assert_eq!(padded.len(), bucket);
            let got = unpad_payload(&padded).unwrap();
            assert_eq!(got, real.as_slice(), "bucket={bucket}");
        }
    }
}
