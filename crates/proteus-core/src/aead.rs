//! Inner AEAD layer for PROTEUS v0.4 frames (M5.4).
//!
//! Defense-in-depth: after PROTEUS auth succeeds, frame payloads are
//! wrapped in a second AEAD layer (ChaCha20-Poly1305) on top of the
//! outer QUIC TLS encryption. Threat-model intent: if the outer
//! transport keys are ever recovered (out-of-band crypto break,
//! future cryptanalysis), the inner layer still protects payload
//! confidentiality and integrity. The exporter material the inner
//! layer derives from is itself bound to the TLS session, so the
//! two layers fail independently.
//!
//! ## Key derivation
//!
//! ```text
//! inner_key = HKDF-SHA256(salt = exporter,
//!                         ikm  = session_nonce,
//!                         info = "PROTEUS-v0.4-inner-aead")
//! ```
//!
//! Both peers MUST call [`InnerAead::derive_key`] with the same
//! exporter bytes and the same `session_nonce` (the nonce the client
//! sent in its AUTH_REQUEST). They then end up with identical key
//! material.
//!
//! ## Nonce construction
//!
//! 12 bytes total:
//!
//! ```text
//!   [8-byte counter, big-endian] [4-byte direction tag, big-endian]
//! ```
//!
//! Direction tag distinguishes the two flow halves so they cannot
//! share a nonce:
//!
//! | Constant   | Value      | Used by                               |
//! |------------|------------|---------------------------------------|
//! | `DIR_C2S`  | 0x00000000 | client→server frames (client sends,   |
//! |            |            | server receives)                      |
//! | `DIR_S2C`  | 0x00000001 | server→client frames                  |
//!
//! Counter starts at 0 immediately after auth and increments by 1 on
//! every successful seal or open. Each (direction, counter) pair is
//! used exactly once per PROTEUS session — losing or replaying frames
//! is detected as an AEAD failure.
//!
//! ## Wire integration
//!
//! M5.4 only ships the primitive. The actual wire-format change
//! (wrapping `DATA` / proxy frames in AEAD) lands in M5.4.1 once the
//! v0.4 server/client both know how to coordinate the per-stream
//! state. Until then this module is callable from tests and future
//! integration code without changing any on-the-wire bytes.

use anyhow::{Result, bail};
use bytes::Bytes;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;

/// Length of the inner-AEAD key in bytes.
pub const KEY_LEN: usize = 32;

/// Length of the per-frame nonce in bytes (8-byte counter + 4-byte direction).
pub const NONCE_LEN: usize = 12;

/// Length of the ChaCha20-Poly1305 tag appended to each sealed frame.
pub const TAG_LEN: usize = 16;

/// Direction tag for client→server frames.
pub const DIR_C2S: u32 = 0x0000_0000;

/// Direction tag for server→client frames.
pub const DIR_S2C: u32 = 0x0000_0001;

/// HKDF `info` parameter — domain separation from any future inner-
/// layer key derivation in later PROTEUS versions.
const HKDF_INFO: &[u8] = b"PROTEUS-v0.4-inner-aead";

/// Per-direction AEAD state. Each peer holds two of these (one for
/// sending, one for receiving). The key bytes are shared between both
/// halves; the direction tag in the nonce keeps the streams
/// cryptographically distinct.
pub struct InnerAead {
    cipher: ChaCha20Poly1305,
    counter: u64,
    direction: u32,
}

impl InnerAead {
    /// Derive the inner-AEAD key from RFC 5705 TLS exporter material
    /// and the AUTH_REQUEST session nonce. Both inputs must be
    /// non-empty; HKDF accepts any length above zero, but for v0.4
    /// the typical sizes are 32 bytes each.
    pub fn derive_key(exporter: &[u8], session_nonce: &[u8]) -> Result<[u8; KEY_LEN]> {
        if exporter.is_empty() || session_nonce.is_empty() {
            bail!("derive_key: exporter and session_nonce must both be non-empty");
        }
        let mut okm = [0u8; KEY_LEN];
        let hk = Hkdf::<Sha256>::new(Some(exporter), session_nonce);
        hk.expand(HKDF_INFO, &mut okm)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        Ok(okm)
    }

    /// Build an `InnerAead` for the given direction. Counter starts at 0.
    pub fn for_direction(key: &[u8; KEY_LEN], direction: u32) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        Self {
            cipher,
            counter: 0,
            direction,
        }
    }

    /// Current counter value. Increments after every successful
    /// `seal` or `open`. Exposed for testing / replay diagnostics.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Seal one frame's payload. `aad` is associated data that the
    /// caller binds to the frame (typically the 16-byte PROTEUS
    /// frame header — type, flags, stream_id, payload_len). The
    /// counter is advanced on success.
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Bytes> {
        let nonce = self.next_nonce()?;
        let ct = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| anyhow::anyhow!("AEAD seal: {e:?}"))?;
        Ok(Bytes::from(ct))
    }

    /// Open one frame's ciphertext+tag. `aad` must exactly match
    /// what the sender provided. The counter is advanced on success.
    /// A mismatched counter (e.g. dropped or replayed frame) causes
    /// the AEAD to fail; the caller treats that as a fatal session
    /// error.
    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Bytes> {
        let nonce = self.next_nonce()?;
        let pt = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|e| anyhow::anyhow!("AEAD open: {e:?}"))?;
        Ok(Bytes::from(pt))
    }

    fn next_nonce(&mut self) -> Result<[u8; NONCE_LEN]> {
        let mut n = [0u8; NONCE_LEN];
        n[0..8].copy_from_slice(&self.counter.to_be_bytes());
        n[8..12].copy_from_slice(&self.direction.to_be_bytes());
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("AEAD counter overflow"))?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPORTER: &[u8; 32] = b"0123456789ABCDEF0123456789ABCDEF";
    const SESSION_NONCE: &[u8; 32] = b"FEDCBA9876543210FEDCBA9876543210";

    /// Helper: sender + receiver pair on the same direction (c2s),
    /// suitable for roundtrip tests.
    fn matched_pair() -> (InnerAead, InnerAead) {
        let key = InnerAead::derive_key(EXPORTER, SESSION_NONCE).unwrap();
        (
            InnerAead::for_direction(&key, DIR_C2S),
            InnerAead::for_direction(&key, DIR_C2S),
        )
    }

    #[test]
    fn key_derivation_is_deterministic() {
        let k1 = InnerAead::derive_key(EXPORTER, SESSION_NONCE).unwrap();
        let k2 = InnerAead::derive_key(EXPORTER, SESSION_NONCE).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), KEY_LEN);
    }

    #[test]
    fn key_derivation_varies_with_inputs() {
        let k1 = InnerAead::derive_key(EXPORTER, SESSION_NONCE).unwrap();
        let other_nonce: &[u8; 32] = b"DIFFERENT-NONCEDIFFERENT-NONCEDF";
        let k2 = InnerAead::derive_key(EXPORTER, other_nonce).unwrap();
        assert_ne!(k1, k2);
        let other_exp: &[u8; 32] = b"DIFFERENT-EXPORTERDIFFERENT-EXPO";
        let k3 = InnerAead::derive_key(other_exp, SESSION_NONCE).unwrap();
        assert_ne!(k1, k3);
    }

    #[test]
    fn derive_key_rejects_empty_inputs() {
        assert!(InnerAead::derive_key(b"", SESSION_NONCE).is_err());
        assert!(InnerAead::derive_key(EXPORTER, b"").is_err());
    }

    #[test]
    fn seal_open_roundtrip() {
        let (mut s, mut r) = matched_pair();
        let pt = b"hello, PROTEUS frame payload";
        let aad = b"frame-header-bytes";
        let ct = s.seal(pt, aad).unwrap();
        assert_eq!(ct.len(), pt.len() + TAG_LEN);
        let got = r.open(&ct, aad).unwrap();
        assert_eq!(got.as_ref(), pt);
        assert_eq!(s.counter(), 1);
        assert_eq!(r.counter(), 1);
    }

    #[test]
    fn counter_increments_per_frame() {
        let (mut s, _) = matched_pair();
        for i in 0..5 {
            s.seal(b"x", b"").unwrap();
            assert_eq!(s.counter(), (i + 1) as u64);
        }
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut s, mut r) = matched_pair();
        let ct = s.seal(b"secret", b"hdr").unwrap();
        let mut bad = ct.to_vec();
        bad[0] ^= 0x40;
        assert!(r.open(&bad, b"hdr").is_err());
    }

    #[test]
    fn tampered_aad_is_rejected() {
        let (mut s, mut r) = matched_pair();
        let ct = s.seal(b"secret", b"original-hdr").unwrap();
        assert!(r.open(&ct, b"changed-hdr").is_err());
    }

    #[test]
    fn truncated_ciphertext_is_rejected() {
        let (mut s, mut r) = matched_pair();
        let ct = s.seal(b"secret", b"hdr").unwrap();
        // Drop the auth tag.
        let truncated = &ct[..ct.len() - TAG_LEN];
        assert!(r.open(truncated, b"hdr").is_err());
    }

    #[test]
    fn different_directions_produce_different_ciphertexts() {
        let key = InnerAead::derive_key(EXPORTER, SESSION_NONCE).unwrap();
        let mut c2s = InnerAead::for_direction(&key, DIR_C2S);
        let mut s2c = InnerAead::for_direction(&key, DIR_S2C);
        let ct1 = c2s.seal(b"identical-msg", b"identical-aad").unwrap();
        let ct2 = s2c.seal(b"identical-msg", b"identical-aad").unwrap();
        assert_ne!(ct1, ct2, "direction tag must differentiate ciphertexts");
    }

    #[test]
    fn cross_direction_open_fails() {
        let key = InnerAead::derive_key(EXPORTER, SESSION_NONCE).unwrap();
        let mut c2s = InnerAead::for_direction(&key, DIR_C2S);
        let mut s2c = InnerAead::for_direction(&key, DIR_S2C);
        let ct = c2s.seal(b"hi", b"").unwrap();
        // s2c uses DIR_S2C in the nonce; ct was sealed under DIR_C2S.
        assert!(s2c.open(&ct, b"").is_err());
    }

    #[test]
    fn out_of_order_open_fails() {
        // If the receiver tries to open frame N twice, the second call
        // has its counter already advanced past N, so the nonce differs.
        let (mut s, mut r) = matched_pair();
        let ct = s.seal(b"frame0", b"").unwrap();
        let _ = r.open(&ct, b"").unwrap(); // counter now 1
        assert!(
            r.open(&ct, b"").is_err(),
            "replay at advanced counter must fail"
        );
    }

    #[test]
    fn distinct_payloads_distinct_ciphertexts() {
        let (mut s, _) = matched_pair();
        let ct1 = s.seal(b"payload-a", b"").unwrap();
        let ct2 = s.seal(b"payload-b", b"").unwrap();
        assert_ne!(ct1, ct2);
    }
}
