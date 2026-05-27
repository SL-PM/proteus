# M19 Spike — Post-Quantum Feasibility (Documentation)

**Date:** 2026-05-27
**Roadmap:** [`ROADMAP-v0.3.md`](ROADMAP-v0.3.md) §M19
**Status:** Forward-looking note. No code lands in v0.3.

## Background

Spec v0.1 §4 proposes hybrid X25519 + ML-KEM-768 as the v1.0 KEM. Spec
v0.2 §3 explicitly defers PQ from v0.3, citing the maturity of ML-KEM
support in Quinn 0.11 + rustls 0.23. This document captures the
May-2026 feasibility picture so v1.0 work can start from a clear
baseline.

## Required pieces

For PROTEUS to negotiate a hybrid PQ key exchange end-to-end, all of:

- The Quinn QUIC layer must accept the named group on the client and
  offer / accept it on the server.
- rustls (the underlying TLS 1.3 stack) must support the ML-KEM hybrid
  group as a key-agreement option.
- The active crypto provider must implement ML-KEM-768 key encapsulation.

## Status of the stack (May 2026)

| Component | ML-KEM-768 support | Notes |
|---|---|---|
| `ring` crypto provider | ✗ | Maintained subset of BoringSSL primitives. No PQ groups as of 0.17.x. PROTEUS currently uses ring (see `proteus_core::tls::install_crypto_provider`). |
| `aws-lc-rs` crypto provider | ✓ (experimental) | Wraps AWS-LC, which gained ML-KEM-768 in 2024. Exposes the `X25519MLKEM768` hybrid group through rustls when the `prefer-post-quantum` (or equivalent) builder switch is set. |
| `rustls` 0.23.x | partial | Provider-driven. With aws-lc-rs and the post-quantum flag, the hybrid group can be advertised. Defaults are still classical-only across all 0.23 patch versions. |
| Quinn 0.11.x | transparent | The QUIC layer is agnostic to which TLS named group was negotiated. The M5 exporter API (`Connection::export_keying_material`) does not care either — the exporter is derived from the agreed master secret regardless of how that secret was reached. |
| h3 / h3-quinn 0.0.x | transparent | H3 sits above QUIC and TLS. No PQ-specific code path. |

## Migration plan sketch (for v1.0)

1. Swap `rustls::crypto::ring::default_provider()` for
   `rustls::crypto::aws_lc_rs::default_provider()` in
   `proteus_core::tls::install_crypto_provider`.
   - Cargo: switch `rustls` features from `["ring"]` (current default)
     to `["aws_lc_rs"]`.
   - Verify `aws-lc-sys` builds on the target platforms (it needs
     a C compiler and cmake; we already have these via rcgen).
2. Configure the rustls server and client builders to advertise the
   `X25519MLKEM768` hybrid group with classical fallback. The exact
   builder API varies by rustls minor version — check at the time of
   writing.
3. Add `PolicyConfig::require_post_quantum: bool` so an operator can
   refuse classical-only handshakes (server-side enforcement, mirrors
   how we already gate `allow_udp` in M12).
4. Update `PROTEUS-spec-v0.2.md` §6 (Cryptographic Primitives) to mark
   hybrid KEM as the default outer key agreement. The Ed25519
   client-auth path stays classical because exporter-binding is robust
   to whatever ECDHE/KEM produced the master secret.
5. Re-run the M5 exporter spike (or equivalent) against the new stack
   to confirm both sides still derive identical bytes when the
   negotiated group is hybrid.

## Risks / open questions

- **ML-KEM-768 key share size (1184 B).** The QUIC Initial packet
  carrying it is materially larger than a classical X25519-only
  ClientHello (~32 B share). This makes the v0.3 baseline and v1.0 PQ
  ClientHello visibly different in size — relevant for the v0.5
  fingerprinting work. Plan: capture both baselines during v0.4
  cover-host testing so the v0.5 padding profile targets the right
  shape from the start.
- **`prefer-post-quantum` interop.** Real-world TLS servers behave
  differently when a client advertises hybrid groups: some accept and
  pick classical; some accept and pick hybrid; a small minority close
  the handshake. v0.4 cover-host validation should include a sweep of
  the major CDN endpoints (Cloudflare, Fastly, Akamai, Google,
  Microsoft) to confirm none of them treat hybrid advertisement as
  unusual enough to break the cover.
- **Performance.** ML-KEM-768 encap/decap is fast on modern CPUs
  (well under 100 µs each) but still 10×+ classical X25519. For v0.3's
  one-handshake-per-session pattern this is negligible. The v0.4 work
  on rekey will be more sensitive; spec v0.1 §8.1 already flags this
  as an open question.
- **WASM / embedded targets.** Out-of-scope for v0.3 and v1.0, but
  worth recording: aws-lc-rs does not build for WASM today. If a
  future browser-extension client is desired, an alternative provider
  (rustcrypto pq-crystals?) would be needed.

## Decision

**Defer to v1.0 as previously planned.** The v0.3 prototype crypto
path is unchanged. This document exists so v1.0 work can begin with a
clear inventory of what's done in the ecosystem, what's left to wire
up in PROTEUS, and where the integration risks live.

The earliest sensible time to attempt enabling the hybrid group in
PROTEUS itself is **after v0.4 lands** (when REALITY-style upstream
forwarding is in place and we can field-test against real CDN cover
hosts) and **before v0.5 fingerprint matching** (so the padding
profiles are computed against the v1.0 wire shape, not the v0.3 one).
