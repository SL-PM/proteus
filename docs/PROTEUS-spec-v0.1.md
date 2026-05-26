# PROTEUS Protocol Specification

**Version:** 0.1 (Draft)
**Status:** Design Sketch — NOT for production use
**Date:** May 2026
**Working Name:** PROTEUS (PRivacy-Oriented Tunneling with Encrypted Universal Streams)

> ⚠️ **Disclaimer:** This document is a design exercise. Before any real-world
> deployment, the protocol requires formal cryptographic review (e.g., Tamarin
> or ProVerif analysis), an audited reference implementation, and extensive
> testing against active censorship infrastructure. Many design choices below
> are deliberate placeholders for discussion and may have non-obvious flaws.

---

## 1. Introduction

PROTEUS is a proposed VPN / circumvention protocol that combines:

- **REALITY's** indistinguishability principle (no detectable TLS fingerprint, no own certificate)
- **Hysteria2's** QUIC-based transport with modern congestion control
- **WireGuard's** clean Noise-based handshake
- **Post-quantum** key agreement from day one (hybrid X25519 + ML-KEM-768)

The design goal: at the network observation point, PROTEUS traffic must be
**indistinguishable from real HTTP/3 traffic** to a popular website — both
in handshake bytes and in long-term statistical properties.

## 2. Threat Model

### In-scope adversaries

- **Network-level DPI** with TLS / QUIC fingerprinting capability
- **Active probing**: adversary that connects to suspected endpoints to verify them
- **Statistical traffic analysis** at a single observation point (entropy, packet size distribution, timing)
- **IP-level blocking** of known endpoints (mitigated via port hopping and SNI rotation)
- **Stored ciphertext + future quantum decryption** ("harvest now, decrypt later")

### Out-of-scope

- **Global passive adversary** with correlation across all internet links
- **Endpoint compromise** (malicious server, malware on client)
- **Side-channel attacks** on client/server hardware
- **Active correlation** when adversary controls both endpoints
- **Legal / coercive** attacks on the operator

## 3. Design Goals

| Goal | Mechanism |
|------|-----------|
| Indistinguishability from HTTP/3 | REALITY-style handshake borrowing |
| Post-quantum security | Hybrid X25519 + ML-KEM-768 |
| Forward secrecy | Ephemeral keys per session, periodic rekey |
| Active-probe resistance | Server returns real upstream content to non-clients |
| Performance over lossy networks | QUIC + BBR-style congestion control |
| Low handshake latency | 0-RTT for resumed sessions |
| Native multiplexing | QUIC streams |
| Censorship adaptivity | Automatic port hopping on RST / latency anomalies |
| Transport flexibility | UDP/QUIC primary, TCP/TLS fallback |

## 4. Cryptographic Primitives

| Function | Algorithm | Rationale |
|----------|-----------|-----------|
| KEM (hybrid) | X25519 ⊕ ML-KEM-768 | PQ + classical for defense-in-depth |
| AEAD (default) | ChaCha20-Poly1305 | Software-fast, no AES-NI dependency |
| AEAD (optional) | AES-256-GCM | Hardware-accelerated on modern servers |
| Hash | SHA-256 | Conservative, NIST-approved |
| KDF | HKDF-SHA256 | Standard, widely-reviewed |
| Client auth | Ed25519 signatures or PSK | Operator choice |
| RNG | OS CSPRNG | `getrandom(2)`, `BCryptGenRandom` |

**Hybrid KEM notation:** `K = X25519(...) || ML-KEM-768(...)`. Both shared
secrets are concatenated and fed into HKDF. If either component is broken
(now or by a future quantum computer), the session remains secure as long
as the other holds.

## 5. Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│  Application Traffic (TCP / UDP / raw IP)                    │
├──────────────────────────────────────────────────────────────┤
│  PROTEUS Inner Layer                                         │
│  - Stream multiplexing (via QUIC streams)                    │
│  - Per-stream addressing (host:port metadata)                │
│  - Inner AEAD with session key                               │
├──────────────────────────────────────────────────────────────┤
│  QUIC (RFC 9000) with borrowed TLS context                   │
│  - Connection migration                                      │
│  - Loss recovery, BBR congestion control                     │
├──────────────────────────────────────────────────────────────┤
│  UDP                                                         │
└──────────────────────────────────────────────────────────────┘
```

**Roles:**

- **Client:** Initiates connection, knows server's static public key and SNI target list
- **Server:** Listens on UDP/TCP, forwards non-PROTEUS traffic transparently to a real upstream (the **masquerade target**) to defeat active probing

## 6. Wire Format

### 6.1 Initial Packet

The client sends a QUIC Initial packet that is byte-indistinguishable from
a real Chrome / Safari / Firefox handshake to the chosen SNI target.

Inside the ClientHello, a covert payload embeds:

| Field | Size | Purpose |
|-------|------|---------|
| Auth Tag | 16 B | HMAC-SHA256(static_secret, ClientHello\AuthTag), truncated |
| Session Nonce | 8 B | Random, for replay protection |
| KEM share (X25519) | 32 B | Classical ephemeral |
| KEM share (ML-KEM-768) | 1184 B | Post-quantum ephemeral |

These are placed in extension fields that real browsers already use
(`key_share` for X25519, post-quantum hybrid groups for ML-KEM are now
standard in Chrome as of 2026, making this plausible).

### 6.2 Server Response

- **Auth Tag valid** → server completes its own QUIC Initial with KEM response and proceeds with PROTEUS session establishment.
- **Auth Tag invalid** → server transparently forwards the entire connection to the masquerade target (e.g., `www.bing.com:443`). The active prober receives a real response and cannot distinguish PROTEUS from a reverse proxy.

This is the **core REALITY-style trick**: there is no distinguishing oracle.

## 7. Handshake

PROTEUS uses a Noise pattern adapted for hybrid KEM:

```
PROTEUS_IKhfs_25519+MLKEM768_ChaChaPoly_SHA256:
  -> s
  <- s
  ...
  -> e, e1, es, ee, e1s1, s, ss
  <- e, e1, ee, e1e1, se
```

Where `e1` denotes ML-KEM-768 ephemerals alongside X25519 (`e`).

### 7.1 Handshake messages

**Message 1 (Client → Server):**
QUIC Initial with embedded auth tag + KEM shares (see §6.1)

**Message 2 (Server → Client):**
QUIC Initial response with server KEM share + AEAD-encrypted server identity

**Message 3 (Client → Server, 0-RTT capable on resumption):**
AEAD-encrypted client identity + first application data

After Message 3, both sides derive:

```
session_key = HKDF(
  salt = transcript_hash,
  ikm  = X25519_shared || MLKEM_shared,
  info = "PROTEUS-v1-session"
)
```

## 8. Session Management

### 8.1 Rekeying

Sessions rekey every:
- **1 GiB** of transferred data, OR
- **1 hour** of session lifetime,

whichever comes first. See Open Question §12.1 on PQ during rekey.

### 8.2 Connection Migration

PROTEUS inherits QUIC's connection migration: the client may switch IP/port
mid-session and the server validates via `PATH_CHALLENGE`. The session ID is
independent of the 5-tuple.

## 9. Anti-Detection

### 9.1 Padding

Each PROTEUS frame is padded to match the empirical packet size distribution
of HTTP/3 traffic to the masquerade target. Distributions are captured
offline and shipped with the client; periodic updates via separate channel.

### 9.2 Timing

Outbound packets are released with jitter drawn from a distribution matching
real browsing patterns. **Constant-rate output is a giveaway** and must be avoided.

### 9.3 SNI Rotation

The client maintains a pool of valid SNI targets and rotates between them
across sessions. Targets must:

- Support TLS 1.3 + HTTP/3
- Be high-traffic (Cloudflare, Google, Microsoft, Apple endpoints)
- Be plausible browsing destinations for the apparent client locale

### 9.4 Port Hopping

If the client observes:
- 3 consecutive RSTs within 10 s, **OR**
- Latency increase > 5× baseline,

it triggers a port migration to a pseudo-randomly selected port:

```
port = 10000 + HKDF(session_secret, "port-hop" || epoch) mod 50000
```

Server listens on the same derived port (synchronized epoch via NTP).

## 10. Multiplexing

PROTEUS uses QUIC streams natively. Each logical proxy connection is a
bidirectional QUIC stream. Stream metadata (target host:port) is sent as
the first frame in CBOR encoding:

```json
{
  "v": 1,
  "cmd": "tcp",
  "host": "example.com",
  "port": 443
}
```

UDP is supported via dedicated streams with a length-prefixed datagram format.

## 11. Server State Machine

```
       ┌─────────┐
       │ LISTEN  │
       └────┬────┘
            │ UDP packet received
            ▼
       ┌─────────────────┐
       │ VERIFY_AUTH_TAG │
       └─────┬──────┬────┘
       valid │      │ invalid
             ▼      ▼
       ┌─────────┐ ┌──────────────────────┐
       │ ACCEPT  │ │ FORWARD_TO_MASQ      │
       └────┬────┘ │ (transparent proxy)  │
            │      └──────────────────────┘
            ▼
       ┌───────────┐
       │ HANDSHAKE │
       └────┬──────┘
            │
            ▼
       ┌──────────┐   rekey trigger
       │ ACTIVE   │◀───────────────────┐
       └────┬─────┘                    │
            │                          │
            ▼                          │
       ┌──────────┐                    │
       │ REKEY    │────────────────────┘
       └──────────┘
```

## 12. Open Questions

1. **PQ during rekey:** Is the cost of ML-KEM-768 per rekey acceptable, or should rekeys use classical-only ephemeral exchange?
2. **Borrowed SNI legality:** Using another site's TLS context for masquerading may have legal implications depending on jurisdiction.
3. **Replay protection for 0-RTT:** Standard QUIC 0-RTT replay risks apply; PROTEUS adds a session nonce, but applications must still be replay-safe.
4. **Masquerade target selection:** How does the operator pick a target that's high-traffic AND won't notice unusual connection patterns AND won't change behavior in ways that break the cover?
5. **Padding distribution updates:** How to distribute updated empirical distributions without leaking the protocol version through the update channel?
6. **Implementation language:** Rust (memory safety, `quinn` is mature) vs. Go (ecosystem, `quic-go`). Recommendation: **Rust + `quinn`**.
7. **Client identity:** PSK is simpler but rotates poorly; Ed25519 keys are clean but require key distribution. Hybrid?
8. **What does an obvious failure look like?** If the protocol *is* detected, how does the client gracefully fall back, and to what?

## 13. Next Steps

1. Tighten threat model with concrete adversary capability assumptions
2. Formal verification of the handshake (Tamarin / ProVerif)
3. Reference implementation skeleton in Rust
4. Wire format fuzzer + test vectors
5. Empirical test against simulated DPI (e.g., GFWatch-style tooling)
6. External cryptographic review before any real deployment

---

## Appendix A: Naming

"PROTEUS" is a working name. Proteus in Greek mythology is the shape-shifting
sea god — fitting for a protocol whose entire purpose is to look like
something it isn't. Alternative names welcomed.

## Appendix B: Comparison Matrix

| Feature | WireGuard | VLESS+REALITY | Hysteria2 | PROTEUS |
|---------|-----------|---------------|-----------|---------|
| Transport | UDP | TCP/UDP | UDP (QUIC) | UDP (QUIC) + TCP fallback |
| Crypto | Noise_IK | TLS 1.3 | TLS 1.3 | Noise + hybrid KEM |
| Post-quantum | No | No | No | **Yes** (X25519+ML-KEM) |
| DPI resistance | Low | High (REALITY) | Medium (obfs) | **High** (REALITY-style on QUIC) |
| Active probe resistance | Low | **High** | Medium | **High** |
| 0-RTT | No | No | Yes | Yes |
| Connection migration | No (handover) | No | Yes | Yes |
| Native mux | No | Yes (XUDP) | Yes | Yes |

---

**License:** CC-BY-SA 4.0 — published for review and discussion.
**Not for production deployment without independent cryptographic review.**
