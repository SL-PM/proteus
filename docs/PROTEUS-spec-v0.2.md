# PROTEUS Protocol Specification

**Version:** 0.2 (Transition Spec for v0.3 Prototype)
**Status:** Design — NOT for production use
**Date:** May 2026
**Companion to:** `PROTEUS-spec-v0.1.md` (long-term vision, retained as-is)

> ⚠️ **Read this first.** v0.2 narrows v0.1 down to what the v0.3 research
> prototype will actually build. It deliberately drops post-quantum crypto,
> REALITY-style upstream masquerading, port hopping, and traffic shaping —
> not because those are wrong, but because building them before the basic
> transport and auth are proven would hide the important risks. They return
> in v0.4+.

---

## 1. Purpose of This Document

v0.1 describes the **long-term vision**: a fully indistinguishable,
post-quantum, REALITY-on-QUIC protocol. That vision remains the destination.

v0.2 describes the **minimum viable v0.3 prototype** — what we build now to
prove the core ideas work in code, not just on paper.

A v0.3 implementation that matches this spec is:

- **Useful** as a research artifact and the basis for v0.4+.
- **NOT useful** as a deployed circumvention tool. It is DPI-detectable.
  See `THREAT-MODEL-v0.3.md` for what it does and does not defend against.

---

## 2. v0.3 Goals

The v0.3 prototype must demonstrate, in working code:

1. QUIC client/server connectivity with standard TLS 1.3 (no covert payload).
2. Per-client Ed25519 authentication, cryptographically bound to the TLS
   session via RFC 5705 exporter material.
3. Replay protection within a bounded time window.
4. TCP proxying through QUIC streams (CONNECT semantics).
5. A SOCKS5 frontend on the client for TCP CONNECT.
6. UDP echo proxying (minimal, via streams or QUIC DATAGRAM — pick one).
7. Server-side policy enforcement (block private ranges, disallowed ports).
8. A local HTTP/3 decoy responder for non-PROTEUS traffic to the listening
   port, so passive probers do not receive PROTEUS-specific error responses.
9. Packet-capture tooling and a baseline comparison against real Chrome H3
   traffic, even if that comparison shows obvious differences.

---

## 3. v0.3 Non-Goals (Deferred)

The following are explicitly **out-of-scope** for v0.3 and remain part of the
v0.1 long-term vision:

| Feature | Deferred to | Reason for deferral |
|---|---|---|
| Hybrid X25519 + ML-KEM-768 KEM | v1.0 | Adds large cryptographic surface area before the simpler base case is verified. ML-KEM support in Quinn/rustls still maturing. |
| REALITY-style upstream forwarding | v0.4 | Requires careful TLS-context borrowing; non-trivial to get right; local H3 decoy is the v0.3 stand-in. |
| Borrowed-SNI initial packets (covert ClientHello payload) | v0.4 or later | This is the core REALITY trick. Implementing it without a deeply-understood TLS stack is dangerous. |
| Port hopping | v0.5 | Adds operational complexity (NTP sync, server multi-listen) that obscures bugs in auth/proxy. |
| SNI rotation | v0.5 | Requires the masquerade machinery from v0.4 to be useful. |
| Empirical padding distributions | v0.5 | Requires a corpus of captures + matching machinery. v0.3 only defines a profile *format*. |
| Timing jitter | v0.5 | Same reasoning as padding. |
| Connection migration | v0.4 | Quinn supports it; PROTEUS-level session-ID handling needs design. |
| 0-RTT resumption | v0.4 | Replay-safety is an open question even at v0.1 (§12.3). |
| Inner AEAD layer (defense-in-depth on top of QUIC) | v0.4 | v0.3 treats QUIC TLS as the sole confidentiality boundary. |

A v0.3 build that quietly adds any of these is **out of scope** for v0.3
sign-off.

---

## 4. Threat Model for v0.3

See `THREAT-MODEL-v0.3.md` for the full statement. One-line summary:

> v0.3 defends against passive interception, unauthorized clients, and replay.
> v0.3 does **not** defend against DPI, active probing with cert inspection,
> traffic-analysis, IP blocking, or harvest-now-decrypt-later.

---

## 5. Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Application (curl, browser, etc.)                           │
├──────────────────────────────────────────────────────────────┤
│  PROTEUS Client                                              │
│  - SOCKS5 listener on 127.0.0.1:1080                         │
│  - Per-stream proxy: TCP CONNECT, UDP echo                   │
│  - PROTEUS frame codec                                       │
│  - Ed25519 signing bound to TLS exporter                     │
├──────────────────────────────────────────────────────────────┤
│  QUIC + TLS 1.3 (Quinn / rustls)                             │
│  - Standard handshake, no covert payload                     │
│  - Server certificate (self-signed acceptable in v0.3 lab)   │
├──────────────────────────────────────────────────────────────┤
│  UDP                                                         │
└──────────────────────────────────────────────────────────────┘
```

The server mirrors this. Non-PROTEUS QUIC traffic to the server's listening
port is handled by the local H3 decoy (§11).

---

## 6. Cryptographic Primitives (v0.3)

| Function | v0.3 Algorithm | v1.0 Vision |
|---|---|---|
| Outer transport | TLS 1.3 (whatever Quinn negotiates) | Same, plus hybrid KEM groups |
| Client auth signature | Ed25519 | Same |
| Channel binding | RFC 5705 TLS exporter | Same |
| Replay nonce hash | SHA-256 | Same |
| Inner AEAD | **None** in v0.3 | ChaCha20-Poly1305 inner layer |
| RNG | OS CSPRNG via `rand::rngs::OsRng` | Same |

v0.3 does **not** define a separate inner-AEAD layer on top of QUIC. The QUIC
TLS 1.3 layer is treated as the sole confidentiality boundary. v0.4 adds an
inner layer for defense-in-depth.

---

## 7. Wire Format

### 7.1 Outer QUIC

Standard. No covert payload in the ClientHello. ALPN is `proteus/0.3` on
client side; server accepts `proteus/0.3` for PROTEUS traffic and `h3` for
decoy traffic.

> **Note:** The distinct ALPN is a v0.3 simplification. It makes the protocol
> trivially identifiable. v0.4 will collapse the ALPN to `h3` only and
> distinguish PROTEUS by post-handshake behavior.

### 7.2 PROTEUS Frame Envelope

After the QUIC handshake completes, all PROTEUS traffic uses this frame
format on a single bidirectional control stream and on per-proxy streams:

```text
+--------+--------+----------------+--------------+----------+
| 2 B    | 2 B    | 8 B            | 4 B          | N B      |
+--------+--------+----------------+--------------+----------+
| type   | flags  | stream_id      | payload_len  | payload  |
+--------+--------+----------------+--------------+----------+
```

All multi-byte fields are big-endian. v0.3 hard-rejects `payload_len > 65535`.
Frame types are an enum defined in `proteus-core`:

| `type` | Name | Direction |
|---|---|---|
| 0x0001 | AUTH_REQUEST | C→S, control stream only |
| 0x0002 | AUTH_RESPONSE | S→C, control stream only |
| 0x0010 | PROXY_OPEN | C→S, first frame on a new proxy stream |
| 0x0011 | PROXY_ACCEPT | S→C |
| 0x0012 | PROXY_REJECT | S→C |
| 0x0020 | DATA | both, on a proxy stream |
| 0x0030 | PING | both, control stream |
| 0x0031 | PONG | both, control stream |

### 7.3 Auth Frames

**AUTH_REQUEST** payload:

```text
client_id_len: u8
client_id:     bytes   (UTF-8, ≤ 64 B)
nonce:         32 B    (random, this auth attempt only)
signature:     64 B    (Ed25519)
```

```text
signature = Ed25519_sign(
  client_static_sk,
  "PROTEUS-v0.3-auth" || exporter || nonce
)
```

`exporter` is 32 bytes of RFC 5705 TLS exporter material:

- label:   `EXPORTER-PROTEUS-v0.3`
- context: empty (zero-length)

**AUTH_RESPONSE** payload:

```text
status:      u8   (0 = ok, non-zero = error code)
reason_len:  u8   (0 if status != 0)
reason:      bytes (opaque; only present on success, never PROTEUS-specific
                    plaintext on failure)
```

On `status != 0`, the server closes the QUIC connection immediately after
sending. The `reason` field is reserved for *successful* responses only
(e.g., future rekey hints). Failed auth produces a **generic** QUIC
application close (see §8.4).

---

## 8. Handshake

### 8.1 QUIC + TLS 1.3

Standard. No PROTEUS-specific behavior at this layer in v0.3.

### 8.2 Post-Handshake PROTEUS Auth

1. Client opens the control stream (lowest bidi stream id, 0x00).
2. Client requests TLS exporter material (32 B, label `EXPORTER-PROTEUS-v0.3`,
   empty context). See roadmap M5 for the exporter feasibility spike.
3. Client constructs AUTH_REQUEST (§7.3) and sends.
4. Server reads AUTH_REQUEST, verifies signature, checks replay cache (§8.3).
5. Server sends AUTH_RESPONSE.
6. On `status != 0`: server closes the connection per §8.4.
7. On `status == 0`: connection is authorized for proxy use (§9).

### 8.3 Replay Protection

The server maintains a per-client replay cache:

- Key: `(client_id, nonce)`.
- TTL: 300 seconds.
- An AUTH_REQUEST whose `(client_id, nonce)` is already in cache is rejected
  with the same generic close as an invalid signature.

The cache must be constant-time-lookup and bounded in memory. The
implementation may evict by LRU once a per-client cap is hit, but the cap
must be set conservatively (≥ expected session-rate × TTL).

### 8.4 Generic Close on Auth Failure

Failed auth closes the QUIC connection with application error code
`H3_GENERAL_PROTOCOL_ERROR` (0x0101) and an empty reason string. Same
behavior as if a malformed H3 client had connected — passive probers
see no PROTEUS-specific signal.

> Open: is this code distinguishable from real H3 server behavior in
> response to a real malformed request? Spike during M14.

---

## 9. Stream Multiplexing

After successful auth, the client opens a new bidirectional stream per proxy
target. The first frame on the stream is `PROXY_OPEN` carrying a CBOR
payload:

```cbor
{
  "v": 1,
  "cmd": "tcp" | "udp",
  "host": "example.com",
  "port": 443
}
```

The server responds with `PROXY_ACCEPT` (empty payload) or `PROXY_REJECT`
(payload: 1-byte reason code; reasons defined in `proteus-core`).

Subsequent frames on an accepted stream carry application data wrapped in
the standard envelope (§7.2) with `type = DATA`.

Server-side policy (roadmap M12) inspects `PROXY_OPEN` and rejects connections
to private ranges or disallowed ports per the server YAML config.

---

## 10. Session Management

v0.3 sessions live for the QUIC connection's lifetime. No rekey, no
migration. When the QUIC connection ends, the session ends. v0.4 adds
rekey (§8.1 of v0.1) and migration (§8.2 of v0.1).

---

## 11. Decoy Behavior

### 11.1 Local HTTP/3 Decoy

The server listens on the same UDP port for both PROTEUS clients and
arbitrary QUIC traffic. A connection whose ALPN is `h3` (or whose
post-handshake first frame is not a valid AUTH_REQUEST within a 3-second
timeout) is handed to an embedded H3 responder that returns a static
HTML page over HTTP/3.

The H3 responder uses the same TLS certificate as the PROTEUS path. There
must be no observable timing or response-size difference between
"client never sent AUTH_REQUEST" and "client sent invalid AUTH_REQUEST".
Both paths funnel into the H3 decoy.

### 11.2 NOT REALITY-Style Masquerading

A local H3 decoy is **not** equivalent to REALITY's upstream-forwarding
trick. The server certificate is its own; a prober can read it and may
recognize the cert as not belonging to any major service. v0.3 accepts
this. v0.4 introduces real upstream forwarding.

---

## 12. Migration Path

```text
v0.3 (this spec)
  └── Prove: QUIC + exporter-bound auth + SOCKS5 + UDP + decoy + policy
        │
        ▼
v0.4
  ├── Real REALITY-style upstream forwarding (replaces local H3 decoy)
  ├── Drop the proteus/0.3 ALPN, use h3 only
  ├── 0-RTT resumption (with replay-safety analysis)
  ├── Connection migration
  └── Inner AEAD layer over PROTEUS frames
        │
        ▼
v0.5
  ├── Port hopping
  ├── SNI rotation
  ├── Padding profiles + timing jitter
  └── Fingerprint comparison passing baseline
        │
        ▼
v1.0
  ├── Hybrid X25519 + ML-KEM-768 (default-on)
  ├── External crypto review complete
  └── Production-readiness statement
```

---

## 13. Open Questions for v0.3

1. **TLS exporter availability in Quinn 0.11.** Roadmap M5 is the answering
   spike. Fallback if unavailable: transcript-hash-binding (less clean,
   needs explicit documentation and a security note).
2. **Generic QUIC close code on auth failure.** §8.4 picks
   `H3_GENERAL_PROTOCOL_ERROR`. Confirm this is plausible vs. a real H3
   server's behavior during M14.
3. **UDP framing.** Length-prefixed datagrams-in-stream (simpler, head-of-line
   blocking) vs. QUIC DATAGRAM frames (lower latency, requires Quinn
   datagram support enabled). v0.3 picks ONE and documents the choice.
4. **Decoy content.** Single static page vs. small SPA-style asset set.
   Default v0.3: single static page.
5. **Cert provenance.** Self-signed is fine for v0.3 lab work; any field
   testing requires a Let's Encrypt cert on a throwaway domain.
6. **ALPN exposure.** v0.3 uses the distinct ALPN `proteus/0.3` for
   simplicity. This is a known fingerprint. Documented; addressed in v0.4.

---

## Appendix A: Relationship to v0.1

v0.1 (`PROTEUS-spec-v0.1.md`) remains the long-term vision. When v0.3
is done, v0.2 is itself superseded by a v0.3 "as-built" spec, and v0.1
starts being incrementally re-targeted by v0.4+.

## Appendix B: What Stays the Same as v0.1

- Working name: PROTEUS.
- Stack: Rust + Quinn + rustls + Ed25519.
- Per-client identity via Ed25519.
- CBOR for stream metadata.
- The 13 open questions in v0.1 remain open for v1.0; v0.3 punts on most.
