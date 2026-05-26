# PROTEUS v0.3 — Threat Model

**Version:** v0.3
**Date:** May 2026
**Companion to:** `PROTEUS-spec-v0.2.md`

> **Bottom line:** v0.3 is a research prototype. It defends against
> unauthorized use and basic interception. It does NOT defend against any
> capable network observer who is looking for PROTEUS specifically.

---

## In-Scope Adversaries (v0.3)

### A1. Passive network observer (transport-only)

- **Capability:** Sees ciphertext on the wire. Cannot inject, cannot probe.
- **Defense:** QUIC + TLS 1.3 confidentiality.
- **Residual risk:** None at this layer for v0.3.

### A2. Unauthorized client

- **Capability:** Can reach the server's UDP port. Does not have a valid
  client Ed25519 keypair.
- **Defense:** Ed25519 signature over TLS exporter material (spec v0.2 §8).
  Without the private key, the adversary cannot produce a valid AUTH_REQUEST.
- **Residual risk:** Compromised client key on a legitimate client device.
  Out of scope (endpoint compromise — A11).

### A3. Replay attacker

- **Capability:** Captured a valid AUTH_REQUEST in flight. Replays it later.
- **Defense:** Per-client `(client_id, nonce)` cache, 300 s TTL
  (spec v0.2 §8.3). Plus: TLS exporter material is per-TLS-session, so a
  replayed AUTH_REQUEST from session A will not validate inside session B
  even with the same nonce. The cache is belt-and-suspenders for the
  same-session case.
- **Residual risk:** Within the same TLS session and within the cache TTL,
  before the cache entry is written. Race window is microseconds.

### A4. Casual port-prober

- **Capability:** Connects to the listening UDP port with arbitrary QUIC
  traffic. Looks for protocol-specific error responses.
- **Defense:** Local H3 decoy (spec v0.2 §11). Invalid connections get a
  static HTML page over HTTP/3. Auth failures close with the generic
  `H3_GENERAL_PROTOCOL_ERROR` code, no PROTEUS-specific text.
- **Residual risk:** A sophisticated prober (A5, A6) is **not** defended
  against.

---

## Out-of-Scope Adversaries (v0.3)

The v0.3 prototype is **NOT** secure against the following. Do not deploy
v0.3 against any of these adversaries.

### A5. DPI / protocol fingerprinter

- **Why out-of-scope:** v0.3 does not implement REALITY-style masquerading,
  has no padding distribution matching, has no timing jitter, has no SNI
  rotation. The QUIC handshake fingerprint, packet size distribution, and
  timing pattern of v0.3 traffic will not match real Chrome H3 traffic.
  Additionally, v0.3 advertises the distinct ALPN `proteus/0.3` — trivially
  identifiable.
- **Coverage:** v0.4 (drop distinct ALPN, masquerading) + v0.5 (shaping).

### A6. Active prober with TLS cert inspection

- **Why out-of-scope:** The server presents its own (self-signed or
  throwaway-domain) certificate. A prober can read the cert and recognize
  it as not belonging to any cover service.
- **Coverage:** v0.4 (upstream forwarding makes the cert belong to the real
  cover host).

### A7. Statistical traffic analyst

- **Why out-of-scope:** Without padding and timing jitter, packet-size and
  inter-arrival distributions are characteristic of the application being
  proxied, not of cover HTTP/3 browsing.
- **Coverage:** v0.5.

### A8. IP-level censor

- **Why out-of-scope:** Single static IP, single port. No port hopping, no
  IP rotation.
- **Coverage:** v0.5 (port hopping) + operational (IP rotation is a
  deployment concern, not a protocol concern).

### A9. Harvest-now-decrypt-later quantum adversary

- **Why out-of-scope:** v0.3 uses classical TLS 1.3 (X25519 / ECDHE).
  Captured ciphertext can be decrypted by a future capable quantum computer.
- **Coverage:** v1.0 (hybrid X25519 + ML-KEM-768).

### A10. Global passive adversary with traffic correlation

- **Why out-of-scope (and out-of-scope in v0.1):** No single-server VPN
  defends against this.

### A11. Endpoint compromise

- **Why out-of-scope (and out-of-scope in v0.1):** Out of scope of any
  network protocol.

---

## Deployment Restrictions for v0.3

A v0.3 build:

- **MAY** be used in a lab for development and testing.
- **MAY** be used to test against simulated DPI as a known-detectable
  baseline that v0.4+ should improve on.
- **MUST NOT** be used as a primary circumvention tool in any adversarial
  environment.
- **MUST NOT** be relied on to hide the *existence* of a VPN connection
  from any capable observer.

The README must reflect these restrictions.

---

## Coverage Across Versions

| Adversary | v0.3 | v0.4 | v0.5 | v1.0 |
|---|:---:|:---:|:---:|:---:|
| A1 Passive interception | ✓ | ✓ | ✓ | ✓ |
| A2 Unauthorized client | ✓ | ✓ | ✓ | ✓ |
| A3 Replay | ✓ | ✓ | ✓ | ✓ |
| A4 Casual probe | ✓ | ✓ | ✓ | ✓ |
| A5 DPI fingerprint | ✗ | partial | ✓ | ✓ |
| A6 Cert inspection | ✗ | ✓ | ✓ | ✓ |
| A7 Statistical traffic analysis | ✗ | ✗ | ✓ | ✓ |
| A8 IP/port block | ✗ | ✗ | partial | ✓ |
| A9 Quantum (harvest-now) | ✗ | ✗ | ✗ | ✓ |
| A10 Global passive | ✗ | ✗ | ✗ | ✗ |
| A11 Endpoint | ✗ | ✗ | ✗ | ✗ |

`partial` = mitigated but not eliminated.
`✗` at v1.0 = out of scope of the protocol entirely.
