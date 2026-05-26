# PROTEUS v0.3 Implementation Roadmap

> **Companion docs:** `PROTEUS-spec-v0.2.md` (what we build), `THREAT-MODEL-v0.3.md` (limits).
> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Build a research prototype of PROTEUS: QUIC/TLS transport,
exporter-bound client auth, TCP/UDP proxying, decoy behavior, and
packet-capture/fingerprint tooling.

**Architecture:** Rust workspace with separate crates for core protocol,
server, client, and tools. QUIC/TLS 1.3 is the outer security layer; PROTEUS
auth happens after handshake and is bound to TLS exporter material. Proxy
features are added only after the transport and auth are tested.

**Tech Stack:** Rust, Tokio, Quinn, rustls, h3/h3-quinn, Ed25519, serde_yaml,
clap, tcpdump/Wireshark/qlog-style capture tooling.

---

## Changelog vs Initial Draft

- **M5 (TLS Exporter Spike) is now the first coding task after M0**, not the
  sixth. Rationale: the entire auth design depends on exporter material being
  available from Quinn/rustls. If it is not, the spec changes and several
  later milestones (M6, M7) shift. Doing M5 early is risk-first — find out
  about the blocker before building 4 milestones on top of it.
- **Explicit "Plan B" block added to M5** specifying the fallback if exporter
  material is not available.
- **§5 Recommended Implementation Order updated** to reflect the new sequence
  (M0 → M5 → M1 → M2 → M3 → M4 → M6 → ...).
- All other milestone numbers are unchanged so external references survive.

---

## 1. v0.3 Scope

v0.3 is a **research prototype**, not production software. See
`PROTEUS-spec-v0.2.md` §2-3 and `THREAT-MODEL-v0.3.md` for full scope.

It must prove:

1. Basic QUIC client/server connectivity works.
2. TLS-exporter-bound authorization works or its blocker is clearly documented.
3. Each client has independent Ed25519 credentials.
4. Replay protection works.
5. TCP proxying works through QUIC streams.
6. SOCKS5 local proxy works for TCP CONNECT.
7. UDP echo proxying works in a minimal form.
8. Invalid clients do not receive PROTEUS-specific plaintext errors.
9. A local HTTP/3 decoy exists.
10. Packet captures can be produced and compared against browser HTTP/3 traffic.

Out of scope (deferred — see spec v0.2 §3):
production deployment, PQ-as-default, advanced traffic shaping, port hopping,
ECH, MASQUE compatibility, mobile clients, GUI, kernel TUN/TAP, perfect
Chrome indistinguishability.

---

## 2. Workspace Layout

```text
proteus/
├── Cargo.toml
├── README.md
├── docs/
│   ├── PROTEUS-spec-v0.1.md
│   ├── PROTEUS-spec-v0.2.md
│   ├── ROADMAP-v0.3.md
│   ├── THREAT-MODEL-v0.3.md
│   ├── TASKS-v0.3.md
│   ├── fingerprinting.md
│   └── test-plan.md
├── crates/
│   ├── proteus-core/
│   ├── proteus-server/
│   ├── proteus-client/
│   └── proteus-tools/
├── configs/
│   ├── server.example.yaml
│   └── client.example.yaml
├── tests/
└── scripts/
```

---

## 3. Rust Crates

```toml
[workspace]
resolver = "2"
members = [
  "crates/proteus-core",
  "crates/proteus-server",
  "crates/proteus-client",
  "crates/proteus-tools"
]
```

Recommended dependencies:

```toml
tokio = { version = "1", features = ["full"] }
anyhow = "1"
thiserror = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
quinn = "0.11"
rustls = "0.23"
rustls-pemfile = "2"
rcgen = "0.13"
h3 = "0.0.6"
h3-quinn = "0.0.7"
bytes = "1"
ed25519-dalek = "2"
rand = "0.8"
sha2 = "0.10"
hmac = "0.12"
base64 = "0.22"
serde = { version = "1", features = ["derive"] }
serde_yaml = "0.9"
toml = "0.8"
clap = { version = "4", features = ["derive"] }
ciborium = "0.2"
```

---

## 4. Milestones

### M0 — Project Skeleton

Create workspace, crates, placeholder configs, README, initial CI-quality
checks.

Definition of done:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

### M5 — TLS Exporter Spike  ⚠️ FIRST CODING MILESTONE AFTER M0

Determine whether Quinn 0.11 + rustls 0.23 expose TLS exporter material
(RFC 5705) sufficiently for client and server to derive matching 32-byte
keys.

Implementation: a single throwaway binary in `crates/proteus-tools` named
`exporter-spike`. Server and client both connect, both call
`Connection::export_keying_material` (or equivalent), both print the bytes
hex-encoded. Compare.

Definition of done — one of:

- **Path A (Exporter works):** Both sides print identical 32-byte exporters.
  Spec stays as written; proceed to M1.
- **Path B (Exporter does not work):** Document the exact failure in
  `docs/spike-m5-exporter.md` and execute Plan B below.

**Plan B if exporter is not available:**

1. Use the TLS transcript hash (whatever Quinn exposes — connection ID
   combined with the peer cert fingerprint, or, if accessible, the actual
   handshake transcript hash) as the binding value instead.
2. Update spec v0.2 §7.3 / §8.2 to substitute `transcript_binding` for
   `exporter` in the signature input.
3. Add a security note in spec v0.2 explaining the weakened binding
   (transcript hash is not as cleanly per-direction as exporter material).
4. File an issue tracking "switch back to exporter binding" for v0.4.

Either path is acceptable for v0.3. The unacceptable outcome is to discover
this is a problem in M6 and have to rewrite the auth design.

### M1 — Config and CLI

Server and client load YAML configs and expose basic CLI flags.

### M2 — Keygen Tool

`proteus-tools keygen` creates Ed25519 keypairs for named clients.

### M3 — Basic QUIC Ping/Pong

Client connects to server over QUIC and exchanges `ping` / `pong` using
plain Quinn streams (no PROTEUS frames yet).

### M4 — Frame Codec

Implement the PROTEUS frame envelope (spec v0.2 §7.2). Encoder/decoder in
`proteus-core`, fuzz-friendly. Replace the M3 plain-streams with framed
PING/PONG (frame types 0x0030 / 0x0031).

### M6 — Exporter-Bound Ed25519 Auth

Client signs `"PROTEUS-v0.3-auth" || exporter || nonce` and sends
AUTH_REQUEST (frame type 0x0001). Server verifies and replies AUTH_RESPONSE.
Builds directly on M5.

### M7 — Replay Cache

Per-client `(client_id, nonce)` cache, 300 s TTL. Reject repeats.

### M8 — TCP Proxy over QUIC

Per-stream PROXY_OPEN with CBOR target metadata. Bidirectional copy between
QUIC stream and target TCP socket. Echo-server integration test.

### M9 — SOCKS5 Local Proxy

Client exposes `127.0.0.1:1080` SOCKS5 CONNECT, translates to PROXY_OPEN.

### M10 — UDP Proxy

Minimal UDP echo. Pick ONE of: length-prefixed datagrams over QUIC streams,
OR QUIC DATAGRAM frames. Document the choice and tradeoff.

### M11 — Remote DNS Mode

Server resolves hostnames sent by client (SOCKS5 `--socks5-hostname` style).

### M12 — Policy Engine

Block RFC1918, loopback, link-local; configurable port allowlist/denylist;
toggle UDP on/off; per-client overrides.

### M13 — Local HTTP/3 Decoy

Serve a static H3 page for non-PROTEUS connections (spec v0.2 §11).

### M14 — Invalid Client Handling

No PROTEUS-specific plaintext in close frames. Use `H3_GENERAL_PROTOCOL_ERROR`
per spec v0.2 §8.4. Verify with a captured close from a real H3 client
malformed-request scenario.

### M15 — Capture Tooling

Scripts in `scripts/` for: capturing Chrome HTTP/3 to a target site, capturing
PROTEUS traffic, basic side-by-side comparison (packet counts, sizes, timing
histogram).

### M16 — Fingerprint Profile Files

YAML format for storing measured browser profile samples. Schema only in
v0.3; matching machinery is v0.5.

### M17 — Metrics

Track: auths attempted/succeeded/failed, replays rejected, active sessions,
bytes per direction, proxy stream open/close counts.

### M18 — Hardening

Connection timeouts, max frame size enforcement, per-client rate limits,
no secret material in logs, malformed-frame fuzz tests.

### M19 — Optional PQ Spike

Document feasibility of ML-KEM/hybrid PQ in current Quinn/rustls without
enabling by default. Output: `docs/spike-m19-pq.md`.

---

## 5. Recommended Implementation Order

```text
1.  M0  Workspace
2.  M5  TLS Exporter Spike      ← RISK-FIRST, blocks M6
3.  M1  Config
4.  M2  Keygen
5.  M3  Basic QUIC
6.  M4  Frame Codec
7.  M6  Auth (depends on M5)
8.  M7  Replay Cache
9.  M8  TCP Proxy
10. M9  SOCKS5
11. M10 UDP Proxy
12. M11 Remote DNS
13. M12 Policy Engine
14. M13 Decoy HTTP/3
15. M14 Invalid Client Handling
16. M15 Capture Tooling
17. M16 Fingerprint Profiles
18. M17 Metrics
19. M18 Hardening
20. M19 PQ Spike
```

Do not start with PQ, traffic shaping, or port hopping. They will make
debugging harder and hide the important risks.

---

## 6. Definition of Done

v0.3 is done when:

1. Server starts from YAML config.
2. Client starts from YAML config.
3. QUIC connection succeeds.
4. Ed25519 auth succeeds (via exporter binding, OR via documented Plan B).
5. Replay attempts fail.
6. TCP echo integration test passes.
7. `curl --socks5-hostname 127.0.0.1:1080 http://example.com` works.
8. UDP echo integration test passes.
9. Invalid auth produces no PROTEUS-specific plaintext error.
10. Capture scripts produce `.pcap` files.
11. A first fingerprint comparison report exists in `docs/`.
12. README states clearly: research prototype, not production-ready.

---

## 7. First Coding Commands

```bash
mkdir proteus
cd proteus
git init
mkdir -p crates docs configs scripts tests
cargo new crates/proteus-core --lib
cargo new crates/proteus-server --bin
cargo new crates/proteus-client --bin
cargo new crates/proteus-tools --bin
```

Create root `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = [
  "crates/proteus-core",
  "crates/proteus-server",
  "crates/proteus-client",
  "crates/proteus-tools"
]
```

Then:

```bash
cargo fmt
cargo test --workspace
git add .
git commit -m "chore: initialize proteus rust workspace"
```

Immediately after that: implement the M5 exporter spike binary in
`crates/proteus-tools/src/bin/exporter-spike.rs` before any other milestone.
