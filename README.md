# PROTEUS

> **Status: v0.5.0-rc.1 working research prototype.**
> v0.4 (Approach C) added inner AEAD wire wrapping, TLS 1.3 0-RTT,
> QUIC connection migration, and a high-fidelity H3 decoy. v0.5-rc.1
> adds **wire-pattern padding**: per-frame bucket-padding (size leak
> closed) + server-side idle dummy traffic (silence leak closed).

## What this is

A research prototype of a VPN / circumvention protocol combining
REALITY's indistinguishability idea, Hysteria2's QUIC transport, and
exporter-bound Ed25519 client auth.

- Long-term vision: [`docs/PROTEUS-spec-v0.1.md`](docs/PROTEUS-spec-v0.1.md).
- v0.3 prototype scope:
  [`docs/PROTEUS-spec-v0.2.md`](docs/PROTEUS-spec-v0.2.md).
- v0.3 implementation milestones:
  [`docs/ROADMAP-v0.3.md`](docs/ROADMAP-v0.3.md).
- **v0.4 design + sign-off:**
  [`docs/PROTEUS-v0.4-plan.md`](docs/PROTEUS-v0.4-plan.md) +
  [`docs/m9.4-rc1-signoff.md`](docs/m9.4-rc1-signoff.md).
- **v0.5 design + sign-off:**
  [`docs/PROTEUS-v0.5-plan.md`](docs/PROTEUS-v0.5-plan.md) +
  [`docs/m5.5-padding-signoff.md`](docs/m5.5-padding-signoff.md).

## ⚠️ Not a production tool

v0.5 is **still DPI-detectable by design** at the connection envelope
(distinctive `proteus/0.3` ALPN; bucket-padding quantizes frame sizes
to 5 values but the distribution shape + timing still differ from a
real cover host). True ALPN unification + REALITY-style upstream relay
is v1.0 work; profile-driven size sampling + timing jitter are v0.5-rc.2.
Do not deploy as a circumvention tool in any adversarial environment.
See [`docs/THREAT-MODEL-v0.3.md`](docs/THREAT-MODEL-v0.3.md) for the
full statement (still accurate for v0.4 — same threat model, more
hardening inside the tunnel).

## Quick start

```sh
# 1. Generate alice's keypair
cargo run --bin proteus-tools -- keygen --name alice --out-dir /tmp/keys

# 2. Server config (paste the printed pubkey)
cat > /tmp/server.yaml <<EOF
listen:
  addr: "127.0.0.1:4433"
clients:
  alice: "$(cat /tmp/keys/alice.pub)"
EOF

# 3. Client config
cat > /tmp/client.yaml <<EOF
server:
  addr: "127.0.0.1:4433"
  sni: "localhost"
identity:
  client_id: "alice"
  private_key: "/tmp/keys/alice.key"
socks5:
  listen: "127.0.0.1:1080"
EOF

# 4. Run both
cargo run --bin proteus-server -- --config /tmp/server.yaml &
cargo run --bin proteus-client -- --config /tmp/client.yaml &

# 5. Use the SOCKS5 endpoint
curl --socks5 127.0.0.1:1080 http://example.com/
```

Full config reference (every field, every default, every milestone):
[`docs/CONFIG.md`](docs/CONFIG.md).

UDP echo (no SOCKS5 frontend yet for UDP):

```sh
cargo run --bin proteus-tools -- udp-test \
    --config /tmp/client.yaml --target 1.1.1.1:53 --payload "..."
```

## v0.4 highlights

What changed since v0.3.0-rc.1:

- **Inner AEAD over PROTEUS frames** (M5.4 + M5.4.1). All proxy-stream
  frames are ChaCha20-Poly1305-sealed inside the QUIC TLS tunnel with
  per-stream subkeys (HKDF over the stream-id).
- **TLS 1.3 0-RTT resumption** (M6.4). Server opts in; replay safety
  analysis in [`docs/m6.4-zero-rtt.md`](docs/m6.4-zero-rtt.md).
- **QUIC connection migration** (M7.4). `(client_id, nonce)` cache
  survives 5-tuple changes. Integration test asserts an active proxy
  stream rides over `endpoint.rebind()`.
- **PEM cert + key loading** (M4.4). Operators no longer constrained
  to self-signed dev certs.
- **High-fidelity H3 decoy** (M3.4 + M8.4 + M8.4.1):
  - `proteus-tools fetch-decoy --url ... --out body.html --out-headers headers.json`
    snapshots a real cover host's body **and** response-header set.
  - Server serves byte-identical body + mirrored headers (27
    cloudflare-style headers vs. 3 hardcoded nginx-style before).
  - `date:` regenerated per-request; hop-by-hop / `content-length`
    handled correctly. See
    [`docs/CONFIG.md`](docs/CONFIG.md#high-fidelity-decoy-v04-m34--m84--m841).
- **Server-as-library** (M9.4). `proteus-server::Server` exposes
  `bind/run/shutdown/metrics` so integration tests spin it up
  in-process; the bin is now a ~80-line wrapper. Auth, migration,
  and 0-RTT regression tests live under
  [`crates/proteus-server/tests/`](crates/proteus-server/tests/).

## v0.5 highlights

What changed since v0.4.0 — wire-pattern padding (opt-in, default off):

- **Bucket-padding** (M1.5 + M2.5). Every PROTEUS frame's on-wire
  `payload_len` is rounded up to one of `{128, 256, 512, 1024, 1500}`.
  A 5-byte and a 100-byte response are now indistinguishable on the
  wire (both 128). Padding lives inside the AEAD-sealed block; reads
  auto-strip it. Enable with `padding.enabled: true` on **both** ends.
- **Idle dummy traffic** (M3.5, server-only). After a configurable
  quiet interval the server emits a padded PING frame, so an idle
  PROTEUS stream isn't distinguishable from an H3 session by its
  silence. `idle_padding.enabled: true`.
- **Wire-distribution test** (M4.5). `tests/padding.rs` reads
  server→client frames at the raw QUIC level and asserts ≥95% land on
  a bucket (observed 100%). A padding-off control proves the change is
  real. Sign-off: [`docs/m5.5-padding-signoff.md`](docs/m5.5-padding-signoff.md).

Known limitations (honestly documented, deferred):

- `proteus/0.3` ALPN still advertised. Unification needs an h3 fork
  or mini-h3 server — see
  [`docs/m2.4-dispatch-research.md`](docs/m2.4-dispatch-research.md).
  Re-scoped as v1.0 work.
- Decoy header mirroring is byte-identical *from the snapshot*; a few
  cover-host headers are per-request unique (e.g. cloudflare's
  `cf-ray`, `__cf_bm`) so a prober making two requests sees the same
  values. True fix = live decoy-proxy (Approach B, v0.5+).
- Bucket-padding quantizes sizes to 5 spikes — still
  distinguishable from a real cover host's smooth distribution, and
  timing is unchanged. Profile-driven sampling + timing jitter (closing
  A7) are **v0.5-rc.2**.

## Milestones

### v0.3 (M0–M19)

All 19 milestones complete in code or doc. M14 sign-off captured
in [`docs/m14-comparison-report.md`](docs/m14-comparison-report.md).
v0.3.0-rc.1 tagged 2026-05-27.

### v0.4 (M0.4–M9.4)

| | Milestone | Status |
|---|---|:---:|
| M0.4 | v0.4-dev branch + plan doc | ✅ |
| M1.4 | Drop `proteus/0.3` ALPN | ⏸ deferred → v1.0 |
| M2.4 | First-frame discriminator | ⏸ deferred → v1.0 |
| M3.4 | High-fidelity decoy (nginx default) | ✅ |
| M4.4 | PEM cert+key loading | ✅ |
| M5.4 | Inner AEAD primitives | ✅ |
| M5.4.1 | Wire-format AEAD wrapping | ✅ |
| M6.4 | TLS 1.3 0-RTT (config-level) | ✅ |
| M7.4 | Connection migration | ✅ |
| M8.4 | `fetch-decoy` utility (body) | ✅ |
| M8.4.1 | Decoy response-header mirroring | ✅ |
| M9.4 | Server-as-library + integration tests + sign-off | ✅ |

Full milestone matrix:
[`docs/PROTEUS-v0.4-plan.md`](docs/PROTEUS-v0.4-plan.md) §9.

### v0.5 (M0.5–M5.5) — rc.1

| | Milestone | Status |
|---|---|:---:|
| M0.5 | v0.5 plan doc | ✅ |
| M1.5 | `proteus_core::padding` module + PADDED-flag protocol | ✅ |
| M2.5 | Wire-up: server + client + udp-test pad/un-pad | ✅ |
| M3.5 | Server-side idle dummy traffic | ✅ |
| M4.5 | Wire-distribution integration test | ✅ |
| M5.5 | Sign-off | ✅ |

Deferred to v0.5-rc.2: profile-driven size sampling, timing jitter,
SNI rotation, port hopping. Matrix:
[`docs/PROTEUS-v0.5-plan.md`](docs/PROTEUS-v0.5-plan.md) §6.

## Documents

| File | Purpose |
|---|---|
| [`docs/PROTEUS-spec-v0.1.md`](docs/PROTEUS-spec-v0.1.md) | Long-term vision (May 2026 draft) |
| [`docs/PROTEUS-spec-v0.2.md`](docs/PROTEUS-spec-v0.2.md) | v0.3 prototype scope + wire formats |
| [`docs/ROADMAP-v0.3.md`](docs/ROADMAP-v0.3.md) | v0.3 implementation milestones |
| [`docs/PROTEUS-v0.4-plan.md`](docs/PROTEUS-v0.4-plan.md) | v0.4 design, milestone matrix, stretch goals |
| [`docs/PROTEUS-v0.5-plan.md`](docs/PROTEUS-v0.5-plan.md) | v0.5 wire-padding design + milestone matrix |
| [`docs/THREAT-MODEL-v0.3.md`](docs/THREAT-MODEL-v0.3.md) | A1–A11 coverage matrix |
| [`docs/CONFIG.md`](docs/CONFIG.md) | Per-field YAML reference + decoy + padding walkthroughs |
| [`docs/m6.4-zero-rtt.md`](docs/m6.4-zero-rtt.md) | 0-RTT design + Quinn-rustls quirks |
| [`docs/m7.4-connection-migration.md`](docs/m7.4-connection-migration.md) | Migration design |
| [`docs/m2.4-dispatch-research.md`](docs/m2.4-dispatch-research.md) | Why ALPN unification needs v1.0 scope |
| [`docs/m9.4-rc1-signoff.md`](docs/m9.4-rc1-signoff.md) | v0.4-rc.1 acceptance evidence |
| [`docs/m5.5-padding-signoff.md`](docs/m5.5-padding-signoff.md) | v0.5-rc.1 acceptance evidence |
| [`docs/m14-comparison-report.md`](docs/m14-comparison-report.md) | v0.3 wire fingerprint baseline |
| [`docs/spike-m19-pq.md`](docs/spike-m19-pq.md) | Post-quantum feasibility for v1.0 |
| [`docs/fingerprint-profile.example.yaml`](docs/fingerprint-profile.example.yaml) | M16 schema for v0.5-rc.2 profile sampling |
| [`CHANGELOG.md`](CHANGELOG.md) | Per-release changes since project start |
| [`scripts/README.md`](scripts/README.md) | M15 capture-and-compare tooling |

## Threat-model summary (v0.5)

- **In scope and covered:** A1 passive interception (QUIC TLS + inner
  AEAD), A2 unauthorized client (Ed25519), A3 replay (`(client_id,
  nonce)` cache, survives QUIC migration), A4 casual port-prober
  (H3 decoy byte-identical to cover host modulo per-request cf-ray).
- **Partially closed:** A5 active DPI / wire-pattern — inner AEAD +
  v0.5 bucket-padding (per-frame size leak) + idle dummies (silence
  leak). Distribution shape + timing remain.
- **Out of scope until later:** A6 cert inspection / A7 statistical
  analysis (rc.2 profile sampling + timing) / A8 IP-block / A9 PQ /
  A10 global passive / A11 endpoint compromise. See the threat-model doc.

## Build / test

```sh
cargo build --workspace
cargo test  --workspace        # 146 tests (119 core + 5 server-lib + 14 tools + 8 server-integration)
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Architecture (one paragraph)

`proteus-core` is the shared library: `aead`, `auth`, `config`,
`decoy`, `frame`, `metrics`, `padding`, `policy`, `proxy`,
`ratelimit`, `replay`, `tls`. `proteus-server` is now a library + thin bin — the library
crate (`proteus_server::Server`) exposes `bind/run/shutdown/metrics`
for in-process integration tests; the bin parses CLI args and prints
the startup banner. `proteus-client` is a SOCKS5 CONNECT daemon
that pays auth once, then opens fresh per-target proxy streams
(AEAD-wrapped). `proteus-tools` ships `keygen` (Ed25519 keypair
generator), `udp-test` (one-shot UDP echo through a server), and
`fetch-decoy` (snapshots cover-host body + headers for the H3
decoy).

## License

- **Code**: GNU Affero General Public License v3.0 or later
  (`AGPL-3.0-or-later`). See [`LICENSE`](LICENSE) for the full text.
- **Documents** (everything under `docs/`): CC-BY-SA 4.0.

The AGPL choice is deliberate for a circumvention tool: forks that
operate the server as a network service must publish their
modifications, so the protocol stays open even if someone builds a
hosted product around it.
