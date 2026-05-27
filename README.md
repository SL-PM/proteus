# PROTEUS

> **Status: v0.3 working research prototype.**
> All 19 roadmap milestones complete in code or doc. 11/12 DoD items
> met — the last (fingerprint comparison report) requires a manual
> capture run with sudo + curl-with-http3.

## What this is

A research prototype of a VPN / circumvention protocol combining
REALITY's indistinguishability idea, Hysteria2's QUIC transport, and
exporter-bound Ed25519 client auth.

- Long-term vision: [`docs/PROTEUS-spec-v0.1.md`](docs/PROTEUS-spec-v0.1.md).
- v0.3 prototype scope (what this repo actually implements):
  [`docs/PROTEUS-spec-v0.2.md`](docs/PROTEUS-spec-v0.2.md).
- v0.3 implementation milestones:
  [`docs/ROADMAP-v0.3.md`](docs/ROADMAP-v0.3.md).

## ⚠️ Not a production tool

v0.3 is **DPI-detectable by design** — REALITY-style upstream
forwarding is deferred to v0.4, post-quantum crypto to v1.0. Do not
deploy v0.3 as a circumvention tool in any adversarial environment.
See [`docs/THREAT-MODEL-v0.3.md`](docs/THREAT-MODEL-v0.3.md) for the
full statement.

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

## Milestones (M0–M19)

| | Milestone | Status |
|---|---|:---:|
| M0 | Cargo workspace bootstrap | ✅ |
| M1 | YAML config + clap CLI | ✅ |
| M2 | `proteus-tools keygen` (Ed25519, base64 .key/.pub, mode 0600) | ✅ |
| M3 | Basic QUIC ping/pong | ✅ |
| M4 | PROTEUS frame envelope (spec §7.2) | ✅ |
| M5 | TLS exporter spike — Path A confirmed | ✅ |
| M6 | Exporter-bound Ed25519 auth on control stream | ✅ |
| M7 | Per-client `(client_id, nonce)` replay cache | ✅ |
| M8 | TCP proxy over QUIC + CBOR PROXY_OPEN | ✅ |
| M9 | SOCKS5 CONNECT frontend daemon | ✅ |
| M10 | UDP proxy + `proteus-tools udp-test` | ✅ |
| M11 | Remote DNS — **implicit** in the M8/M9/M10 design | ✅ |
| M12 | Server-side policy engine | ✅ |
| M13 | Local HTTP/3 decoy on ALPN `h3` | ✅ |
| M14 | Invalid-client handling | ⚠️ code-path done; pcap sign-off pending |
| M15 | Capture tooling (`scripts/capture-*.sh`) | ✅ |
| M16 | Fingerprint profile YAML schema | ✅ |
| M17 | Runtime metrics counters + periodic snapshot | ✅ |
| M18 | Connection idle timeout + AUTH_REQUEST read timeout | ✅ |
| M18.1 | Per-IP auth rate limit + frame decode fuzz | ✅ |
| M19 | Post-quantum feasibility note (forward-looking) | ✅ |

## Documents

| File | Purpose |
|---|---|
| [`docs/PROTEUS-spec-v0.1.md`](docs/PROTEUS-spec-v0.1.md) | Long-term vision (May 2026 draft) |
| [`docs/PROTEUS-spec-v0.2.md`](docs/PROTEUS-spec-v0.2.md) | v0.3 prototype scope + wire formats |
| [`docs/ROADMAP-v0.3.md`](docs/ROADMAP-v0.3.md) | Implementation milestones M0–M19 |
| [`docs/THREAT-MODEL-v0.3.md`](docs/THREAT-MODEL-v0.3.md) | A1–A11 with coverage matrix |
| [`docs/CONFIG.md`](docs/CONFIG.md) | Per-field YAML reference |
| [`docs/m14-invalid-client.md`](docs/m14-invalid-client.md) | M14 status + sign-off acceptance criteria |
| [`docs/spike-m5-exporter.md`](docs/spike-m5-exporter.md) | M5 result note |
| [`docs/spike-m19-pq.md`](docs/spike-m19-pq.md) | Post-quantum feasibility for v1.0 |
| [`docs/fingerprint-profile.example.yaml`](docs/fingerprint-profile.example.yaml) | M16 schema for v0.5 fingerprint work |
| [`scripts/README.md`](scripts/README.md) | M15 capture-and-compare tooling |

## Threat-model summary (one-line)

- **In scope and covered in v0.3:** A1 passive interception, A2
  unauthorized client (Ed25519), A3 replay (nonce cache), A4 casual
  port-prober (M13 H3 decoy).
- **Out of scope for v0.3:** A5 DPI / A6 cert inspection / A7
  statistical analysis / A8 IP-block / A9 PQ / A10 global passive /
  A11 endpoint compromise. See the threat-model doc for which
  milestone closes each.

## Build / test

```sh
cargo build --workspace
cargo test --workspace        # 73 tests (68 core + 5 tools)
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Architecture (one paragraph)

`proteus-core` is the shared library: `auth`, `config`, `frame`,
`metrics`, `policy`, `proxy`, `ratelimit`, `replay`, `tls`. The
binary crates are thin: `proteus-server` runs auth + replay + policy
+ rate-limit + per-target TCP/UDP proxy streams + H3 decoy fallback;
`proteus-client` runs an auth-once daemon with a SOCKS5 CONNECT
frontend; `proteus-tools` ships `keygen` and `udp-test`
subcommands.

## License

Documents: CC-BY-SA 4.0.
Code: not yet licensed; please ask before any redistribution. A
proper license will be chosen before any v0.4 / external release.
