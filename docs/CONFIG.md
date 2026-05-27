# PROTEUS v0.3 — Configuration Reference

Both `proteus-server` and `proteus-client` load a single YAML config
file via `--config PATH`. The schemas below match the Rust types in
[`proteus-core::config`](../crates/proteus-core/src/config.rs) and the
milestone status of each section.

> ⚠️ See [`THREAT-MODEL-v0.3.md`](THREAT-MODEL-v0.3.md) for the
> deployment restrictions on v0.3. None of the fields below change the
> fact that v0.3 is DPI-detectable by design.

---

## Server (`server.yaml`)

```yaml
# Required.
listen:
  addr: "0.0.0.0:4433"             # SocketAddr the server binds for QUIC

# Optional. Default: "info". Reserved — not yet wired through tracing.
log_level: "info"

# Optional — activated in M6. Reserved for PEM cert/key loading; v0.3
# always generates a fresh self-signed cert on startup, so the section
# is parsed but ignored with a stderr warning (see proteus-core::tls).
tls:
  cert: "configs/server-cert.pem"
  key:  "configs/server-key.pem"

# Optional — activated in M6 (M2 generates the values). Map of
# client_id → standard base64 of the 32-byte Ed25519 public key. Use
# `proteus-tools keygen` and copy the printed YAML line here.
clients:
  alice: "BASE64_ED25519_PUBKEY"
  bob:   "BASE64_ED25519_PUBKEY"

# Optional — activated in M12. Server-side policy engine. Absent
# section = no checks (all targets allowed).
policy:
  block_private_ranges: true        # reject loopback / RFC1918 / link-local
  allowed_ports: [80, 443, 8080]    # empty = no allowlist constraint
  denied_ports: [22]                # takes precedence over allowed_ports
  allow_udp: false                  # gate UDP traffic separately from TCP

# Optional — reserved for M13. Path to the static HTML page the H3
# decoy will serve to non-PROTEUS QUIC connections.
decoy:
  static_page: "configs/decoy.html"
```

---

## Client (`client.yaml`)

```yaml
# Required.
server:
  addr: "127.0.0.1:4433"            # SocketAddr of the PROTEUS server
  sni:  "localhost"                 # TLS SNI sent in the QUIC handshake
  cert_sha256: ""                   # lowercase hex SHA-256 of the server
                                    # leaf cert. Empty = accept any
                                    # (v0.3 lab only; do not deploy).

# Required.
identity:
  client_id: "alice"                # must match a key in server.clients
  private_key: "keys/alice.key"     # output of `proteus-tools keygen`

# Required.
socks5:
  listen: "127.0.0.1:1080"          # SOCKS5 CONNECT listener (M9)

# Optional. Default: "info". Reserved.
log_level: "info"
```

---

## Working with a keypair (M2)

```sh
# Generate Ed25519 keypair, writes alice.key + alice.pub into ./keys/
proteus-tools keygen --name alice --out-dir keys

# Copy the printed `alice: "..."` line into the server's clients: map.
# Reference alice.key from the client's identity.private_key.
```

The private key file is written with mode `0600` on Unix. The public
key is also written to `alice.pub` for convenience and is printed to
stdout in YAML-ready form.

---

## Field-by-field summary

### Server

| Field | Type | Required | Milestone | Effect |
|---|---|:---:|---|---|
| `listen.addr` | SocketAddr | ✅ | M3 | QUIC bind address |
| `log_level` | String | — | M1 | reserved (not yet wired) |
| `tls.cert` | PathBuf | — | M6 (future) | PEM loading deferred — v0.3 generates self-signed |
| `tls.key` | PathBuf | — | M6 (future) | same |
| `clients.<id>` | base64 string | — | M6 | per-client Ed25519 pubkey |
| `policy.block_private_ranges` | bool | — | M12 | reject loopback / RFC1918 / link-local |
| `policy.allowed_ports` | `[u16]` | — | M12 | empty = no allowlist constraint |
| `policy.denied_ports` | `[u16]` | — | M12 | takes precedence over allowed |
| `policy.allow_udp` | bool | — | M12 | gate UDP separately |
| `decoy.static_page` | PathBuf | — | M13 (future) | reserved |

### Client

| Field | Type | Required | Milestone | Effect |
|---|---|:---:|---|---|
| `server.addr` | SocketAddr | ✅ | M3 | server QUIC endpoint |
| `server.sni` | String | ✅ | M3 | TLS SNI in handshake |
| `server.cert_sha256` | String | — | M3 | empty = accept-any (lab); else hex SHA-256 pin |
| `identity.client_id` | String | ✅ | M6 | must match an entry in server `clients:` |
| `identity.private_key` | PathBuf | ✅ | M6 | base64 Ed25519 secret key file |
| `socks5.listen` | SocketAddr | ✅ | M9 | SOCKS5 CONNECT listener address |
| `log_level` | String | — | M1 | reserved (not yet wired) |

---

## Quick-start: full local demo

```sh
# 1. Generate alice's keypair
proteus-tools keygen --name alice --out-dir /tmp/keys

# 2. Write server.yaml using the printed pubkey, e.g.:
cat > /tmp/server.yaml <<EOF
listen:
  addr: "127.0.0.1:4433"
clients:
  alice: "$(cat /tmp/keys/alice.pub)"
EOF

# 3. Write client.yaml referencing alice.key:
cat > /tmp/client.yaml <<EOF
server:
  addr: "127.0.0.1:4433"
  sni:  "localhost"
identity:
  client_id: "alice"
  private_key: "/tmp/keys/alice.key"
socks5:
  listen: "127.0.0.1:1080"
EOF

# 4. Run both:
proteus-server --config /tmp/server.yaml &
proteus-client --config /tmp/client.yaml &

# 5. Use the SOCKS5 endpoint:
curl --socks5 127.0.0.1:1080 http://example.com/
```

For UDP, use the `proteus-tools udp-test` subcommand instead of SOCKS5
(v0.3 SOCKS5 frontend is TCP-CONNECT only):

```sh
proteus-tools udp-test --config /tmp/client.yaml \
    --target 127.0.0.1:9998 --payload "hello-udp"
```
