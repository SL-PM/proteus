# M5 Spike Result — TLS Exporter Material

**Date:** 2026-05-26
**Roadmap:** [`ROADMAP-v0.3.md`](ROADMAP-v0.3.md) §M5
**Binary:** _Removed post-M6._ (Lived at `crates/proteus-tools/src/bin/exporter-spike.rs`; see commit history.)
**Result:** ✅ **Path A — exporter works.** Spec v0.2 unchanged. M6 unblocked.

## Setup

- Quinn 0.11.9
- rustls 0.23.40 (ring crypto provider)
- rcgen 0.13.2 (self-signed cert with SAN `localhost`)
- ALPN `proteus/0.3-spike`
- Exporter label `EXPORTER-PROTEUS-v0.3`, empty context, 32-byte output

In-process server + client, loopback over `127.0.0.1`.

## Run

```
$ cargo run --bin exporter-spike
server bound to 127.0.0.1:59062
client exporter: 0e313d4d16baae22e833a24c2d00eb67211e28be66b8c7e88ca23f262280790c
server exporter: 0e313d4d16baae22e833a24c2d00eb67211e28be66b8c7e88ca23f262280790c
---
MATCH: both sides derived identical exporter bytes.
```

## Conclusion

`quinn::Connection::export_keying_material(&mut [u8; 32], label, b"")`
returns the same 32 bytes on both sides of a TLS 1.3 QUIC handshake when
called with identical `(label, context)`. RFC 5705 binding works as
intended.

Implication for the spec: no changes to `PROTEUS-spec-v0.2.md` §7.3
(AUTH_REQUEST signature input) or §8.2 (post-handshake auth flow). The
M5 Plan B (transcript-hash fallback) is not needed.

## Next

Proceed in roadmap order: M1 (Config) → M2 (Keygen) → M3 (Basic QUIC) →
M4 (Frame Codec) → M6 (Auth, reusing the exporter API exercised here).

The `exporter-spike` binary was removed once M6's real auth path was
verified end-to-end through `proteus-client` / `proteus-server`. This
doc remains as the M5 historical record.
