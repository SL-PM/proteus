# Changelog

All notable changes to PROTEUS are tracked here. Pre-1.0 the entry
granularity is per-commit; once we hit 1.0 we move to grouped
release-note style.

## [v0.5.0-rc.1] — 2026-05-28

Wire-pattern padding. Reduces the v0.4 connection-envelope
fingerprint with two opt-in mechanisms (both default off, so v0.4
deployments are unaffected). Design + sign-off:
[`docs/PROTEUS-v0.5-plan.md`](docs/PROTEUS-v0.5-plan.md),
[`docs/m5.5-padding-signoff.md`](docs/m5.5-padding-signoff.md).

**Highlights:**

* **Bucket-padding (M1.5 + M2.5).** Every PROTEUS frame's on-wire
  `payload_len` is rounded up to one of `{128, 256, 512, 1024, 1500}`
  bytes via a new `proteus_core::padding` module + `FLAG_PADDED`
  protocol bit. Padding lives inside the AEAD-sealed block for
  proxy-stream frames; `read_frame` / `read_frame_aead` auto-strip it.
  Wired through server, client, and udp-test via
  `write_frame_*_maybe_padded`. Config: `padding.enabled` +
  `padding.buckets` (both ends, lockstep).
* **Idle dummy traffic (M3.5, server-only).** Bridge send loops emit
  a padded PING after a configurable quiet interval; receive loops
  skip inbound PINGs. Eliminates the "idle = silence" tell. Config:
  `idle_padding.{enabled, interval_secs, bucket}`.
* **Wire-distribution test (M4.5).** `tests/padding.rs` reads
  server→client frames at the raw QUIC level and asserts ≥95% land on
  a bucket (observed 100%: 5/100/300/1000-byte payloads →
  128/128/512/1024). A padding-off control confirms the change is real.

**Known limitations (deferred to v0.5-rc.2):** the 5-bucket
quantization still differs from a real cover host's smooth size
distribution; timing is unchanged; idle PINGs are fixed-rate/size.
Profile-driven sampling (the `fingerprint-profile.yaml` schema is
ready) + timing jitter close A7 in rc.2. `proteus/0.3` ALPN remains
distinctive (v1.0).

146 tests pass (+25 since v0.4.0). fmt + clippy -D warnings clean.

### Commits since v0.4.0

* `3c802dc` docs(m0.5): PROTEUS-v0.5-plan.md — bucket-padding + idle dummies design
* `231a8b8` feat(m1.5): proteus_core::padding — bucket-rounding + FLAG_PADDED protocol
* `367f3c6` feat(m2.5): wire bucket-padding through server + client + udp-test
* `c59a11e` feat(m3.5): server-side idle dummy traffic (constant-rate PING padding)
* `1fb558c` test(m4.5): integration test for wire-level bucket distribution
* `2c51ade` docs(m5.5): v0.5-rc.1 sign-off — bucket padding wire-verified

## [v0.4.0] — 2026-05-27

**Approach C complete.** No code changes vs. v0.4.0-rc.2; this is
the stabilizing release after two RCs with no follow-up issues. The
v0.4.0 tag is the canonical "Approach C done" reference point for
anyone reading the repo or pulling a release artifact.

What v0.4.0 means in practice:

* All M0.4–M9.4 milestones shipped (M1.4 + M2.4 explicitly deferred
  to v1.0 per `docs/m2.4-dispatch-research.md`).
* H3 decoy returns byte-identical body + cover-host-mirrored
  response headers from a snapshot. Closes the v0.4 fingerprint gap
  documented in M9.4 sign-off §2.6.
* Inner ChaCha20-Poly1305 AEAD wraps every proxy-stream frame inside
  the QUIC TLS tunnel, with per-stream subkeys (HKDF over stream-id).
* TLS 1.3 0-RTT enabled at the config layer; replay-safety analysis
  in `docs/m6.4-zero-rtt.md`.
* QUIC connection migration works transparently — `(client_id, nonce)`
  cache survives 5-tuple changes; integration test pins this.
* `proteus-server` refactored into a library + thin bin. Auth +
  migration + 0-RTT regression tests live in
  `crates/proteus-server/tests/`.

Documented residual leaks (v0.5+ work, see CONFIG.md):

* `proteus/0.3` ALPN still distinctive.
* Static-snapshot leaks: `cf-ray`, `__cf_bm` echoed unchanged. True
  fix = live decoy-proxy (Approach B, deferred).
* No wire-pattern padding / timing jitter yet (closes A5, v0.5).

121 tests pass. fmt + clippy -D warnings clean.

### Commits since v0.4.0-rc.2

* `7574650` docs(changelog): v0.4.0-rc.2 entry — M8.4.1 header-mirroring
* (no further code changes — README updated as part of the v0.4.0 polish pass)

## [v0.4.0-rc.2] — 2026-05-27

Single-milestone polish release on top of v0.4.0-rc.1: closes the
H3-decoy response-header divergence documented in the rc.1 sign-off
(`docs/m9.4-rc1-signoff.md` §2.6).

**Highlights:**

* **M8.4.1 — Decoy response-header mirroring.** The H3 decoy now
  echoes the cover host's full header set 1:1 (modulo hop-by-hop +
  stale `date:`). Before: 3 hardcoded nginx-style headers. After:
  27 cloudflare-style headers including `server`, `cache-control`,
  `strict-transport-security`, the full ~3 KB CSP, `link` preload
  hints, `set-cookie`, `alt-svc`, `cf-*`, `x-*` tracking headers,
  `nel`, `report-to`, etc. Plus a fresh per-request `date:`.
* `proteus-tools fetch-decoy --out-headers <path>` — new flag.
  Writes the snapshotted headers as JSON alongside the body. Both
  files are referenced from server config (`decoy.static_headers`).
* Backward-compatible: `static_headers` is optional. Missing =
  M3.4 hardcoded behavior.

**Known residual leaks (honestly documented in CONFIG.md):** some
headers are per-request unique on the real cover host (`cf-ray`,
`__cf_bm` cookie value) and PROTEUS echoes the static snapshot;
some headers are intermittent on the real host but always present
in PROTEUS responses (`server`, `alt-svc`, `nel`, `report-to`).
True fix = live decoy-proxy mode (Approach B in v0.4-plan §6),
v0.5+ work.

121 tests pass (+12 since rc.1). fmt + clippy -D warnings clean.

### Commits since v0.4.0-rc.1

* `5dd2c7e` feat(m8.4.1): decoy response-header mirroring (snapshot + serve)

## [v0.4.0-rc.1] — 2026-05-27

Approach C complete. Adds inner AEAD over PROTEUS frames, TLS 1.3
0-RTT resumption (config-level), connection migration, high-fidelity
H3 decoy snapshotting, and integration-test coverage for all of it.
See [`docs/m9.4-rc1-signoff.md`](docs/m9.4-rc1-signoff.md) for the
formal sign-off + acceptance evidence.

**Highlights:**

* **Inner AEAD wire layer (M5.4 + M5.4.1).** All proxy-stream frames
  are now ChaCha20-Poly1305-sealed inside the QUIC TLS tunnel. Key
  derivation: `HKDF(salt=stream_id_be, ikm=session_key, info=...)`
  to avoid nonce reuse across parallel streams. AAD binds frame
  type / flags / stream id.
* **High-fidelity H3 decoy (M3.4 + M8.4).** The H3 decoy serves
  byte-identical body to a chosen cover host (e.g. cloudflare.com).
  `proteus-tools fetch-decoy --url ... --out file.html` snapshots
  the cover host at deploy time; sign-off verified SHA-256 match
  against a live cloudflare.com fetch.
* **TLS 1.3 0-RTT (M6.4).** Server opts in via
  `MAX_EARLY_DATA_BYTES = u32::MAX` (Quinn requires this exact
  value or 0); replay-safety analysis documented. Live happy-path
  trigger deferred; regression test in place.
* **Connection migration (M7.4).** Quinn default + PROTEUS's
  client-id-keyed cache makes 5-tuple changes free. Integration
  test verifies an active proxy stream survives `endpoint.rebind()`.
* **PEM cert+key loading (M4.4).** Previously self-signed-only.
* **Server-as-library refactor (M9.4).** `proteus-server::Server`
  exposes `bind`/`run`/`shutdown`/`metrics()` so integration tests
  spin the server up in-process. Bin shrunk 708 → ~80 lines.
* **Three new integration test binaries** in
  `crates/proteus-server/tests/`: auth smoke, migration, 0-RTT.
* **CONFIG.md** gets a "high-fidelity decoy" section walking
  operators through the fetch-decoy + decoy.static_page flow.

**Deferred (documented):**

* M1.4 + M2.4 (ALPN unification / first-frame discriminator) —
  infeasible without forking h3 or writing a mini-h3 server, see
  [`docs/m2.4-dispatch-research.md`](docs/m2.4-dispatch-research.md).
  Re-classified as v1.0-scope.
* Decoy response *header* mirroring — body is byte-identical, but
  headers still nginx-style. v0.5.
* Deterministic real-0-RTT acceptance test (rustls ticket-cache
  timing). Not blocking — production short-lived-client scenario
  doesn't exist yet for PROTEUS.

109 tests pass (91 core + 12 tools + 6 server integration).
fmt + clippy -D warnings clean.

### Commits since v0.3.0-rc.1 (oldest first)

* `3b1e76a` docs(v0.4): PROTEUS-v0.4-plan.md design draft
* `c35292b` feat(m4.4): PEM cert+key loading for proteus-core::tls
* `7288baf` feat(m5.4): inner AEAD primitives (proteus-core::aead)
* `02e70a2` docs(m7.4): connection migration — Quinn default + replay-cache design
* `5be0025` feat(m3.4): high-fidelity decoy — nginx welcome page + headers + file override
* `a605eaa` docs(m2.4): dispatch research — Approach C as written is infeasible
* `5e67bc8` feat(m6.4): enable TLS 1.3 0-RTT resumption (config-level)
* `a3c20ba` feat(m5.4.1): wire-format AEAD wrapping for all proxy-stream frames
* `330e5e1` feat(m8.4): proteus-tools fetch-decoy — snapshot cover-host index for H3 decoy
* `97fc809` feat(m9.4): server-as-library refactor + auth/migration/0-RTT integration tests
* `6a337e8` docs(m9.4): v0.4-rc.1 sign-off — high-fidelity decoy proven byte-identical

## [v0.3.0-rc.1] — 2026-05-27

Initial PROTEUS v0.3 research-prototype release. Protocol-complete
per [`docs/PROTEUS-spec-v0.2.md`](docs/PROTEUS-spec-v0.2.md), with
the M14 sign-off (capture comparison report) included.
AGPL-3.0-or-later licensed.

**Highlights:**

* QUIC + TLS 1.3 transport with exporter-bound Ed25519 client auth
  (M5 + M6).
* TCP and UDP proxying over per-target QUIC streams (M8 + M10).
* SOCKS5 CONNECT frontend on the client (M9).
* Server-side policy engine — block-private-ranges, port allow/deny,
  UDP gate (M12).
* Per-IP auth rate limit + replay-cache + frame-decode fuzz (M7,
  M18, M18.1).
* Local HTTP/3 decoy on ALPN `h3` (M13).
* Runtime metrics counters surfaced every 30s to stderr (M17).
* Capture tooling under `scripts/` + comparison report against real
  HTTP/3 baseline (M14 + M15).

73 tests, fmt + clippy clean. See
[`docs/THREAT-MODEL-v0.3.md`](docs/THREAT-MODEL-v0.3.md) for what
v0.3 actually defends against vs. what stays out-of-scope until
v0.4 (REALITY upstream forwarding) / v0.5 (padding + timing) /
v1.0 (post-quantum).

### Commits since project start (oldest first)

* `0945f43` chore: bootstrap proteus repo with v0.2 spec and M0 workspace
* `e3f2221` chore: commit Cargo.lock
* `febcbed` feat(spike): M5 TLS exporter spike — MATCH, Path A confirmed
* `90a9009` feat(m1): YAML config + clap CLI for server and client
* `e824c48` feat(m2): proteus-tools keygen subcommand
* `ddfc63e` feat(m3): basic QUIC ping/pong server and client
* `3b7cb71` feat(m4): frame envelope codec + framed PING/PONG over QUIC
* `1e72ad3` feat(m6): exporter-bound Ed25519 auth on the control stream
* `1cf9625` feat(m7): replay cache for AUTH_REQUEST nonces
* `af6ecab` chore(core): drop unused exporter helpers from tls.rs
* `e61ac15` feat(m8): TCP proxy over QUIC + CBOR PROXY_OPEN
* `b5adea8` feat(m9): SOCKS5 CONNECT frontend for the client
* `b64fc36` feat(m10): UDP proxy over QUIC + proteus-tools udp-test
* `14fe301` feat(m12): server-side policy engine
* `e8315af` chore(m5): remove exporter-spike throwaway binary
* `f43f950` docs: mark M11 implicit, add CONFIG.md reference
* `f23447a` docs(m16+m19): fingerprint profile schema + PQ feasibility note
* `78442b7` feat(m17): runtime metrics counters + periodic snapshot
* `b8289cc` feat(m18): connection idle timeout + AUTH_REQUEST read timeout
* `607002b` docs(m14): invalid-client handling — status and acceptance criteria
* `1fcef72` feat(m15): capture tooling for PROTEUS vs HTTP/3 comparison
* `4b97e2b` feat(m13): local HTTP/3 decoy on ALPN h3
* `9c9fb1f` feat(m18.1): per-IP auth rate limiter + Frame::decode fuzz test
* `66e2975` docs(readme): sync to v0.3 protocol-complete state
* `ece1847` docs: OPEN-ITEMS.md — checklist of manual actions for the operator
* `cfb9b33` docs(open-items): drop section D (VPN-infra carryover all resolved)
* `ac66d3f` docs(m14): comparison report from local capture run
* `573344d` docs(open-items): mark A1 (M14 sign-off) as done — history note
* `f9d0052` chore: license under AGPL-3.0-or-later
