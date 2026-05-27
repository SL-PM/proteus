# PROTEUS v0.4 — Plan

**Status:** DESIGN DRAFT — not all items below are committed to.
**Supersedes for next iteration:** [`PROTEUS-spec-v0.2.md`](PROTEUS-spec-v0.2.md).
**Date:** 2026-05-27 (start of v0.4 design)

> ⚠️ Read this first. v0.4 is where PROTEUS earns the "PR" in its name —
> the v0.3 prototype is DPI-detectable by design; v0.4 is the milestone
> that closes that gap. The hard problem is REALITY-style upstream
> forwarding adapted to QUIC, and it has non-obvious crypto and
> packet-handling subtleties. This document captures the design
> decisions before any v0.4 code lands.

---

## 1. What v0.4 fixes (vs v0.3)

Threat-model items v0.3 explicitly left out of scope, ordered by what
v0.4 should close:

| Adversary | v0.3 status | v0.4 target |
|---|---|---|
| A5 DPI / protocol fingerprinter | ✗ | **partial** — close the obvious ALPN + cert tells; the timing + size fingerprint stays a v0.5 problem |
| A6 Active prober with cert inspection | ✗ | **closed** — by upstream forwarding, the cert a prober sees IS the cover host's |
| A7 Statistical traffic analysis | ✗ | still ✗ (v0.5) |
| A8 IP-level censor | ✗ | still ✗ (v0.5 port hopping; v1.0 IP rotation) |
| A9 Quantum | ✗ | still ✗ (v1.0) |

v0.4 is therefore primarily an **A5 + A6** milestone, plus a handful of
QUIC-native features (0-RTT, migration, inner AEAD) that round out
production-readiness without protocol redesign.

---

## 2. v0.4 Goals (the full list)

From [`PROTEUS-spec-v0.2.md`](PROTEUS-spec-v0.2.md) §12 migration path:

1. **REALITY-style upstream forwarding.** Server transparently
   forwards non-PROTEUS QUIC traffic to a real cover host, so a
   prober sees the cover host's actual cert and behavior.
2. **Drop the `proteus/0.3` distinctive ALPN.** Server advertises only
   `h3` (and/or `h3-29`, etc., matching the cover host).
3. **0-RTT resumption** with explicit replay-safety analysis.
4. **Connection migration** — wire up Quinn's native support behind
   PROTEUS-level session-ID handling.
5. **Inner AEAD layer** over PROTEUS frames, on top of the QUIC TLS
   layer. Defense-in-depth.

---

## 3. v0.4 Non-Goals (still deferred)

| Feature | Still deferred to | Reason |
|---|---|---|
| Hybrid X25519 + ML-KEM-768 KEM | v1.0 | PQ is its own crypto-review milestone |
| Port hopping | v0.5 | Operationally complex; orthogonal |
| SNI rotation | v0.5 | Operational |
| Padding distributions + timing jitter | v0.5 | Needs corpora + matching machinery |
| Fingerprint passing baseline | v0.5 | The success-metric for v0.5 |

---

## 4. The hard problem: REALITY-on-QUIC

### 4.1 What REALITY does for TCP+TLS

In Xray-core's REALITY:

1. Client connects, sends a TLS ClientHello whose `session_id` field
   carries a covert authenticator (typically a short Ed25519
   signature or HMAC of a static secret).
2. Server intercepts the ClientHello before completing the TLS
   handshake. Two paths:
   - **Authenticator valid** → server completes the TLS handshake
     itself using a key it controls, and the connection becomes a
     normal VLESS/Vmess session. The cert the client *sees* is one
     the server crafted to match the cover host's identity (using
     the real cover host's public key but the server's signing
     key — a deliberate cert-validation-skip on the client side).
   - **Authenticator invalid or absent** → server TCP-proxies the
     entire connection to the real cover host, byte-for-byte. The
     prober finishes a TLS handshake with the cover host directly.
3. Net effect: the prober cannot distinguish PROTEUS-server from a
   passive reverse proxy, because indistinguishability is enforced
   *by actually being* a reverse proxy for non-authenticated traffic.

### 4.2 What changes for QUIC

QUIC's TLS 1.3 handshake lives inside the QUIC Initial packet, whose
payload is encrypted with a key derived from the connection's
*publicly-visible* destination connection ID. So:

* **Good news:** the server *can* decrypt the Initial packet and read
  the ClientHello without owning the cover host's private key. The
  authenticator-in-ClientHello trick from TCP REALITY still works.
* **Bad news:** completing the QUIC TLS 1.3 handshake produces session
  keys that are bound to the *server's* cert. If we want the prober
  (or even a legitimate non-PROTEUS client) to see the cover host's
  cert and a working TLS session terminated *by the cover host*, we
  cannot terminate the QUIC connection locally for that traffic. We
  must UDP-relay the QUIC packets to the cover host.
* **Worse news:** for legitimate PROTEUS clients we *want* to
  terminate locally (otherwise we have no PROTEUS session to wrap
  proxy streams in). So the server has to make the keep-or-forward
  decision very early — from the first Initial packet — and stick
  with it.

### 4.3 Three possible approaches

#### Approach A — Full REALITY-for-QUIC

The Xray approach adapted: server peeks at the Initial packet, reads
the ClientHello, checks the covert authenticator.

- Valid: terminate locally with a *crafted* cert that uses the cover
  host's public key but the server's private key. The PROTEUS client
  must be willing to skip standard cert validation in favor of
  pinning the cover host's pubkey out-of-band.
- Invalid: UDP-relay every packet for this connection-ID 5-tuple to
  the cover host. Bidirectional, until the connection closes.

**Pros:** strongest indistinguishability, matches Xray-REALITY behavior.
**Cons:** requires the server to construct a cert with the cover
host's public key. Most QUIC stacks (including Quinn) do not have
APIs for that today. Likely requires forking Quinn or implementing
custom TLS hooks. Substantial.

#### Approach B — Cover-host relay + same-cert PROTEUS

The server actually obtains a CA-signed cert *for the cover host's
domain* (impossible) OR a CA-signed cert for a domain the server
controls that *looks like* the cover host (e.g.,
`fastly.cdnnetwork.example.com` — plausible CDN-name). Server then
advertises only `h3` and:

- Connections that start with a valid PROTEUS auth-tag in their
  ClientHello → terminate locally with the server's own cert
  (different cert from the cover host, but at least not the
  self-signed `localhost` cert v0.3 ships).
- Connections without the tag → UDP-relay to the cover host (or
  serve a local high-fidelity decoy that copies the cover host's
  index page).

**Pros:** doesn't require Quinn-internal crypto hacks. The server's
cert is real (CA-signed), just not the same as the cover host's.
**Cons:** weaker than REALITY — a prober comparing the server-side
cert against the cover host's cert directly will spot it. Mitigated
by the cert being "plausible CDN-name" rather than obviously wrong.

#### Approach C — ALPN unification + better local decoy

The cheapest path: keep the v0.3 architecture, but:

- Drop the `proteus/0.3` ALPN. Server advertises only `h3`.
  Distinguish PROTEUS at the first-frame level (auth_request as the
  first frame on the first bidi stream = PROTEUS; H3 SETTINGS frame
  = decoy).
- Replace the v0.3 "It works." placeholder decoy HTML with a
  high-fidelity copy of a real cover host's index page (fetched once
  at deploy time, served with matching headers).

**Pros (as originally written):** minimal code change (~200 lines).
No Quinn forks. No upstream cover host required at runtime.
**Cons (as originally written):** the server's cert is still its own
— a prober checking the cert sees something that isn't the cover
host. Only mitigates A5 (ALPN tell), not A6 (cert tell).

> **2026-05-27 finding:** the "first-frame on first bidi stream"
> discriminator doesn't survive RFC 9114 §6.2 — H3's first stream
> from a client is *unidirectional* (control + SETTINGS), not bidi.
> A naïve `accept_uni() vs accept_bi()` race in tokio::select is
> also blocked: Quinn has no peek API, so consuming the H3 control
> stream prevents `h3::server::Connection` from ever seeing
> SETTINGS. Full analysis in
> [`m2.4-dispatch-research.md`](m2.4-dispatch-research.md). The
> realistic alternatives (mini-h3 server / fork `h3` / PROTEUS-over-h3)
> are all larger than the original "~200 LOC" estimate. **Approach C
> as written is deferred; bundle the ALPN drop with Approach B's
> cover-host forwarding in v0.4-rc.2 or later.**

### 4.4 Recommended v0.4-rc.1 scope

**Approach C as v0.4-rc.1**, then revisit B or A for v0.4-rc.2 / v0.4
final based on how much engineering effort proves available.

Rationale:
- Approach C ships in ~1 session, closes A5 partially, and gives a
  stable wire format that we can iterate from.
- Approaches A and B both require either Quinn-internal hacks or
  acquiring a real CA-signed cert. Treat as separate engineering
  blocks.
- The 0-RTT / migration / inner-AEAD goals are independent of which
  approach we pick for upstream forwarding and can land in parallel.

---

## 5. Architecture changes

```text
v0.3 server                          v0.4 server (Approach C)
─────────────                        ────────────────────────
QUIC accept                          QUIC accept
  ├─ ALPN proteus/0.3 → auth path      ├─ ALPN h3 (always)
  └─ ALPN h3 → local decoy             └─ first-frame switch:
                                          ├─ PROTEUS auth → auth path
                                          └─ H3 SETTINGS → high-fidelity decoy
```

For Approaches A and B, the diagram grows a third branch (UDP-relay
to cover host) and the decision point moves earlier (Initial-packet
peek, before handshake completion).

---

## 6. Wire format changes

### 6.1 ALPN

* **Server advertises** `h3` only.
* **Client advertises** `h3` only.

The `proteus/0.3` ALPN value used in v0.3 is retired. Old v0.3
clients will fail to connect to v0.4 servers; v0.4 clients fail to
connect to v0.3 servers. This is a deliberate compat break — v0.3
was a research prototype.

### 6.2 Frame envelope

Unchanged from v0.3 spec §7.2. The 16-byte header survives.

### 6.3 First-frame discriminator

After the QUIC handshake completes and the client opens its first
bidi stream, the first frame is one of:

* **`AUTH_REQUEST` (0x0001)** → PROTEUS client. Continue with the
  v0.3 §8.2 auth flow (exporter-bound Ed25519, replay-cache,
  policy, per-target streams).
* **Anything else** (specifically H3's SETTINGS frame at the
  start) → real H3 client. Hand the connection to the decoy.

This is already structurally similar to v0.3's M13 + auth dispatch
in `handle_conn`; v0.4 just makes the ALPN identical instead of
relying on the ALPN as the dispatch signal.

### 6.4 Inner AEAD (Approach C + add-on)

After successful auth, all subsequent PROTEUS frames are wrapped in
an additional ChaCha20-Poly1305 AEAD layer. The key is derived from:

```
inner_key = HKDF(salt=exporter, ikm=session_nonce, info="PROTEUS-v0.4-inner-aead")
```

Each frame gets a 12-byte nonce (8-byte big-endian counter, 4-byte
context). 16-byte tag follows the payload.

Rationale: a defense-in-depth layer if either the QUIC TLS layer is
broken or the prober gains a transport-key-recovery primitive in the
future. Effectively cheap on modern CPUs.

### 6.5 0-RTT resumption

QUIC's 0-RTT is enabled. The PROTEUS-level concern is replay-safety
of the AUTH_REQUEST. Mitigation: when a connection arrives over 0-RTT,
the server rejects AUTH_REQUESTs that *would not also be rejected by*
the replay cache. The 0-RTT data buffer is held until 1-RTT keys are
established before any side-effect (proxy connect). Detailed
analysis in §8 of this doc.

### 6.6 Connection migration

QUIC's PATH_CHALLENGE / PATH_RESPONSE handles this transparently.
PROTEUS's per-client `(client_id, nonce)` cache is keyed on
client_id, not 5-tuple, so the cache survives an IP/port change.
**Implementation cost: minimal** — just don't fight Quinn on it.

---

## 7. Operator-visible changes

### 7.1 Server config additions

```yaml
# New v0.4 sections — non-breaking add to the v0.3 schema.

cover:
  host: "www.cloudflare.com"     # Approach A/B: where to relay
  fetch_decoy_on_startup: true   # Approach C: snapshot the cover
                                 #             host's index for the decoy

# (PEM cert loading from M6, deferred since v0.3, lands here.)
tls:
  cert: "/path/to/cert.pem"
  key:  "/path/to/key.pem"
```

For Approach C the `cover.host` is only used at startup (to fetch
the decoy HTML). For Approaches A/B it's used at every connection.

### 7.2 Client config additions

No required changes for Approach C. Approach A/B may require a new
field `server.cover_host_pubkey_pin` for cert pinning, since the
server-side cert is no longer the same as `cert_sha256` for the
PROTEUS-path cert.

---

## 8. Open questions

1. **Which approach for the cover host?** A (full REALITY), B
   (relay with own cert), or C (ALPN-only + high-fidelity decoy)?
   This doc recommends C for v0.4-rc.1 and revisits later.
2. **Cover-host upstream forwarding mechanism for Approaches A/B.**
   The server must UDP-relay packets keyed on the QUIC connection ID
   (and its derivatives). Quinn does not expose Initial-packet
   inspection directly; this likely needs a `quinn::Endpoint`
   subclass / wrapping UDP socket.
3. **PEM cert loading (carry-over from v0.3 M6).** Lands here, but
   the design is small — `rustls`'s `with_single_cert` already
   accepts PEM-loaded DER bytes; just wire up the config field.
4. **0-RTT replay safety formal analysis.** v0.3 spec §13 listed
   this as open; v0.4 needs to commit to a position. Likely: 0-RTT
   data is buffered until 1-RTT, and AUTH_REQUEST is treated as
   replay-cache-checked even in 0-RTT.
5. **Inner AEAD key derivation.** The proposed HKDF input
   (`salt=exporter, ikm=session_nonce`) is one option. An
   alternative is to derive from the AUTH_RESPONSE payload bytes.
   To be confirmed against a crypto-review.
6. **High-fidelity decoy fetching (Approach C).** Should the server
   re-fetch periodically, or snapshot once at deploy time? Once is
   simpler but stale; periodic fetch needs a config field for the
   interval.

---

## 9. Milestones (v0.4)

Numbered M0.4-style to avoid clashing with v0.3's M0-M19.

| | Milestone | Approach | Effort |
|---|---|---|---|
| M0.4 | v0.4-dev branch + plan-doc lands | C | small |
| M1.4 | Drop `proteus/0.3` ALPN; server advertises only `h3` | C → B/A | **deferred** — see [m2.4-dispatch-research.md](m2.4-dispatch-research.md) |
| M2.4 | First-frame discriminator (AUTH_REQUEST vs H3 SETTINGS) | C → B/A | **deferred** — original design infeasible w/o h3 fork or mini-h3 server |
| M3.4 | High-fidelity decoy: configurable static HTML + headers ✅ | C | small |
| M4.4 | PEM cert loading (M6 carry-over) | C | small |
| M5.4 | Inner AEAD primitives (`aead::InnerAead`, key derivation, per-stream subkeys) ✅ | C | medium |
| M5.4.1 | Wire-format AEAD wrapping: all proxy-stream frames go through `read_frame_aead` / `write_frame_aead`; AAD binds `(frame_type, flags, stream_id)`; TCP+UDP smoke pass ✅ | C | medium |
| M6.4 | 0-RTT resumption + replay-safety analysis ⚠️ config-only; integration test → M9.4. See [`m6.4-zero-rtt.md`](m6.4-zero-rtt.md) | C | medium |
| M7.4 | Connection migration (mostly Quinn) ✅ — see [`m7.4-connection-migration.md`](m7.4-connection-migration.md) | C | small |
| M8.4 | Operator-facing fetch-decoy utility (`proteus-tools fetch-decoy`) ✅ | C | small |
| M9.4 | v0.4-rc.1 sign-off: server-as-library refactor + integration tests + decoy comparison ✅ — see [`m9.4-rc1-signoff.md`](m9.4-rc1-signoff.md) | C | medium |
| M10.4 | (stretch) Approach B: own real cert for proxy host | B | large |
| M11.4 | (stretch) Approach A: REALITY-style upstream relay | A | very large |

**v0.4-rc.1 = M0.4 through M9.4.** M10.4 and M11.4 are stretch
goals for v0.4-rc.2 / v0.4-final.

---

## 10. Migration impact

### What breaks for existing v0.3 clients

* v0.3 clients use `proteus/0.3` ALPN. v0.4 servers reject this
  (only `h3` advertised). v0.3 clients cannot connect to v0.4
  servers.
* No way to bridge — clients must upgrade.

### What breaks for existing v0.3 server operators

* `proteus/0.3` is gone from the server config implicitly. No config
  change required to migrate, but they need a v0.4 client.
* New optional sections in the YAML (`cover:`, `tls:`); old configs
  without them keep working in Approach-C mode.

### What stays the same

* `clients:` map format (M2 keygen format unchanged).
* `policy:` engine semantics (M12 unchanged).
* `socks5.listen` on the client (M9 unchanged).
* Wire format of PROTEUS frames inside QUIC (M4 unchanged, M5.4
  optionally wraps them in an inner AEAD).

---

## 11. Roadmap: v0.4 → v0.5 → v1.0

```text
v0.4 (this plan)
  └── Close A5 partially + A6 (with stretch goals A/B)
  └── 0-RTT, migration, inner AEAD
        │
        ▼
v0.5
  ├── Padding profiles + timing jitter (close remaining A5)
  ├── SNI rotation
  ├── Port hopping
  └── Fingerprint comparison passing baseline (A5 fully closed)
        │
        ▼
v1.0
  ├── Hybrid X25519 + ML-KEM-768 (A9)
  ├── External crypto review complete
  └── Production-readiness statement
```

---

## 12. Acceptance criteria for v0.4-rc.1

When all of these are true, v0.4-rc.1 is taggable:

1. Server starts with v0.3 OR v0.4 YAML config (additive change).
2. Server advertises only `h3` in ALPN.
3. Real H3 client (curl --http3) gets a high-fidelity decoy
   response that visually matches the cover host's response.
4. PROTEUS client (the v0.4 release of proteus-client) does the
   first-frame switch correctly.
5. Inner AEAD wraps DATA frames; integration smoke confirms
   bidirectional flow over the wrapped layer.
6. PEM cert loading works; the integration test no longer ships
   the self-signed `localhost` cert.
7. 0-RTT resumption integration test passes; replay-safety
   documented in this file's §8.
8. Connection migration integration test passes (client switches
   source port mid-flight; session continues).
9. M9.4 sign-off: a comparison report against the cover host shows
   the only remaining tell is timing/size (deferred to v0.5).
10. All 73 v0.3 tests still pass + new v0.4 tests; fmt + clippy clean.
11. CHANGELOG.md updated.
12. README mentions v0.4 status and the rc.1 tag.

---

## What is NOT in v0.4

For completeness — these stay deferred:

- Post-quantum crypto (A9 → v1.0).
- Padding distributions and timing jitter (A7 partial → v0.5).
- Port hopping and IP rotation (A8 → v0.5 + operational).
- Multi-tenant cover-host pools (operational).
- Production-grade observability beyond stderr metrics snapshots
  (operational).

---

## Notes for the reader

This is a *plan* document, not a *spec*. The spec for what v0.4 will
actually do, once design is locked, lands as
`docs/PROTEUS-spec-v0.4.md` (analogous to how v0.2 was the spec for
v0.3). Until then, treat the design choices above as proposals open
to revision once we start coding M1.4 and discover the first
ground-truth blocker.
