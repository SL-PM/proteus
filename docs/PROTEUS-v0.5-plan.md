# PROTEUS v0.5 — Wire-Pattern Padding (plan)

> **Status:** Design draft, no code yet.
> **Roadmap context:** [`PROTEUS-v0.4-plan.md`](PROTEUS-v0.4-plan.md) §11
> places v0.5 as "Padding profiles + timing jitter (close remaining
> A5), SNI rotation, Port hopping, Fingerprint comparison passing
> baseline." This plan narrows that scope to the rc.1-shippable
> subset and explicitly defers the rest.

---

## 1. What v0.5 closes

v0.4 left the connection envelope (ALPN, packet sizes, idle behavior)
recognizable as PROTEUS even with byte-identical decoy bodies and
mirrored cover-host headers:

| Adversary | v0.4 status | v0.5-rc.1 target |
|---|---|---|
| A5 active DPI / wire-pattern fingerprint | partial — covered inside the tunnel via AEAD, but per-frame sizes + idle silence still leak | **partial → mostly closed** — bucket-pad frames, fill idle with cover-rate dummies |
| A7 statistical traffic analysis | ✗ | **partial** — bucket-padding eliminates per-frame size leak; full profile-matching deferred |
| A8 IP-level censor | ✗ | still ✗ (port hopping → v0.5-rc.2 or later) |
| A6, A9, A10, A11 | unchanged | unchanged |

v0.5-rc.1 is therefore a focused **A5 + partial-A7** milestone. It does
NOT claim to defeat a motivated statistical attacker — that needs
profile-driven sampling + timing jitter calibrated against a real
trace corpus, both deferred (see §3).

## 2. v0.5-rc.1 goals (the full list)

1. **Bucket-pad every PROTEUS frame on the wire** to one of a small
   fixed set of sizes. Eliminates per-frame size information.
2. **Constant-rate idle dummy frames.** Server emits a small dummy
   frame at a configurable interval during periods with no real
   traffic. Eliminates the "PROTEUS-idle = total silence" signal.
3. **Both directions, all frame types** (auth-stream + proxy-stream
   alike). Auth frames are the most fingerprint-rich single packets,
   so leaving them un-padded would be self-defeating.
4. **Test coverage** for the wire-level invariants (every emitted
   frame size ∈ allowed bucket set; padding round-trips
   transparently; receiver doesn't see padding bytes in payload).
5. **Sign-off comparison.** Re-run the M14-style capture against a
   v0.5 deployment + the cover host; document the residual gap.

## 3. v0.5-rc.1 non-goals

| Feature | Why deferred |
|---|---|
| Cover-profile-driven size sampling | Needs trained distributions from real captures; the [`fingerprint-profile.example.yaml`](fingerprint-profile.example.yaml) schema is ready but the matching machinery + corpus aren't. v0.5-rc.2 candidate. |
| Inter-arrival timing jitter | Same — needs profile data + scheduler. rc.2. |
| Periodic per-stream re-keying | Useful but separate. rc.2 or v0.6. |
| SNI rotation | Operational, orthogonal. rc.2 or v0.6. |
| Port hopping | Operational, large infra impact. v0.6+. |
| Hybrid X25519 + ML-KEM | v1.0. |

## 4. Design decisions

Choices recorded here so the rc.1 implementation doesn't have to
re-derive them at every site. Defaults are the recommendation.

### 4.1 Padding strategy

**Bucket-padding** with a fixed power-of-2-ish allowlist:

```
{ 128, 256, 512, 1024, 1500 }  bytes (post-header, pre-tag)
```

- The smallest bucket (128) comfortably fits one AUTH_REQUEST.
- The largest (1500) is the IPv4 MTU-minus-overhead — fits a full
  TCP payload chunk from the M5.4.1 bridge (8192-byte `BRIDGE_BUF_SIZE`
  → split into multiple bucket-sized frames if needed).
- Why not just always 1500? Pure 1500-byte frames are themselves a
  fingerprint — real H3 traffic has a non-trivial small-frame tail.
- Why not finer-grained? Each new bucket adds one wire-observable
  size class; five is enough for the size distribution to be
  plausible, few enough to be cheap to reason about.

Frames larger than 1500-MTU are NOT supported by v0.5-rc.1. The
M5.4.1 TCP bridge already splits to 8 KiB and frames AEAD-wrap with
+16 B tag; we may need to drop `BRIDGE_BUF_SIZE` to ~1450 to keep
the encrypted frame ≤ 1500. Detail decided at implementation time.

### 4.2 Idle dummy traffic

**Constant-rate** dummy frames:
- Server sends one PING (frame type 0x0030) at every
  `DUMMY_INTERVAL` (default: 5 seconds) of stream-quiet time.
- PING payload is a random bucket-sized blob; receiver discards
  silently (PING already has no defined semantics in v0.3 spec).
- Client side: opt-in via config; server still emits even if client
  doesn't (the asymmetry matches H3 idle patterns where the server
  occasionally PINGs).

### 4.3 Overhead budget

Targeting **10–30% bandwidth overhead** in practical workloads:

- Bucket-padding cost: depends on real frame-size distribution. For
  the M5.4.1 TCP bridge with 8192-byte chunks → 8 KiB ÷ 1500 ≈ 6
  bucket-1500 frames + 1 bucket-1024 frame, vs. raw 6×1500 + 1×704.
  Overhead is the rounding-up of the last frame ≈ ~320 B / ~8 KiB
  = ~4% on bulk transfer.
- For tiny request/response patterns (e.g. a 50-byte HTTP HEAD),
  overhead is much higher relative — 50 B → 128 B = 156% local cost,
  but absolute cost is tiny.
- Idle PING cost: 1500 B × (1 / 5 s) = 300 B/s = 0.3 KB/s. Trivial
  in normal usage; visible in a fully-idle session.

Operators trading throughput for tarnish quality at v0.5-rc.2+ can
configure a smaller bucket set or longer DUMMY_INTERVAL.

### 4.4 Wire format

**No header layout change.** v0.5 reuses the v0.4 16-byte frame
header. Padding is signaled via a new bit in the existing `flags`
field, and the padding byte count is carried inside the payload:

```
flags bit 0x0001 = PADDED
```

When PADDED is set:
- `payload_len` (in header) = bucket size — includes both real
  payload and padding + 2-byte trailer.
- Last 2 bytes of `payload` = `padding_len: u16 big-endian` — bytes
  of padding NOT counting the 2-byte trailer itself.
- Real payload = `payload[.. payload_len - 2 - padding_len]`.

Round-trip:
```
encode_padded(frame, bucket):
    n_real      = frame.payload.len()
    target      = bucket - 2 - n_real     # padding bytes needed
    padded      = real || zeros(target) || u16_be(target)
    out.flags  |= 0x0001
    out.payload = padded                  # length = bucket
    return out

decode(frame):
    if flags & 0x0001:
        payload_len  = frame.payload.len()
        padding_len  = u16_be(frame.payload[payload_len-2 ..])
        real         = frame.payload[.. payload_len - 2 - padding_len]
        return real
    else:
        return frame.payload
```

Both endpoints must agree on padding. v0.4 servers presented with a
padded v0.5 frame would misinterpret the trailing bytes as real
payload — so v0.5 is a **non-rolling** upgrade: bump both ends
together. (This is acceptable because PROTEUS deployments are
typically operator-controlled.)

For AEAD-wrapped frames (M5.4.1 proxy stream), the padding lives
inside the AEAD-sealed block, so an on-wire observer sees only the
bucket size — they can't see "the real payload was 50 bytes, the
rest is zeros". For unencrypted control-stream frames
(AUTH_REQUEST/RESPONSE), the padding is structurally visible to a
wire observer who knows the format, but the bucket-size choice
itself is the fingerprint elimination.

### 4.5 Configuration (additive YAML)

```yaml
# v0.5 additions to server.yaml and client.yaml. Default = off.

padding:
  enabled: true                  # opt-in per deployment
  buckets: [128, 256, 512, 1024, 1500]   # override the default set if desired

# Server-only:
idle_padding:
  enabled: true
  interval_secs: 5               # one dummy frame per N seconds of stream-quiet time
  bucket: 1024                   # which bucket to use for the dummy
```

If `padding.enabled` is false, every code path behaves exactly as
v0.4 — full backward compatibility within a deployment.

## 5. Acceptance criteria for v0.5-rc.1

When all true → v0.5-rc.1 taggable:

1. New `proteus_core::padding` module with bucket-rounding + the
   PADDED flag protocol. Round-trip tests.
2. Frame encode-side: every emitted proxy-stream frame goes through
   the padding wrapper when `padding.enabled = true`.
3. Frame decode-side: PADDED flag transparently stripped before
   `payload` reaches application code.
4. Server-side idle-padding timer per active stream emits dummy
   PING frames at the configured rate.
5. Integration test: send a 50-byte request through the SOCKS5
   client, observe at the QUIC wire level that ≥ 95% of emitted
   PROTEUS frames have one of the 5 allowed bucket sizes.
6. Sign-off doc with manual capture comparison (M14-style) of:
   - v0.5 PROTEUS session
   - real H3 fetch of the cover host
   showing the **packet-size distribution** is meaningfully closer
   than v0.4 (quantified as histogram bin overlap or similar).
7. No regression: all 121 v0.4 tests still pass with `padding.enabled
   = false`.

## 6. Milestone matrix

| | Milestone | Effort |
|---|---|---|
| M0.5 | v0.5 plan doc + branch ✅ | small |
| M1.5 | `proteus_core::padding` module + bucket-rounding logic + PADDED-flag encode/decode ✅ | small |
| M2.5 | Wire-up: client + server pad/un-pad every proxy-stream frame when config opt-in ✅ | small |
| M3.5 | Idle-padding timer + dummy PING emission (server side) ✅ | small |
| M4.5 | Integration test verifying bucket distribution + no-regression sweep ✅ | small |
| M5.5 | Sign-off: wire-distribution evidence + [`m5.5-padding-signoff.md`](m5.5-padding-signoff.md) ✅ | small |

**v0.5-rc.1 = M0.5 through M5.5, all complete.** Profile-driven
sampling (rc.2) and SNI rotation / port hopping (rc.2 / v0.6) remain
deferred per §3.

Total: ~5 commits, ~1-2 sessions for a complete rc.1.

### v0.5-rc.2 milestones (timing jitter)

Design in §11. Closes the *timing* half of A7 (the size half waits on
profile-driven sampling).

| | Milestone | Effort |
|---|---|---|
| M6.5 | `proteus_core::jitter` module (bounded delay sampler) + `TimingJitterConfig` + this design ✅ | small |
| M7.5 | Wire-up: apply jitter on the proxy-stream send path (server + client bridges) ✅ | small |
| M8.5 | Tests (sampler bounds + data round-trips with jitter on) + [`m8.5-timing-jitter-signoff.md`](m8.5-timing-jitter-signoff.md) ✅ | small |

**v0.5-rc.2 = M6.5 through M8.5, all complete.** Profile-driven
size + inter-arrival sampling (needs a capture corpus) and a
lower-overhead token-bucket pacer remain deferred.

## 7. Migration impact

**Breaking change scope:** padded vs. un-padded frames are NOT
wire-compatible. Mitigation:
- `padding.enabled` defaults to `false` → drop-in upgrade for v0.4
  operators.
- Operators who want A5 closure flip both ends to `enabled: true`
  in lockstep.
- No protocol-level negotiation in rc.1 — keep it simple. rc.2 may
  add a flag in AUTH_RESPONSE to surface server-side padding so the
  client can warn on mismatch.

**Persistent state:** none. No DB / cache schema changes.

## 8. Out-of-scope (still deferred beyond v0.5-rc.1)

* Profile-driven size sampling (uses `fingerprint-profile.example.yaml`).
* ~~Inter-arrival timing jitter~~ — **now in scope for rc.2, see §11.**
* SNI rotation.
* Port hopping.
* Periodic per-stream re-keying.
* Adversarial-testing harness (a "DPI tool" that tries to
  distinguish v0.5 from real H3; useful but its own project).

## 9. Roadmap: v0.5 → v0.6 → v1.0

```text
v0.5 (this plan, rc.1 scope)
  └── Bucket padding + idle dummies (close A5 mostly)
        │
        ▼ (v0.5-rc.2/final or v0.6)
  ├── Profile-driven sampling + timing jitter (close A5 fully + part of A7)
  ├── SNI rotation
  ├── Port hopping
        │
        ▼
v1.0
  ├── Hybrid X25519 + ML-KEM-768 (A9)
  ├── External crypto review
  └── Production-readiness statement
```

## 10. References

* [`PROTEUS-v0.4-plan.md`](PROTEUS-v0.4-plan.md) §11 — v0.4 → v0.5 → v1.0 roadmap.
* [`fingerprint-profile.example.yaml`](fingerprint-profile.example.yaml) — schema for v0.5-rc.2 profile work.
* [`m14-comparison-report.md`](m14-comparison-report.md) — v0.3 wire baseline (14 packets vs 41 for real H3).
* [`m9.4-rc1-signoff.md`](m9.4-rc1-signoff.md) — v0.4 sign-off, §2.6 + §3 document what v0.5 inherits.
* [`THREAT-MODEL-v0.3.md`](THREAT-MODEL-v0.3.md) — A1–A11 framework (still accurate for v0.4/v0.5; only the per-adversary status moves).

---

## 11. v0.5-rc.2 addendum: timing jitter

rc.1 quantized *frame sizes*. rc.2 attacks the other axis a statistical
analyst (A7) keys on: **inter-arrival timing**. Right now PROTEUS
writes each frame the instant the bridge produces it, so the gaps
between frames directly mirror the application's data-production
timing plus RTT — a low-jitter, deterministic signature.

### 11.1 Mechanism

A **bounded random delay before each outgoing proxy-stream frame**.
The sender sleeps a sampled duration, then writes the frame.

The single most important property: **timing jitter is sender-side
only.** The receiver decodes frames exactly as before — there is **no
wire-format change, no flag, no lockstep upgrade**. Each side may
enable jitter independently. This is strictly simpler than bucket
padding (which needed the `FLAG_PADDED` bit + both ends in agreement).

### 11.2 Distribution

rc.2 first cut: **uniform** delay in `[min_ms, max_ms]`. Uniform is
trivially testable (every sample provably within bounds) and good
enough to break the *deterministic* send pattern.

It is explicitly **not** a mimic of any real cover host's
inter-arrival distribution — that needs the same recorded-profile
machinery deferred for size sampling (§3). Exponential / profile-driven
inter-arrival is a later increment. This mirrors how rc.1 bucket
padding was "a quantizer, not a mimic": rc.2 jitter is "a
decorrelator, not a mimic."

### 11.3 Scope

* **Proxy-stream frames, both directions.** Server→client and
  client→server DATA/control-on-proxy-stream frames go through the
  jitter delay when enabled.
* **NOT auth-stream frames.** Auth is a one-shot handshake; delaying
  it just adds login latency with negligible fingerprint benefit (a
  single AUTH_REQUEST has no inter-arrival pattern to hide).
* **Idle PINGs** (M3.5) already have their own interval timer; jitter
  does not stack on top of them.

### 11.4 The throughput trade-off (honest)

Per-frame delay is **not free**. A uniform `[min_ms, max_ms]` delay
adds an average of `(min+max)/2` ms of latency *per frame*. On a bulk
transfer split into many ~1500-byte frames, throughput is capped at
roughly `frame_size / avg_delay`:

| avg delay | rough bulk-throughput ceiling |
|---:|---|
| 1 ms | ~1.5 MB/s |
| 5 ms | ~300 KB/s |
| 20 ms | ~75 KB/s |

So the default range is kept **small** (`min_ms: 0`, `max_ms: 5`), and
the config docs warn that larger ranges trade throughput for timing
decorrelation. An operator who only proxies interactive / low-volume
traffic can afford a wider range; a bulk-download use case cannot.

A smarter design (token-bucket pacer that only jitters frame
*boundaries* without serializing every write, or coalescing small
frames) is future work — noted in the sign-off, not built in rc.2.

### 11.5 Configuration (additive YAML, default off)

```yaml
# v0.5-rc.2. Sender-side only — set independently per side (no lockstep).
timing_jitter:
  enabled: true
  min_ms: 0
  max_ms: 5      # uniform delay [min_ms, max_ms] before each proxy-stream frame
```

When `enabled: false` (default), the send path is byte-for-byte and
timing-identical to rc.1.

### 11.6 Acceptance criteria for rc.2

1. `proteus_core::jitter` module: a sampler that, given
   `(min_ms, max_ms)`, returns a `Duration` provably in range.
   Unit tests over many samples + edge cases (`min == max`,
   `min == max == 0`).
2. `TimingJitterConfig` in `proteus_core::config`, default off,
   validated (`min_ms <= max_ms`).
3. Send path applies the delay on proxy-stream frames (server +
   client) when enabled; disabled = no delay, no behavior change.
4. Integration test: data round-trips correctly through the SOCKS5
   proxy with jitter enabled (proves the delay doesn't break the
   bridge or desync AEAD counters). A no-jitter control.
5. Sign-off doc `m8.5-timing-jitter-signoff.md` with the honest
   throughput-cost statement + what remains for profile-driven
   timing.
