# M14 — Invalid Client Handling (status note)

**Date:** 2026-05-27
**Roadmap:** [`ROADMAP-v0.3.md`](ROADMAP-v0.3.md) §M14
**Status:** Code path lands; capture-based comparison pending M15.

## Current behavior

The PROTEUS server treats any of the following as an "invalid client"
and closes the QUIC connection with application error code
`H3_GENERAL_PROTOCOL_ERROR` (`0x0101`) and an empty reason payload:

| Condition | Handler in `proteus-server::main` |
|---|---|
| First frame on control stream is not `AUTH_REQUEST` | early-bail before `metrics.auth_attempt()` |
| `AUTH_REQUEST` not received within 5 s | M18 read timeout (`AUTH_READ_TIMEOUT`) |
| `AUTH_REQUEST` malformed (encoding / length / UTF-8) | `AuthRequest::decode` Err path |
| Ed25519 signature does not verify | `ClientRegistry::verify` Err |
| `client_id` not present in the registry | same |
| Replay-cache hit on `(client_id, nonce)` | `ReplayCache::check_and_record` Err |

All paths share the same close code (`AUTH_FAIL_CLOSE_CODE = 0x0101`)
and an empty reason string. The per-reason `eprintln!` log is
server-internal only — nothing about *why* the rejection happened
leaves the server on the wire.

Source-of-truth: spec v0.2 §8.4 ("Generic Close on Auth Failure").

## What is verified (in the v0.3 build)

- **Source review.** Only one close-code constant is used for all
  auth-failure paths; grep confirms.
- **Integration smokes** for M6 (auth FAIL), M7 (replay FAIL), and
  M12 (policy FAIL) exercise three of the six rejection paths
  end-to-end. The client observes "UDP proxy rejected: policy-denied"
  / similar at the PROXY level (which is a separate frame, not the
  QUIC close); the QUIC connection close itself happens after auth
  failure and was verified by inspection in M6.
- **No-secret-logs audit** (M18): the only `println` mentioning a key
  is in `proteus-tools::keygen` and it prints the *path*, not the key
  bytes.

## What is not yet verified

Spec v0.2 §13 Open Question #2 asks whether
`H3_GENERAL_PROTOCOL_ERROR` is plausibly indistinguishable from what
a real HTTP/3 server emits when its client malforms the first frame.
Answering that requires three deliverables that the v0.3 prototype
does not yet have:

1. **Capture tooling (M15).** Wrappers around `tcpdump` /
   `tshark` that record a PROTEUS rejection event reproducibly.
2. **Baseline capture from a real H3 server** (Cloudflare, Google,
   Microsoft) reacting to a malformed first frame.
3. **Diff report** identifying any timing, packet-size, or close-code
   difference a DPI box could fingerprint on.

These three are a coupled deliverable, not three independent
milestones. They land together in the v0.3 sign-off block (M14 + M15
+ a `captures/v0.3/` directory).

## What changes in v0.4 (and why this gap is bounded)

The v0.4 REALITY-style upstream forwarding plan makes this question
largely moot: a non-PROTEUS QUIC connection — or one that fails auth —
gets its raw bytes forwarded to a real upstream cover host. The close
the client observes is whatever the cover host actually emitted, by
construction indistinguishable from a real H3 server because that *is*
what answered. M14 in v0.3 is the fallback baseline ("no upstream
forwarding yet, but the close code is at least generic").

## Acceptance criteria for M14 to be marked done

- [ ] M15 capture scripts exist (e.g. `scripts/capture-proteus-reject.sh`,
      `scripts/capture-h3-malformed.sh`).
- [ ] One PROTEUS-reject `.pcap` and one real-H3-reject `.pcap` are
      stored under `captures/v0.3/`.
- [ ] A diff report — even a short one, even "the two are obviously
      different" — lives at `docs/m14-comparison-report.md`.

Until then, M14 is **"code path correct, end-to-end
indistinguishability not measured."**
