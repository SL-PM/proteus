# PROTEUS

> **Status: Pre-implementation research project.** No working code yet.
> See [`docs/ROADMAP-v0.3.md`](docs/ROADMAP-v0.3.md) for what is planned.

## What this is

A design study and (eventually) reference implementation of a VPN /
circumvention protocol that combines REALITY's indistinguishability idea,
Hysteria2's QUIC transport, and a clean Noise-style handshake.

- Long-term vision: [`docs/PROTEUS-spec-v0.1.md`](docs/PROTEUS-spec-v0.1.md).
- v0.3 prototype scope (what we are actually going to build first):
  [`docs/PROTEUS-spec-v0.2.md`](docs/PROTEUS-spec-v0.2.md).

## ⚠️ Not a production tool

The v0.3 prototype is **DPI-detectable by design** — REALITY-style
masquerading is deferred to v0.4, post-quantum crypto to v1.0. Do not
deploy v0.3 as a circumvention tool in any adversarial environment.

Full threat model and deployment restrictions:
[`docs/THREAT-MODEL-v0.3.md`](docs/THREAT-MODEL-v0.3.md).

## Documents

| File | What it is |
|---|---|
| [`docs/PROTEUS-spec-v0.1.md`](docs/PROTEUS-spec-v0.1.md) | Long-term vision (May 2026 draft). |
| [`docs/PROTEUS-spec-v0.2.md`](docs/PROTEUS-spec-v0.2.md) | Transition spec: what v0.3 will actually build. |
| [`docs/ROADMAP-v0.3.md`](docs/ROADMAP-v0.3.md) | Implementation milestones M0–M19. |
| [`docs/THREAT-MODEL-v0.3.md`](docs/THREAT-MODEL-v0.3.md) | What v0.3 defends against and what it doesn't. |

## Getting started

The first coding milestone (M0 in the roadmap) creates the Cargo workspace.
Until then, this repo is documentation only.

When code lands, the first thing to run will be the M5 TLS exporter spike —
the entire auth design depends on it. See roadmap §4 "M5" for the rationale.

## License

Documents: CC-BY-SA 4.0.
Code (when it lands): TBD before M0.
