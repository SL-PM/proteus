# PROTEUS v0.6 — "Control": management portal (plan)

> **Status:** Design draft, no code yet (M0.6).
> **Goal:** turn PROTEUS from a CLI-configured tunnel into a
> manageable, eventually **commercial** VPN service — admin panel,
> per-client traffic quotas, subscription/QR distribution, and (later)
> payment-gated self-service with a Telegram sales bot.

This is a multi-component subproject, deliberately phased so each phase
ships something usable and the hard parts aren't blocked on the easy
ones.

---

## 1. The full vision (where we're going)

A web portal + tooling around the existing PROTEUS server that lets an
operator **sell and manage end-customer VPN access**:

- **Admin panel** — create/disable clients, set quota + expiry, see usage.
- **Per-client traffic quotas** — e.g. "15 GB then cut off"; per-client
  expiry dates.
- **Distribution** — each client gets a config download, a
  **subscription URL**, and a **QR code** for easy import into a client app.
- **End-customer self-service portal** (later) — customers see their
  usage/expiry, re-download config.
- **Payment-gated auto-provisioning** (later) — customer pays → webhook
  → a client is auto-created with the purchased quota → QR/code returned.
- **Telegram sales bot** (later) — the delivery channel: customer buys
  via the bot, gets the QR/access code automatically.

## 2. What PROTEUS has today vs. needs

| Capability | Today | Needed |
|---|---|---|
| Client identity | static `clients:` map in `server.yaml` | dynamic, DB-backed, hot-reload |
| Per-client traffic accounting | **none** | byte counters per client |
| Quotas / expiry | **none** | enforce at the server |
| Config distribution | manual `client.yaml` | download + subscription URL + QR |
| Admin/customer UI | **none** | web panel |
| Payments / bot | **none** | Phase 3 |

**The crux is traffic accounting + quota enforcement in
`proteus-server`** — not the UI. PROTEUS moves bytes through the proxy
bridge (`proteus_core::proxy`) but counts nothing per-client. Selling
"15 GB" is impossible until the server meters and enforces. Marzban/
Hiddify get this from Xray's stats API; we must build it natively.

## 3. Stack (Rust-consistent, all in the workspace)

- **`proteus-panel`** — new crate, **Rust + axum**. Management API +
  admin web UI. Reuses `proteus-core` (Ed25519 keygen, config types).
- **SQLite** via **sqlx** — embedded, no separate DB server. Holds
  clients, admins, subscription tokens, usage, (later) customers +
  payments.
- **Admin UI** — server-rendered Rust (**maud/askama + htmx**). No JS
  build chain; plenty for an admin panel.
- **Customer-facing portal** (Phase 3) — frontend choice deferred until
  we get there (server-rendered may still suffice; SPA only if it must
  be a polished consumer product).
- **QR codes** — `qrcode` crate → SVG/PNG of the subscription URL.
- **Telegram bot** (Phase 3) — pure **Telegram Bot API** (e.g. `teloxide`),
  deterministic provisioning. **Not** an LLM agent (Hermes); an LLM would
  be unpredictable + costly for transactional logic. Hermes optional
  later only for conversational support.
- **TLS** — panel served over HTTPS on TCP 443/8443 (the firewall ports
  requested). PROTEUS itself stays on UDP 4433.

## 4. Data model (initial)

```
clients
  id            TEXT PK         -- the PROTEUS client_id
  label         TEXT            -- human note ("alice", "kunde-42")
  pubkey_b64    TEXT            -- Ed25519 public key
  enabled       BOOL
  quota_bytes   INTEGER NULL    -- NULL = unlimited
  used_bytes    INTEGER         -- updated by the server's accounting
  expires_at    TIMESTAMP NULL
  created_at    TIMESTAMP

admins
  username, argon2_hash, created_at

subscription_tokens
  token TEXT PK, client_id FK, created_at, revoked

-- Phase 3:
customers (id, contact/telegram_id, ...)
payments  (id, customer_id, client_id, amount, provider, status, ...)
```

## 5. Phasing

### Phase 1 — Foundation (build now)
- M0.6 — this design doc + `proteus-panel` crate scaffold (axum, builds).
- M1.6 — SQLite store + migrations; data layer for `clients`.
- M2.6 — Management API (axum): client CRUD (add → server-side keygen or
  accept pubkey; set quota/expiry; disable; list), admin auth
  (session cookie + argon2), metrics passthrough.
- M3.6 — `proteus-server`: replace static `ClientRegistry` with a
  DB-backed one + hot-reload, so panel changes apply without restart.
- M4.6 — Admin web UI (maud + htmx): login, client list, add/remove,
  show config + subscription link + **QR**, usage view.
- M5.6 — Distribution: per-client `client.yaml` download + `/sub/<token>`
  subscription endpoint + QR generation.

### Phase 2 — Quotas (the crux)
- M6.6 — Per-client byte accounting in the proxy bridge → periodic
  persist to DB.
- M7.6 — Enforcement: server refuses / disables a client at
  `used_bytes >= quota_bytes` or past `expires_at`; surfaced in panel.

### Phase 3 — Commerce (later / background)
- Customer self-service portal.
- Payment provider integration (TBD) → webhook → auto-provision.
- Telegram sales bot (pure Bot API) → deliver QR/code on payment.

## 6. Deploy target
`sl-projectmanagementserver3` (212.227.12.251, Ubuntu 24.04): panel
behind TLS on 443/8443; PROTEUS server on UDP 4433; SQLite on local disk.

## 7. Open / TBD (don't block Phase 1)
- Payment provider + flow (Stripe? crypto? local?) — Phase 3.
- Customer-auth model (Telegram-id-based? email?) — Phase 3.
- **Legal/compliance** (ToS, tax, KYC/AML depending on payment rail) —
  operator's responsibility; flagged, not solved here.

## 8. Guardrails (how the assistant works on this)
- Never handles real payment credentials or moves money — only
  integrates a provider's API (webhook-driven). Customers/operator
  transact.
- Firewall / cloud-access-control changes are made by the operator in
  the IONOS panel, not by the assistant.
- Admin/customer auth uses hashed credentials (argon2); no plaintext
  secrets in the repo or DB.

## 9. References
- [`PROTEUS-v0.5-plan.md`](PROTEUS-v0.5-plan.md) — the protocol the panel manages.
- [`CONFIG.md`](CONFIG.md) — current static client/config model being replaced.
- Prior art for UX (not code): Marzban / Marzneshin (user mgmt + quotas
  + subscriptions), Hiddify (client config distribution).
