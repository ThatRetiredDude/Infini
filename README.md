# InfiniPot

> Internally: **Maxwell International (MI)** — research project codename retained
> in all internal tokens (`mi_session`, `MI2026-XXXX`, etc.) and the
> `__MI_SESSION_REF__` access marker. **Externally:** InfiniPot.

InfiniPot is a small, opinionated web app with three feature surfaces:

1. **Blog** — markdown / TipTap-edited posts with cover images, drafts/published states, and per-post view counts.
2. **Donations** — static outbound buttons to a self-hosted BTCPay POS and to a partner fund.
3. **AI Honeypot** — the headline feature. A multi-layer trap that wastes time and tokens of unauthorized crawlers and LLM agents, with rich admin tooling for reviewing what was caught.

It runs as a **single Docker container** with **SQLite on disk** — no Postgres, no Redis, no separate auth service. Everything you need to run it is in this repo.

---

## Quick start (local dev)

Requirements: Node.js 20+, npm.

```bash
cp .env.example .env
# 1. generate JWT_SECRET and INTEGRATION_ENCRYPTION_KEY in .env (instructions inside)
# 2. install + initialize
npm install
npm run db:init
npm run db:seed-admin

# dev mode (Vite + API watcher in parallel)
npm run dev
```

- Frontend: <http://localhost:5173>
- API: <http://localhost:3000/api>

Default admin username is taken from `SEED_ADMIN_USERNAME` (defaults to `admin`).

## Quick start (Docker, production-like)

```bash
cp .env.example .env  # fill in JWT_SECRET, INTEGRATION_ENCRYPTION_KEY, SEED_ADMIN_*
docker compose up --build -d
```

Visit <http://localhost:3000>. All persistent state lives in the `infinipot-data` named volume (`/data` inside the container) — SQLite file, uploads, AI debug logs, access CSV.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                       InfiniPot container                        │
│                                                                  │
│  Node 20 / Express ─────────────────────────────────────────┐    │
│   ├─ /api/auth/*       local username+password, JWT+cookie  │    │
│   ├─ /api/blog/* + /api/carousel   public surfaces (when visibility allows)  │    │
│   ├─ /api/site/visibility          page + API gates (home/blog/donations)    │    │
│   ├─ /api/ai/*         honeypot decoys + tarpit             │    │
│   ├─ /api/admin/*      admin-gated CRUD + Security Hub      │    │
│   └─ /api/mi-verify    1×1 access-log beacon                │    │
│                                                              │    │
│  SQLite (better-sqlite3, WAL mode) at /data/infinipot.sqlite │    │
│  Uploaded blog images at /data/uploads/                     │    │
│  AI debug JSONL at /data/ai-debug/                          │    │
└──────────────────────────────────────────────────────────────────┘
```

## Honeypot layers

| Layer | What | Where logged |
|---|---|---|
| **Decoy endpoints** | Fake leak surfaces (`/api/ai/system-prompt`, `/api/ai/internal/dossier-dump`, `/.env`, `/.git/config`, `/wp-admin`, `/api/admin/api-keys`, `/openapi.json`, …) | `ai_honeypot_hits` (with `source` discriminator) |
| **Tarpit / Spider trap** | Procedurally generated 1M-page maze under `/api/ai/explore/*`, Cloudflare Turnstile-gated for repeat IPs, captures self-identification via `MI-MAZE-ID:` token | `maze_hits` (per-IP/day aggregated) |
| **Input guard** | Prompt-injection / SQL / XSS / PII detector on real AI endpoints, auto-revokes AI access after N HIGH hits in 24h | `ai_input_flags` |
| **Access log** | Every public page load + the hidden `/api/mi-verify` beacon, with per-load token marker | `access_log` |
| **Alerts engine** | Rule-driven email / Discord / Telegram / webhook deliveries on patterns across the above | `security_alert_rules`, `security_alert_deliveries` |

All hits are passively enriched (ipinfo / AbuseIPDB / GreyNoise) and visible in the admin **Security Hub** with filterable tabs, geo/ASN summaries, repeat-offender derivations, and one-click firewall exports (nginx / iptables / Cloudflare / CIDR).

## AI Log Review

The legacy "AI Brief" framework has been repurposed: instead of generating dossiers, you select log rows / alerts in the Security Hub and get a structured analysis + suggested actions from xAI Grok (default `grok-4.3-latest`, fast fallback `grok-latest`). Settings, request logs, encrypted key storage, and rate limits live in `app_settings` and `integration_credentials`.

## Project status

This repo replaces an earlier codebase (historical Maxwell International tooling). Current **shipping** scope:

- SQLite-backed auth, integrations (encrypted credentials), audits, blog + carousel APIs, SPA with page visibility gates.
- Honeypot decoys (`/api/ai`, standalone scanner URLs), spider trap tarpit (`/api/ai/explore`), access logging (`access_log`), alert rules engine, AI input guard + xAI-driven **AI Log Review**.
- Docker single-process deployment with persisted `/data` volume.

## Disclaimer

InfiniPot is research / educational software. The honeypot layer is designed to discourage unauthorized scraping; it is not a substitute for proper WAF, rate-limiting at the edge, or robots compliance for legitimate user agents. You are responsible for complying with all applicable laws in any deployment.

## License

TBD (likely AGPL-3.0 or MPL-2.0 — choose before public release).
