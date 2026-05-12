# InfiniPot

**Work in progress.** Behavior, APIs, security surfaces, and documentation may change without notice. Treat production deployments as experimental until you pin a release and review configuration yourself.

## How to run

### First admin account

This applies to **local** `npm run db:seed-admin` and **Docker**, where **`docker-entrypoint.sh`** runs the **same seed script** before `node server/index.js`.

| | |
| --- | --- |
| **Created when** | The database has **no** admin row yet (`role = admin` or `is_admin`). If one exists, seed **exits quietly** — it does **not** replace users. |
| **Username** | **`SEED_ADMIN_USERNAME`** from `.env`, default **`admin`**. |
| **Initial password** | **`SEED_ADMIN_PASSWORD`** if set and non-empty in `.env`. If **unset or blank**, **`ChangeMeImmediately!`**. (Stored as bcrypt only.) |
| **After first sign-in** | Complete **Set your password** in the SPA (**new** password **≥ 12** characters). Until then, **`/admin`** and **`/api/admin/*`** respond **`403`** (`password_change_required`). |

**Troubleshooting:** Use **`COOKIE_SECURE=true`** only behind **HTTPS**; leave **`false`/unset on HTTP** (e.g. `http://localhost` Docker). If **`admin`**’s hash no longer matches the password you expect, run seed **once** with **`SEED_ADMIN_OVERWRITE_PASSWORD=1`** plus the desired **`SEED_ADMIN_PASSWORD`** (or empty for **`ChangeMeImmediately!`**), then **remove** that variable — details in [`.env.example`](.env.example).

### Local development

Requirements: **Node.js 20+** and **npm**.

```bash
git clone <repository-url>
cd InfiniPot
cp .env.example .env
```

Edit `.env` and set at least `JWT_SECRET` and `INTEGRATION_ENCRYPTION_KEY` (hex instructions are in the file comments).

```bash
npm install
npm run db:seed-admin
npm run dev
```

**`npm run db:init`** is optional — the schema is applied by **`db:seed-admin`** and on every API boot (`ensureSchema()`). Use **First admin account** above for bootstrap username/password after seed.

- **UI:** <http://localhost:5173> — proxies **`/api`** and **`/uploads`** to the API on port 3000. Sign in with the seeded credentials from **First admin account**.

### Docker (production-like)

Image rebuilds do **not** remove data; SQLite and uploads persist in the Compose volume **`infinipot-data`** (mounted **`/data`**) unless you delete that volume.

Each container start: **`docker-entrypoint.sh`** runs seed (**First admin account**), then the API (**`tini`** → **`node server/index.js`**).

```bash
cp .env.example .env   # JWT_SECRET, INTEGRATION_ENCRYPTION_KEY, optional SEED_ADMIN_*
docker compose up --build -d
```

Open **`http://localhost:3000`**, or the host port from **`HOST_PORT`** in `.env` ([`docker-compose.yml`](docker-compose.yml)). Sign-in is always as defined in **First admin account** — not duplicated here.

On the public Internet, set a strong **`SEED_ADMIN_PASSWORD`**; the documented bootstrap is predictable.

To reinstall from scratch: `docker compose down`, then **`docker volume rm …`** matching your **`…_infinipot-data`** volume (`docker volume ls`; Compose prefixes by project).

### Smoke check (optional)

With the API listening (e.g. `PORT=3000 npm start`):

```bash
SMOKE_BASE=http://127.0.0.1:3000 npm run smoke
```

---

> Internally: **Maxwell International (MI)** — research project codename retained
> in all internal tokens (`mi_session`, `MI2026-XXXX`, etc.) and related access markers. **Externally:** InfiniPot.

InfiniPot is a small, opinionated web app with three feature surfaces:

1. **Blog** — markdown / TipTap-edited posts with cover images, drafts/published states, and per-post view counts.
2. **Donations** — static outbound buttons to a self-hosted BTCPay POS and to a partner fund.
3. **Security monitoring** — monitored endpoint and data-room activity surfaces help identify unauthorized scanners and retrieval systems, with admin tooling for review.

It runs as a **single Docker container** with **SQLite on disk** — no Postgres, no Redis, no separate auth service. Everything you need to run it is in this repo.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                       InfiniPot container                        │
│                                                                  │
│  Node 20 / Express ─────────────────────────────────────────┐    │
│   ├─ /api/auth/*       login, me, change-password; bcrypt; JWT+cookie   │    │
│   ├─ /api/blog/* + /api/carousel   public surfaces (when visibility allows)  │    │
│   ├─ /api/site/visibility          page + API gates (home/blog/donations)    │    │
│   ├─ /api/secrets/explore/*  data room (Turnstile, etc.)    │    │
│   ├─ /api/secrets/*          monitored decoy endpoints       │    │
│   ├─ /api/admin/integrations  encrypted integration creds   │    │
│   ├─ /api/admin/*        other admin CRUD, Security Hub, …   │    │
│   └─ /api/mi-verify    1×1 access-log beacon                │    │
│                                                              │    │
│  SQLite (better-sqlite3, WAL mode) at /data/infinipot.sqlite │    │
│  Uploaded blog images at /data/uploads/                     │    │
│  Access CSV mirror at /data/logs/                           │    │
└──────────────────────────────────────────────────────────────────┘
```

## Security monitoring layers

| Layer | What | Where logged |
|---|---|---|
| **Monitored endpoints** | Internal-looking surfaces (`/api/secrets/system-prompt`, `/api/secrets/internal/dossier-dump`, `/.env`, `/.git/config`, `/wp-admin`, `/api/admin/api-keys`, `/openapi.json`, …) | `ai_honeypot_hits` (with `source` discriminator) |
| **Data room activity** | Procedurally generated 1M-page Arden Point Capital data-room tree under `/api/secrets/explore/*`, Cloudflare Turnstile-gated for repeat IPs, captures self-identification via `APC-ACCESS-ID:` token | `maze_hits` (per-IP/day aggregated) |
| **Input guard** | Prompt-injection / SQL / XSS / PII detector on real AI endpoints, auto-revokes AI access after N HIGH hits in 24h | `ai_input_flags` |
| **Access log** | Every public page load + the hidden `/api/mi-verify` beacon, with per-load token marker | `access_log` |
| **Alerts engine** | Rule-driven email / Discord / Telegram / webhook deliveries on patterns across the above | `security_alert_rules`, `security_alert_deliveries` |

All hits are passively enriched (ipinfo / AbuseIPDB / GreyNoise) and visible in the admin **Security Hub** with filterable tabs, geo/ASN summaries, repeat-offender derivations, and one-click firewall exports (nginx / iptables / Cloudflare / CIDR).

## AI Log Review

The legacy "AI Brief" framework has been repurposed: instead of generating dossiers, you select log rows / alerts in the Security Hub and get a structured analysis + suggested actions from xAI Grok (default `grok-4.3-latest`, fast fallback `grok-latest`). Settings, request logs, encrypted key storage, and rate limits live in `app_settings` and `integration_credentials`.

## Project status

This repo replaces an earlier codebase (historical Maxwell International tooling). Current **shipping** scope:

- SQLite-backed auth (bcrypt passwords, documented **`admin`** / **`ChangeMeImmediately!`** bootstrap unless overridden, mandatory first-login **Set your password**; `password_change_required` gates `/api/admin/*`), integrations (encrypted credentials), audits, blog + carousel APIs, SPA with page visibility gates.
- Monitored endpoints (`/api/secrets`, standalone scanner URLs), data-room activity (`/api/secrets/explore`), access logging (`access_log`), alert rules engine, AI input guard + xAI-driven **AI Log Review**.
- Docker single-process deployment (`docker-entrypoint.sh` seeds admin once), persisted `/data` volume.

## Disclaimer

InfiniPot is research / educational software. The security monitoring layer is designed to discourage unauthorized scraping; it is not a substitute for proper WAF, rate-limiting at the edge, or robots compliance for legitimate user agents. You are responsible for complying with all applicable laws in any deployment.

## License

TBD (likely AGPL-3.0 or MPL-2.0 — choose before public release).
