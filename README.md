# Infini

**Self-hosted security monitoring and honeypot-style surfaces** behind a small Node/Express API and SPA. *Work in progress — behavior, APIs, and documentation may change without notice; treat production as experimental until you pin a release and review config yourself.*

## Purpose

Infini is a **research-style honeypot / monitoring stack** in **active development**: decoy and instrumented routes, a data-room-style exploration surface, access logging, enrichment, admin review (Security Hub), and alert delivery. Expect **more surfaces and behavior over time.**

It ships as **one container (or dev process)** with **SQLite on disk** — no Postgres, no Redis, no separate auth service. Everything needed to run it lives in this repo.

Internally, **Maxwell International (MI)** remains the codename in tokens (`mi_session`, `MI2026-XXXX`, etc.) and related markers; **externally** the product is **Infini**.

## Features overview

- **Security & monitoring** — Monitored endpoints, procedurally surfaced data-room activity under `/api/secrets/explore/*`, passive enrichment, Security Hub dashboards, configurable alerts, AI-assisted log review, and related admin tooling (see **Detailed overview** below for depth).
- **Blog** — Optional and casual: Markdown/TipTap posts, drafts/published states, carousel — use it to read something light or pad the site with nonsense; it isn’t why this project exists.
- **Public cover** — A donations-related page exists as part of the normal site shell (visibility-gated outbound links); it is **not** the primary purpose of Infini.

**More to come** as development continues.

## How to run

**Quick paths**

| | |
| --- | --- |
| **Docker** | `cp .env.example .env` → set **`JWT_SECRET`**, **`INTEGRATION_ENCRYPTION_KEY`**, optionally **`SEED_ADMIN_*`** → `docker compose up --build -d` → open `http://localhost:${HOST_PORT:-3000}` |
| **Local dev** | Same `.env` setup → `npm install` → `npm run db:seed-admin` → `npm run dev` → UI at <http://localhost:5173> (proxies `/api` and `/uploads` to port 3000) |

Details: [Local development](#local-development) · [Docker](#docker-production-like)

### Local development

Requirements: **Node.js 20+** and **npm**.

```bash
git clone <repository-url>
cd <repository-directory>
cp .env.example .env
```

Edit `.env` and set at least `JWT_SECRET` and `INTEGRATION_ENCRYPTION_KEY` (hex instructions are in the file comments).

```bash
npm install
npm run db:seed-admin
npm run dev
```

**`npm run db:init`** is optional — the schema is applied by **`db:seed-admin`** and on every API boot (`ensureSchema()`). After seed, sign in per **[How to log in](#how-to-log-in)**.

### Docker (production-like)

Image rebuilds do **not** remove data; SQLite and uploads persist in the Compose volume **`infini-data`** (mounted **`/data`**) unless you delete that volume.

Each container start: **`docker-entrypoint.sh`** runs the same admin seed as local dev, then the API (**`tini`** → **`node server/index.js`**).

```bash
cp .env.example .env   # JWT_SECRET, INTEGRATION_ENCRYPTION_KEY, optional SEED_ADMIN_*
docker compose up --build -d
```

Open **`http://localhost:3000`**, or the host port from **`HOST_PORT`** in `.env` ([`docker-compose.yml`](docker-compose.yml)). Sign in per **[How to log in](#how-to-log-in)**.

On the public Internet, set a strong **`SEED_ADMIN_PASSWORD`**; the documented bootstrap is predictable.

To reinstall from scratch: `docker compose down`, then **`docker volume rm …`** matching your **`…_infini-data`** volume (`docker volume ls`; Compose prefixes by project).

### Smoke check (optional)

With the API listening (e.g. `PORT=3000 npm start`):

```bash
SMOKE_BASE=http://127.0.0.1:3000 npm run smoke
```

## How to log in

This applies to **local** `npm run db:seed-admin` and **Docker**, where **`docker-entrypoint.sh`** runs the **same seed script** before `node server/index.js`.

| | |
| --- | --- |
| **Created when** | The database has **no** admin row yet (`role = admin` or `is_admin`). If one exists, seed **exits quietly** — it does **not** replace users. |
| **Username** | **`SEED_ADMIN_USERNAME`** from `.env`, default **`admin`**. |
| **Initial password** | **`SEED_ADMIN_PASSWORD`** if set and non-empty in `.env`. If **unset or blank**, **`ChangeMeImmediately!`**. (Stored as bcrypt only.) |
| **After first sign-in** | Complete **Set your password** in the SPA (**new** password **≥ 12** characters). Until then, **`/admin`** and **`/api/admin/*`** respond **`403`** (`password_change_required`). |

### Troubleshooting login

Use **`COOKIE_SECURE=true`** only behind **HTTPS**; leave **`false`/unset on HTTP** (e.g. `http://localhost` Docker).

**Host dev vs Docker use two different SQLite *files*:** [`.env.example`](.env.example) uses **`./data/infini.sqlite`** locally; Compose sets **`DATABASE_FILE=/data/infini.sqlite`** inside the container (on the **`infini-data`** volume). Seeding only on the laptop does not update the container DB (and vice versa). Keep **`DATABASE_FILE`** aligned with [`.env.example`](.env.example) unless you know you need a split.

If **`admin`** / the bootstrap password should work but the hash is wrong (old volume), run seed **once** with **`SEED_ADMIN_OVERWRITE_PASSWORD=1`** plus **`SEED_ADMIN_PASSWORD`** (or empty for **`ChangeMeImmediately!`**), restart, then **remove** that variable — see [`.env.example`](.env.example).

**`curl` check:**  
`curl -s -X POST http://localhost:3000/api/auth/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"ChangeMeImmediately!"}'`  
→ **`invalid_credentials`** means no matching user/hash; a JSON **`user`** means the password is fine (then look at cookies / **Set your password**).

---

## Detailed overview

### Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                       Infini container                         │
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
│  SQLite (better-sqlite3, WAL mode) at /data/infini.sqlite (DATABASE_FILE) │    │
│  Uploaded blog images at /data/uploads/                     │    │
│  Access CSV mirror at /data/logs/                           │    │
└──────────────────────────────────────────────────────────────────┘
```

### Security monitoring layers

| Layer | What | Where logged |
|---|---|---|
| **Monitored endpoints** | Internal-looking surfaces (`/api/secrets/system-prompt`, `/api/secrets/internal/dossier-dump`, `/.env`, `/.git/config`, `/wp-admin`, `/api/admin/api-keys`, `/openapi.json`, …) | `ai_honeypot_hits` (with `source` discriminator) |
| **Data room activity** | Procedurally generated 1M-page Arden Point Capital data-room tree under `/api/secrets/explore/*`, Cloudflare Turnstile-gated for repeat IPs, captures self-identification via `APC-ACCESS-ID:` token | `maze_hits` (per-IP/day aggregated) |
| **Input guard** | Prompt-injection / SQL / XSS / PII detector on real AI endpoints, auto-revokes AI access after N HIGH hits in 24h | `ai_input_flags` |
| **Access log** | Every public page load + the hidden `/api/mi-verify` beacon, with per-load token marker | `access_log` |
| **Alerts engine** | Rule-driven email / Discord / Telegram / webhook deliveries on patterns across the above | `security_alert_rules`, `security_alert_deliveries` |

All hits are passively enriched (ipinfo / AbuseIPDB / GreyNoise) and visible in the admin **Security Hub** with filterable tabs, geo/ASN summaries, repeat-offender derivations, and one-click firewall exports (nginx / iptables / Cloudflare / CIDR).

### AI Log Review

The legacy "AI Brief" framework has been repurposed: instead of generating dossiers, you select log rows / alerts in the Security Hub and get a structured analysis + suggested actions from xAI Grok (default `grok-4.3-latest`, fast fallback `grok-latest`). Settings, request logs, encrypted key storage, and rate limits live in `app_settings` and `integration_credentials`.

### Current scope

This repo replaces an earlier codebase (historical Maxwell International tooling). Current **shipping** scope:

- SQLite-backed auth (bcrypt passwords, documented **`admin`** / **`ChangeMeImmediately!`** bootstrap unless overridden, mandatory first-login **Set your password**; `password_change_required` gates `/api/admin/*`), integrations (encrypted credentials), audits, blog + carousel APIs, SPA with page visibility gates.
- Monitored endpoints (`/api/secrets`, standalone scanner URLs), data-room activity (`/api/secrets/explore`), access logging (`access_log`), alert rules engine, AI input guard + xAI-driven **AI Log Review**.
- Docker single-process deployment (`docker-entrypoint.sh` seeds admin once), persisted `/data` volume.

### Migrating older volumes and SQLite files

Infini’s **default on-disk database** is **`infini.sqlite`** (path from **`DATABASE_FILE`**: **`./data/infini.sqlite`** in dev, **`/data/infini.sqlite`** in Docker).

1. **Compose volume:** Older stacks may have used **`infinipot-data`** (InfiniPot era). This repo uses **`infini-data`**. Copy contents between volumes before cutover (see `docker volume ls`; names are often prefixed with the project directory).
2. **SQLite filename:** If you still have **`infinipot.sqlite`** on the **`/data`** volume (legacy InfiniPot default), rename once with the app stopped, e.g. **`mv /data/infinipot.sqlite /data/infini.sqlite`**, or set **`DATABASE_FILE`** explicitly until you merge data.
3. **`/api/health`:** **`service`** is **`infini`**. Update external monitors that asserted the previous string.

### Product vs legacy identifiers

| Area | Name |
| --- | --- |
| **Public product** | **Infini** (SPA, `package.json`, `/api/health` → `service: "infini"`) |
| **Default SQLite file** | **`infini.sqlite`** via **`DATABASE_FILE`** ([`.env.example`](.env.example), Docker **`/data/infini.sqlite`**) |
| **InfiniPot-era installs** | Rename **`infinipot-data`** / **`infinipot.sqlite`** using [Migrating older volumes](#migrating-older-volumes-and-sqlite-files) above |
| **Internal MI markers** | Cookie **`mi_session`**, **`/api/mi-verify`**, admin “MI Access” — Maxwell International lineage, kept intentionally |

The SQL table **`ai_honeypot_hits`** uses “honeypot” in the infosec sense; it is not the InfiniPot product name.

### Disclaimer

Infini is research / educational software. The security monitoring layer is designed to discourage unauthorized scraping; it is not a substitute for proper WAF, rate-limiting at the edge, or robots compliance for legitimate user agents. You are responsible for complying with all applicable laws in any deployment.

### License

TBD (likely AGPL-3.0 or MPL-2.0 — choose before public release).
