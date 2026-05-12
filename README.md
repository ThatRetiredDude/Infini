# InfiniPot

**Work in progress.** Behavior, APIs, security surfaces, and documentation may change without notice. Treat production deployments as experimental until you pin a release and review configuration yourself.

## How to run

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
npm run db:init
npm run db:seed-admin
npm run dev
```

- Frontend (Vite): <http://localhost:5173>
- API (Express): <http://localhost:3000/api>

**First admin:**

- **`SEED_ADMIN_USERNAME`** defaults to **`admin`**; **`SEED_ADMIN_PASSWORD`** is **optional**.
- Omitting the env password prints a one-time **`[seed-admin] BOOTSTRAP_PASSWORD=…`** line to stderr when you run `npm run db:seed-admin`.

**After Sign in:**

- The SPA prompts **Set your password** until you submit a replacement. New passwords must be at least **12** characters (`POST /api/auth/change-password`).
- Until then, **`/api/admin/*`** returns **`403`** with **`password_change_required`**. Only **bcrypt** hashes are stored in SQLite (`users.password_change_required` tracks the gate).

### Docker (production-like)

Rebuilds (`--build`) replace image layers only. SQLite, uploads, and logs live in the Compose volume **`infinipot-data`** (mounted at **`/data`** in the container); rebuilding does not wipe that data unless you remove the volume on purpose.

On **each container start**, **`docker-entrypoint.sh`** runs the same flow as **`npm run db:seed-admin`**, then starts the API (`tini`, then `node server/index.js`). If **no admin** exists yet, one is created with `SEED_ADMIN_USERNAME`, optional `SEED_ADMIN_PASSWORD`, optional `SEED_ADMIN_EMAIL`. With **no env password**, a random bootstrap password is logged once (see **`docker logs infinipot`** and search for **`BOOTSTRAP_PASSWORD=`**). If you **set** `SEED_ADMIN_PASSWORD`, it is bcrypt-hashed like any password and never printed. Every **newly seeded** admin starts with **`password_change_required`** and must complete **Set your password** in the app before admin APIs work. Idempotent seed: if an admin already exists, the script skips.

```bash
cp .env.example .env   # JWT_SECRET, INTEGRATION_ENCRYPTION_KEY; optional SEED_ADMIN_*
docker compose up --build -d
```

Open **http://localhost:3000** unless you set a different **`HOST_PORT`** in `.env` (see [`docker-compose.yml`](docker-compose.yml)).

For production **either** rely on tightly controlled orchestration logs when using bootstrap output **or** set `SEED_ADMIN_PASSWORD` in `.env` so the initial secret never appears in logs.

To reinstall from scratch (new SQLite and uploads), remove the named volume deliberately (destructive): `docker compose down`, then `docker volume rm …` for your `infinipot-data` volume (check `docker volume ls`; Compose often prefixes the volume name with the project directory).

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
│   ├─ /api/secrets/*    monitored endpoints + data room      │    │
│   ├─ /api/admin/*      admin-gated CRUD + Security Hub      │    │
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

- SQLite-backed auth (bcrypt passwords, optional random seed bootstrap, first-login **Set your password** rotation; `password_change_required` gate on `/api/admin/*`), integrations (encrypted credentials), audits, blog + carousel APIs, SPA with page visibility gates.
- Monitored endpoints (`/api/secrets`, standalone scanner URLs), data-room activity (`/api/secrets/explore`), access logging (`access_log`), alert rules engine, AI input guard + xAI-driven **AI Log Review**.
- Docker single-process deployment (`docker-entrypoint.sh` seeds admin once), persisted `/data` volume.

## Disclaimer

InfiniPot is research / educational software. The security monitoring layer is designed to discourage unauthorized scraping; it is not a substitute for proper WAF, rate-limiting at the edge, or robots compliance for legitimate user agents. You are responsible for complying with all applicable laws in any deployment.

## License

TBD (likely AGPL-3.0 or MPL-2.0 — choose before public release).
