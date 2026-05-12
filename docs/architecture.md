# Architecture

Single-process **Node 20** + **Express**. Static SPA from `dist/` after build; SQLite via **better-sqlite3** (WAL). No separate database or cache service.

## Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                  Infini container (Docker image)                 │
│                                                                   │
│  Express ─────────────────────────────────────────────────────┐   │
│   ├─ /api/health        liveness JSON (service: infini)       │   │
│   ├─ /api/auth/*        login, logout, me, change-password     │   │
│   ├─ /api/blog/* + /api/carousel   public (visibility-gated)    │   │
│   ├─ /api/site/visibility         page + API gates               │   │
│   ├─ /api/secrets/explore/*      data room (Turnstile, etc.)      │   │
│   ├─ /api/secrets/*               monitored decoy routes         │   │
│   ├─ /api/admin/integrations      encrypted integration creds     │   │
│   ├─ /api/admin/security/*       Security Hub, Tor exit feed,* …  │   │
│   ├─ /api/admin/*                blog, carousel, audits, AI, …    │   │
│   └─ /api/mi-verify              1×1 access-log beacon           │   │
│                                                                 │   │
│  *Tor: cached bulk exit list (Tor Project) for Security Hub UX   │   │
│                                                                   │
│  SQLite at DATABASE_FILE (default /data/infini.sqlite in Docker) │
│  Blog uploads under UPLOADS_DIR (default /data/uploads/)          │
│  Access CSV mirror under ACCESS_LOG_CSV_DIR (/data/logs/ in Dock.)│
└──────────────────────────────────────────────────────────────────┘
```

Root-level scanner-style paths (`/.env`, `/.git/config`, `/wp-admin`, `/openapi.json`, …) are registered on the **same app**—see [`server/index.js`](../server/index.js)—so hits are logged with distinct `source` values instead of silently falling through the SPA shell.

[`vite.config.js`](../vite.config.js) mirrors many of those paths through the proxy in **`npm run dev`** so instrumentation works there too—that path is optional for honeypot operators who only run Docker.

For background on **Tor feed** caching, see [`server/tor-feed.js`](../server/tor-feed.js).

## Security monitoring layers

| Layer | What | Where logged |
|---|---|---|
| **Monitored endpoints** | Internal-looking surfaces (`/api/secrets/system-prompt`, `/api/secrets/internal/dossier-dump`, `/.env`, `/.git/config`, `/wp-admin`, `/api/admin/api-keys`, `/openapi.json`, …) | `ai_honeypot_hits` (with `source` discriminator) |
| **Data room activity** | Procedurally generated 1M-page Arden Point Capital data-room tree under `/api/secrets/explore/*`, Cloudflare Turnstile-gated for repeat IPs, self-identification via `APC-ACCESS-ID:` token | `maze_hits` (per-IP/day aggregated) |
| **Input guard** | Prompt-injection / SQL / XSS / PII detector on real AI endpoints; auto-revokes AI access after N HIGH hits in 24h | `ai_input_flags` |
| **Access log** | Public page loads + hidden `/api/mi-verify` beacon, per-load token | `access_log` |
| **Alerts engine** | Email / Discord / Telegram / webhooks from rules | `security_alert_rules`, `security_alert_deliveries` |

Enrichment (ipinfo / AbuseIPDB / GreyNoise) feeds the admin **Security Hub** (tabs, geo/ASN, repeat offenders, firewall export snippets).

## AI Log Review

Legacy “AI Brief” flow is repurposed: select rows/alerts in the Security Hub → structured analysis via **xAI Grok** (default `grok-4.3-latest`, fallback `grok-latest`). Settings and encrypted keys live in `app_settings` and `integration_credentials`.

## Current scope

- **Auth:** bcrypt, JWT session cookie (`mi_session` by default). Bootstrap `admin` / `ChangeMeImmediately!` unless overridden; first login must **set a new password** (≥ 12 characters) before `/admin` and `/api/admin/*` work (`password_change_required`).
- **Surfaces:** Monitored endpoints, data room, access logging, alert engine, AI input guard, **AI Log Review**, blog + carousel, page visibility, Docker + persisted `/data`.

## Migrating older volumes and SQLite files

Default DB file is **`infini.sqlite`** (`DATABASE_FILE`: `./data/infini.sqlite` in the example env, `/data/infini.sqlite` in Compose).

1. **Compose volume:** Older stacks may have used **`infinipot-data`**. This repo uses **`infini-data`**. Copy data between volumes before cutover (`docker volume ls`; names are often prefixed by project directory).
2. **Filename:** If you still have **`infinipot.sqlite`** on disk, stop the app and e.g. `mv /data/infinipot.sqlite /data/infini.sqlite`, or point **`DATABASE_FILE`** at the legacy path until migrated.
3. **Health monitors:** `/api/health` reports **`service: "infini"`**—adjust external checks if they expected the old name.

## Product vs legacy identifiers

| Area | Name |
| --- | --- |
| **Public product** | **Infini** (`package.json` name `infini`, `/api/health` → `"infini"`) |
| **Default SQLite file** | **`infini.sqlite`** via **`DATABASE_FILE`** ([`.env.example`](../.env.example), Docker **`/data/infini.sqlite`**) |
| **InfiniPot-era installs** | Volumes/files named `infinipot-*` → see **Migrating** above |
| **Internal MI markers** | Cookie **`mi_session`**, **`/api/mi-verify`**, “MI Access” in admin — lineage label, intentional |

Table **`ai_honeypot_hits`** uses “honeypot” in the **infosec** sense—not the old product name InfiniPot.
