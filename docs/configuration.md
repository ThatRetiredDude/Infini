# Configuration

All settings are controlled via environment variables in `.env` (copy from `.env.example`).

## Contents

- [Docker Runtime Secrets](#docker-runtime-secrets)
- [Server Settings](#server-settings)
- [Database](#database)
- [Authentication](#authentication)
- [Encryption](#encryption)
- [Data Room (Turnstile)](#data-room-turnstile)
- [AI Features](#ai-features)
- [Alerts & Mail](#alerts--mail)
- [Blog & Misc](#blog--misc)
- [Danger Flags](#danger-flags)

## Docker Runtime Secrets

On first boot, if `JWT_SECRET` or `INTEGRATION_ENCRYPTION_KEY` are missing or invalid, the entrypoint script automatically generates them and stores them in `/data/.secrets/` (never logged).

Valid values in `.env` always take precedence.

**Backups:** Always include the entire `/data` volume.

## Server Settings

| Variable                    | Description                                      | Default          |
|-----------------------------|--------------------------------------------------|------------------|
| NODE_ENV                    | development / production                         | production (in Docker) |
| PORT                        | Listen port                                      | 3000             |
| PUBLIC_BASE_URL             | Used for absolute URLs                           | http://localhost:3000 |
| PUBLIC_SITE_ORIGIN          | For webhooks etc.                                | same as above    |
| DISABLE_SECURITY_ALERT_SCHEDULER | Set 1 to pause alerts (testing)             | 0                |

**Production note**: When deploying behind a domain + TLS (Caddy, nginx, or Cloudflare Tunnel), set `PUBLIC_BASE_URL=https://yourdomain.com`, `ENFORCE_HTTPS=true`, `COOKIE_SECURE=true`, and `CORS_ORIGINS=https://yourdomain.com`. See [Production Deployment](production-deployment.md) for full details.

## Database

`DATABASE_FILE` — Path to SQLite. In Docker: `/data/infini.sqlite`

## Authentication

- `JWT_SECRET`: ≥32 chars (auto-generated in Docker)
- `JWT_EXPIRES_IN`: e.g. `7d`
- `COOKIE_NAME`: `mi_session`
- `COOKIE_SECURE`: `false` for HTTP, `true` for HTTPS-only
- `SEED_ADMIN_*`: Bootstrap admin credentials (password change forced on first login)

## Encryption

`INTEGRATION_ENCRYPTION_KEY`: Exactly 64 hex characters (32 bytes). Used to encrypt third-party credentials. Auto-generated if omitted.

## Data Room (Turnstile)

Optional Cloudflare Turnstile keys for the infinite maze to challenge repeat visitors.

## AI Features

- `AI_GUARD_*` thresholds for input sanitization
- `XAI_API_KEY` or store via UI for Grok log review
- Model selection for AI Log Review

## Alerts & Mail

SMTP settings + webhook secrets for the alert delivery engine.

## Blog & Misc

- `BLOG_PUBLISH_WEBHOOK_*`
- `ACCESS_LOG_CSV_DIR`

## Danger Flags (dev/lab only)

`INFINI_RESET_DATABASE=1` + `INFINI_CONFIRM_DATABASE_RESET=YES` — wipes SQLite once on next boot. Remove after use. Does **not** affect secrets.

For the full `.env.example` with comments, see the file in the repository root.