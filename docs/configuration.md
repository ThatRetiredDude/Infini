# Configuration

Copy [`.env.example`](../.env.example) to `.env` and fill in values. Never commit `.env`.

Docker Compose loads `.env` automatically. [`docker-compose.yml`](../docker-compose.yml) maps **`HOST_PORT`** (default `3000`) to the container’s port `3000`; set `HOST_PORT` in `.env` if something else already uses 3000 on the host.

Compose also sets **`DATABASE_FILE=/data/infini.sqlite`**, **`UPLOADS_DIR=/data/uploads`**, **`ACCESS_LOG_CSV_DIR=/data/logs`**, **`NODE_ENV=production`**, and **`PORT=3000`** inside the container—these override the same keys from `.env` where defined in `docker-compose.yml`.

Below follows the sections in `.env.example`.

## Server

| Variable | Notes |
| --- | --- |
| `NODE_ENV` | `development` locally; production in Docker image. |
| `PORT` | API listen port (3000 in Docker). |
| `PUBLIC_BASE_URL` | Used for absolute URLs where needed. |
| `PUBLIC_SITE_ORIGIN` | Blog publish webhooks, etc. |
| `DISABLE_SECURITY_ALERT_SCHEDULER` | Set `1` to silence the alert cron loop (tests / debugging). |

## Database

| Variable | Notes |
| --- | --- |
| `DATABASE_FILE` | SQLite path. Default in example: `./data/infini.sqlite`; in Compose: `/data/infini.sqlite` on the persisted volume. |

## Auth

| Variable | Notes |
| --- | --- |
| `JWT_SECRET` | **Required.** At least 32 characters (see generate hint in `.env.example`). |
| `JWT_EXPIRES_IN` | Session lifetime (e.g. `7d`). |
| `COOKIE_NAME` | Default `mi_session`. |
| `COOKIE_DOMAIN` | Usually empty; set if serving under a subdomain setup. |
| `COOKIE_SECURE` | `false` for plain HTTP (e.g. local Docker). **`true`** behind HTTPS only. |

### Seed admin (first boot)

Created only if no admin user exists yet. Same script runs locally and in [`docker-entrypoint.sh`](../docker-entrypoint.sh).

| Variable | Notes |
| --- | --- |
| `SEED_ADMIN_USERNAME` | Default `admin`. |
| `SEED_ADMIN_PASSWORD` | If unset or empty, bootstrap password is **`ChangeMeImmediately!`**. |
| `SEED_ADMIN_EMAIL` | Stored on the seeded user. |
| `SEED_ADMIN_OVERWRITE_PASSWORD` | One-shot: set `1` with `SEED_ADMIN_PASSWORD` to reset an existing admin hash; remove after use. |

## Encryption

| Variable | Notes |
| --- | --- |
| `INTEGRATION_ENCRYPTION_KEY` | **Required** for storing integration API keys in the DB. 64 hex chars (32 bytes). Generate: `openssl rand -hex 32`. |

## Data room (Turnstile)

| Variable | Notes |
| --- | --- |
| `TURNSTILE_SITE_KEY` | Optional; challenges repeat visitors. |
| `TURNSTILE_SECRET_KEY` | Server-side verification. |

## AI input guard

| Variable | Notes |
| --- | --- |
| `AI_GUARD_HIGH_REVOKE_THRESHOLD` | Auto-revoke after N HIGH findings in window. |
| `AI_GUARD_IP_DENSITY_THRESHOLD` | IP density tuning. |

## AI Log Review (xAI)

| Variable | Notes |
| --- | --- |
| `XAI_API_KEY` | Optional if you store the key via admin Integrations UI instead. |
| `AI_LOG_REVIEW_MODEL` | Default `grok-4.3-latest`. |
| `AI_LOG_REVIEW_FALLBACK_MODEL` | Default `grok-latest`. |

## Blog publish hooks

| Variable | Notes |
| --- | --- |
| `BLOG_PUBLISH_WEBHOOK_URL` | Optional outbound webhook on publish. |
| `BLOG_PUBLISH_WEBHOOK_SECRET` | Shared secret for the hook. |

## Mail (alert engine)

SMTP variables in `.env.example` when using email delivery for security alerts.

## Misc

| Variable | Notes |
| --- | --- |
| `ACCESS_LOG_CSV_DIR` | CSV mirror of access log (Docker: typically `/data/logs` via Compose). |
