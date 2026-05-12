# Configuration

Copy [`.env.example`](../.env.example) to `.env` and fill in values. Never commit `.env`.

Docker Compose loads `.env` automatically. [`docker-compose.yml`](../docker-compose.yml) maps **`HOST_PORT`** (default `3000`) to the container’s port `3000`; set `HOST_PORT` in `.env` if something else already uses 3000 on the host.

Compose also sets **`DATABASE_FILE=/data/infini.sqlite`**, **`UPLOADS_DIR=/data/uploads`**, **`ACCESS_LOG_CSV_DIR=/data/logs`**, **`NODE_ENV=production`**, and **`PORT=3000`** inside the container—these override the same keys from `.env` where defined in `docker-compose.yml`.

### Docker runtime secrets

On container start, [`docker-entrypoint.sh`](../docker-entrypoint.sh) resolves **`JWT_SECRET`** and **`INTEGRATION_ENCRYPTION_KEY`** in this order for the container process (after optional DB reset flags may run):

Persisted files live under **`/data/.secrets/`** on the Compose volume (`jwt_secret`, `integration_encryption_key`). — If the variable is **valid**, it is used as-is (Compose `env_file` / `.env` wins).
   - `JWT_SECRET`: non-empty and at least **32** characters.
   - `INTEGRATION_ENCRYPTION_KEY`: exactly **64 hexadecimal** characters (32 bytes), matching [`server/crypto.js`](../server/crypto.js).
2. **Persisted file** on the volume: `/data/.secrets/jwt_secret` and `/data/.secrets/integration_encryption_key` (mode `600`; directory mode `700`).
3. **Generate** with Node `crypto`, write the file, **`export`** for the process — one stderr notice per generated secret (values are never logged).

Invalid-but-nonempty env values (wrong length or bad hex) are **ignored** with a stderr warning; the entrypoint falls through to the persisted file or a new generated secret.

**Backups:** include the whole **`/data`** volume (SQLite, uploads, logs CSV mirror, and **`/data/.secrets`**). If you change `INTEGRATION_ENCRYPTION_KEY` without keeping the old key, existing encrypted integration rows cannot be decrypted.

### Danger — optional SQLite reset (dev / lab only)

**Never** enabled by secret rotation or auto-generation. To delete the main SQLite database file (and `-wal` / `-shm` siblings) **once** before `seed-admin` runs, set **both**:

| Variable | Required value |
| --- | --- |
| `INFINI_RESET_DATABASE` | `1` |
| `INFINI_CONFIRM_DATABASE_RESET` | `YES` (exact string; not `yes`) |

The entrypoint logs a clear stderr line when files were removed. Remove both variables after the reset. Do **not** rely on this for production workflows; `/data/.secrets` is **not** deleted (avoids accidental mass lockout).

**Manual checks:** Fresh Compose volume + minimal `.env` → container logs up to two auto-generation notices on first boot, login works, integrations UI can save credentials; second restart reuses `/data/.secrets` files without regenerating. Set valid secrets in `.env` → entrypoint prefers env over files. Dual reset flags → SQLite removed once only when both match exactly; secret auto-generation alone never deletes the DB.

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
| `JWT_SECRET` | At least **32** characters for login/sessions. **Docker:** optional if omitted or invalid — generated and persisted under `/data/.secrets/jwt_secret` (see [Docker runtime secrets](#docker-runtime-secrets)). |
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
| `INTEGRATION_ENCRYPTION_KEY` | **64 hex chars** (32 bytes) for encrypting integration credentials in the DB. Generate: `openssl rand -hex 32`. **Docker:** optional if omitted or invalid — generated and persisted under `/data/.secrets/integration_encryption_key` (see [Docker runtime secrets](#docker-runtime-secrets)). |

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
