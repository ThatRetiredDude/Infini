# Operations

Day-to-day running, health checks, and maintenance.

## Contents

- [Health Check](#health-check)
- [Smoke Tests](#smoke-tests)
- [Logs and Data Locations](#logs-and-data-locations)
- [Backups](#backups)
- [Updating](#updating)

## Health Check

**GET `/api/health`**

Returns JSON status including Cowrie status when enabled.

Used by Docker Compose healthcheck.

Example response includes service name, environment, and optional Cowrie metadata.

## Smoke Tests

Run from host:

```bash
SMOKE_BASE=http://127.0.0.1:3000 npm run smoke
```

Or directly:

```bash
node server/scripts/smoke-check.mjs
```

Verifies public routes, admin auth requirements, and several lure responses.

## Logs and Data Locations

Inside the container (persisted via `infini-data` volume):

- SQLite DB: `/data/infini.sqlite`
- Uploads: `/data/uploads/`
- Access log CSV mirror: `/data/logs/`
- Secrets (auto-generated): `/data/.secrets/`
- Cowrie home (if enabled): `/data/cowrie/`

## Backups

Simply back up the entire `/data` volume (or bind-mount). 

**Important:** If you rotate `INTEGRATION_ENCRYPTION_KEY`, old encrypted rows become unreadable unless you keep the previous key.

## Updating

Pull latest code, rebuild the image:

```bash
docker compose pull
docker compose up -d --build
```

Database migrations run automatically on startup.