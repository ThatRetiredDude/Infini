# Operations

## Health check

**GET `/api/health`**

Returns JSON, for example:

```json
{ "ok": true, "service": "infini", "env": "production" }
```

- **`ok`** — process is up.
- **`service`** — always `infini` in current releases (update monitors if you migrated from older `infinipot` strings).
- **`env`** — `NODE_ENV` value.

Docker Compose uses this endpoint for the container [healthcheck](../docker-compose.yml).

## Smoke tests

With the API listening (host or container port):

```bash
SMOKE_BASE=http://127.0.0.1:3000 npm run smoke
```

Or:

```bash
SMOKE_BASE=http://127.0.0.1:3000 node server/scripts/smoke-check.mjs
```

Default base if unset: `http://127.0.0.1:${PORT||3000}`.

The script hits public routes (health, visibility, blog, carousel, beacon), verifies admin APIs return **401** without a session, and performs a few decoy-route checks—see [`server/scripts/smoke-check.mjs`](../server/scripts/smoke-check.mjs) for the exact list.
