#!/bin/sh
set -eu

# ─── Optional destructive DB reset (dual-flag, dev/lab only) ─────────────────
if [ "${INFINI_RESET_DATABASE:-}" = "1" ] && [ "${INFINI_CONFIRM_DATABASE_RESET:-}" = "YES" ]; then
  db="${DATABASE_FILE:-}"
  if [ -n "$db" ]; then
    removed=false
    for f in "$db" "$db-wal" "$db-shm"; do
      if [ -f "$f" ]; then
        rm -f "$f"
        removed=true
      fi
    done
    if [ "$removed" = true ]; then
      echo "[entrypoint] Removed SQLite database files for ${db} (INFINI_RESET_DATABASE=1 and INFINI_CONFIRM_DATABASE_RESET=YES)." >&2
    fi
  fi
fi

SECRETS_DIR=/data/.secrets
JWT_FILE="$SECRETS_DIR/jwt_secret"
INT_FILE="$SECRETS_DIR/integration_encryption_key"

mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

# ─── JWT_SECRET (env → persisted file → generate) ────────────────────────────
jwt_env_ok=false
if [ -n "${JWT_SECRET:-}" ] && [ "${#JWT_SECRET}" -ge 32 ]; then
  jwt_env_ok=true
elif [ -n "${JWT_SECRET:-}" ]; then
  echo "[entrypoint] JWT_SECRET is set but invalid (need >= 32 characters); ignoring — using persisted file or generating a new secret." >&2
fi

JWT_RESOLVED=
if [ "$jwt_env_ok" = true ]; then
  JWT_RESOLVED=$JWT_SECRET
else
  if [ -f "$JWT_FILE" ]; then
    JWT_RESOLVED=$(tr -d '\r\n' < "$JWT_FILE")
    if [ "${#JWT_RESOLVED}" -lt 32 ]; then
      echo "[entrypoint] Persisted jwt_secret is invalid (need >= 32 characters); regenerating." >&2
      JWT_RESOLVED=
    fi
  fi
  if [ -z "$JWT_RESOLVED" ]; then
    JWT_RESOLVED=$(node -p "require('crypto').randomBytes(48).toString('hex')")
    printf '%s' "$JWT_RESOLVED" > "$JWT_FILE"
    chmod 600 "$JWT_FILE"
    echo "[entrypoint] Auto-generated JWT_SECRET and persisted to ${JWT_FILE} (value not logged)." >&2
  fi
fi
export JWT_SECRET="$JWT_RESOLVED"

# ─── INTEGRATION_ENCRYPTION_KEY (64 hex chars; env → file → generate) ─────────
integration_env_ok=false
if [ -n "${INTEGRATION_ENCRYPTION_KEY:-}" ]; then
  if printf '%s' "$INTEGRATION_ENCRYPTION_KEY" | node -e "
const k = require('fs').readFileSync(0, 'utf8').trim();
process.exit(/^[0-9a-fA-F]{64}$/.test(k) ? 0 : 1);
" 2>/dev/null; then
    integration_env_ok=true
  else
    echo "[entrypoint] INTEGRATION_ENCRYPTION_KEY is set but invalid (need 64 hex characters); ignoring — using persisted file or generating a new key." >&2
  fi
fi

INT_RESOLVED=
if [ "$integration_env_ok" = true ]; then
  INT_RESOLVED=$INTEGRATION_ENCRYPTION_KEY
else
  if [ -f "$INT_FILE" ]; then
    INT_RESOLVED=$(tr -d '\r\n' < "$INT_FILE")
    if ! printf '%s' "$INT_RESOLVED" | node -e "
const k = require('fs').readFileSync(0, 'utf8').trim();
process.exit(/^[0-9a-fA-F]{64}$/.test(k) ? 0 : 1);
" 2>/dev/null; then
      echo "[entrypoint] Persisted integration_encryption_key is invalid; regenerating." >&2
      INT_RESOLVED=
    fi
  fi
  if [ -z "$INT_RESOLVED" ]; then
    INT_RESOLVED=$(node -p "require('crypto').randomBytes(32).toString('hex')")
    printf '%s' "$INT_RESOLVED" > "$INT_FILE"
    chmod 600 "$INT_FILE"
    echo "[entrypoint] Auto-generated INTEGRATION_ENCRYPTION_KEY and persisted to ${INT_FILE} (value not logged)." >&2
  fi
fi
export INTEGRATION_ENCRYPTION_KEY="$INT_RESOLVED"

node server/scripts/seed-admin.js

if [ "${INFINI_NETWORK_HONEYPOT_ENABLED:-0}" = "1" ]; then
  node server/scripts/prepare-cowrie-config.mjs || echo "[entrypoint] prepare-cowrie-config failed (non-fatal)" >&2
fi

exec "$@"
