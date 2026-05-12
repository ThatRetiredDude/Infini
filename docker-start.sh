#!/bin/sh
# Start Cowrie in the background when enabled, then exec the main command (Node).
set -eu

# Friendly startup banner (cyan)
printf '\033[1;36m%s\033[0m\n' "Infini - A MaxwellInternational.ai project - @ThatRetiredDude on 𝕏 and GitHub"

if [ "${INFINI_NETWORK_HONEYPOT_ENABLED:-0}" = "1" ]; then
  export COWRIE_HOME="${COWRIE_HOME:-/data/cowrie}"
  if [ -x /opt/cowrie-install/venv/bin/python ] && [ -f /opt/cowrie-install/bin/cowrie ]; then
    # Run the Cowrie control script directly (it is a shell script with proper shebang)
    (cd /opt/cowrie-install && ./bin/cowrie start) || echo "[infini] cowrie start failed (honeypot disabled?)" >&2
  else
    echo "[infini] Cowrie not installed at /opt/cowrie-install — skipping honeypot" >&2
  fi
fi

exec "$@"
