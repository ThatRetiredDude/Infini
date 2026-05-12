# Cowrie network honeypot

Cowrie is **enabled by default** (`INFINI_NETWORK_HONEYPOT_ENABLED=1` in `.env`).

When enabled, the Docker image starts **[Cowrie](https://github.com/cowrie/cowrie)** alongside the Node app. Infini tails Cowrie’s JSON log into the **`network_sensor_events`** SQLite table, reuses passive IP enrichment, and surfaces events in **Security Hub → Network sensor**.

To disable Cowrie entirely, set `INFINI_NETWORK_HONEYPOT_ENABLED=0`.

## Licensing

Cowrie is distributed under **GNU GPL v2**. Bundling Cowrie **inside** the same container/image as your application may create a **combined work** under the GPL. If you redistribute that image, understand your obligations (source offer, license compatibility with your app’s license, etc.). This is not legal advice.

If you cannot accept GPL constraints, run Cowrie as a **separate** container/service, ingest only its logs into Infini over a volume or HTTP, or omit the honeypot feature entirely.

## Ports (defaults)

| Service | Container port | Compose host var (default) |
|--------|------------------|-----------------------------|
| SSH honeypot | 2222 | `HOST_SSH_HONEYPOT_PORT` → 2222 |
| Telnet honeypot | 2223 | `HOST_TELNET_HONEYPOT_PORT` → 2223 |

**Cloudflare Tunnel note**: When running behind Cloudflare Tunnel, the SSH/Telnet honeypots are reachable only through the tunnel. Many mass scanners do not follow Tunnel origins, reducing automated discovery of the interactive SSH surface.

Telnet is disabled in Cowrie’s stock config; set **`COWRIE_TELNET_ENABLED=1`** so the entrypoint patches `[telnet] enabled = true` before Cowrie starts.

## Data layout

- **`COWRIE_HOME`** (default `/data/cowrie` in Docker): config, logs, downloads. Persisted on the Compose volume with the rest of `/data`.
- **`COWRIE_JSON_LOG`**: optional override for the JSON log path; otherwise Infini infers `var/log/cowrie/cowrie.json` under `COWRIE_HOME`.

## Artifact retention

Downloaded files live under Cowrie’s download path; Infini runs a **best-effort** sweep on an interval (see **`COWRIE_ARTIFACT_RETENTION_DAYS`**, default 14) to delete old files—**not** a full malware lab workflow; tune or disable by not enabling the honeypot.
