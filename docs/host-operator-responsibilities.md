# Host Operator Responsibilities

Infini is deliberately designed as a **single-container, zero-dependency** system (Node + optional Cowrie + SQLite on a Docker volume). This makes initial setup trivial, but it shifts most security and operational responsibilities to the person running the host (VPS, bare metal, or cloud instance).

## Contents

- [What Infini Automates for You](#what-infini-automates-for-you)
- [What You Must Do Manually on the Host](#what-you-must-do-manually-on-the-host)
  - [1. Host Environment & Docker Basics](#1-host-environment--docker-basics)
  - [2. Networking, Firewall & Exposure Control (Critical)](#2-networking-firewall--exposure-control-critical)
  - [3. Secrets & Credential Hygiene](#3-secrets--credential-hygiene)
  - [4. Host OS & Docker Hardening](#4-host-os--docker-hardening)
  - [5. Blog & Content Operations](#5-blog--content-operations)
  - [6. Ongoing Maintenance & Compliance](#6-ongoing-maintenance--compliance)
- [Quick Reference Table](#quick-reference-table)
- [Related Documentation](#related-documentation)

## What Infini Automates for You

- **First-boot secrets**: If `JWT_SECRET` or `INTEGRATION_ENCRYPTION_KEY` are missing/invalid in `.env`, the entrypoint (`docker-entrypoint.sh`) generates cryptographically strong values and persists them under `/data/.secrets/` (never logged, 600 perms).
- **Admin bootstrap**: Creates the `admin` user (or uses `SEED_ADMIN_*` values) and forces a password change (≥12 chars) on first login via the SPA.
- **Database**: Auto-runs schema creation/migrations on startup (`ensureSchema`).
- **Cowrie (when enabled)**: Clones v2.6.1 at image build time, prepares config dirs + optional Telnet patch, starts it in the background via `docker-start.sh`, and tails its JSON logs into SQLite for the Security Hub.
- **Security middleware**: Helmet headers, login rate-limiting (10/min), CSRF protection, CORS (configurable), body-size limits, `trust proxy`, session cookies, MFA/TOTP support, password-change gates.
- **Blog & content**: Slug sanitization, prepared-statement queries (no SQLi), client-side DOMPurify sanitization of rich-text posts, cover-image URL storage (no server-side file upload handling for covers).
- **Honeypot lures**: All the monitored endpoints (`/.env`, `/wp-admin`, Jenkins, AWS creds, data-room maze, etc.) are built-in and log hits with source discriminators.
- **Operational features**: Healthcheck endpoint, access-log CSV mirroring, IP enrichment (ipinfo/AbuseIPDB/GreyNoise), alerts engine (email/webhook/Discord/Telegram), AI log review hooks, Tor exit feed caching, artifact retention sweep for Cowrie downloads.
- **Updates**: DB schema changes are forward-compatible; `docker compose up -d --build` is sufficient.

In short: once the container is running, the **application layer** (auth, logging, lures, blog, monitoring) is fully self-contained and requires no external services.

## What You Must Do Manually on the Host

These steps are **outside the container** and cannot be fully automated by the current codebase.

### 1. Host Environment & Docker Basics

- Install Docker + Docker Compose (or Podman equivalent) on the host OS.
- Clone the repo, `cp .env.example .env`, edit as needed.
- Run `docker compose up -d --build`.
- (Optional but recommended) Use a `.env` override or Compose profiles for production values (strong `SEED_ADMIN_PASSWORD`, real API keys, `ENFORCE_HTTPS=true`, `COOKIE_SECURE=true`, `CORS_ORIGINS`).

### 2. Networking, Firewall & Exposure Control (Critical)

- Configure the host firewall (ufw, firewalld, nftables, or cloud security groups) to **explicitly allow only** the published ports (default 3000 for web/blog, 2222/2223 for Cowrie SSH/Telnet) and block/reject everything else.
- Place a reverse proxy (Caddy, nginx, Traefik) in front for TLS termination, additional rate-limiting, and WAF rules. Set `ENFORCE_HTTPS` and `COOKIE_SECURE` accordingly.
- **Strongly recommended**: Run the entire stack on a dedicated isolated VLAN/subnet with strict egress filtering (no direct routes to production networks). The current `docker-compose.yml` uses the default Docker bridge — this is a deliberate simplicity choice, not a secure default.
- Restrict egress from the container/host where possible (honeypots should not be able to initiate arbitrary outbound connections to the internet or other internal systems).
- Cloud-specific: AWS Security Groups, GCP firewall rules, Azure NSGs, etc., must be configured by the operator.

#### Production: Reverse Proxy vs Cloudflare Tunnel

For internet-facing deployments, choose one of two supported approaches (detailed in [Production Deployment](production-deployment.md)):

- **Recommended (Path A)**: Run a traditional reverse proxy (Caddy or nginx) on the host on ports 80/443. This keeps standard honeypot ports (21, 22, 3306, etc.) publicly reachable and maximizes automated scanner hits.
- **Advanced (Path B)**: Use Cloudflare Tunnel (`cloudflared`). This hides the origin IP but significantly reduces visibility from mass scanners and Shodan-style indexing because many tools do not follow Tunnel origins.

See the new guide for step-by-step Caddy, nginx, and Tunnel instructions plus the visibility trade-off table.

#### Firewall Tool Options

Multiple host firewall tools are available. Choose one that matches your Linux distribution and comfort level:

- **ufw** (Uncomplicated Firewall) — Simple CLI, default on Ubuntu/Debian.
- **firewalld** — Dynamic zones, common on Fedora/RHEL/CentOS.
- **nftables** — Modern replacement for iptables, powerful and flexible.
- **Cloud Security Groups** — AWS, GCP, Azure, DigitalOcean, etc. — often the primary control in cloud environments.

**Detailed instructions for ufw (user's preferred tool):**

```bash
# Install if not present (Ubuntu/Debian)
sudo apt update && sudo apt install ufw -y

# Set default policies (deny incoming, allow outgoing)
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH to the host itself (change port if non-standard)
sudo ufw allow 22/tcp

# Allow Infini web/blog (port 3000 or your HOST_PORT)
sudo ufw allow 3000/tcp

# Allow Cowrie honeypot ports (enabled by default via INFINI_NETWORK_HONEYPOT_ENABLED=1)
sudo ufw allow 2222/tcp comment 'Cowrie SSH honeypot'
sudo ufw allow 2223/tcp comment 'Cowrie Telnet honeypot'

# Enable the firewall
sudo ufw enable

# Check status
sudo ufw status verbose
```

For production, also allow your reverse proxy port (usually 80/443) and consider rate-limiting with `ufw limit`.

### 3. Secrets & Credential Hygiene (beyond auto-generation)

- Provide strong values for `SEED_ADMIN_PASSWORD`, `XAI_API_KEY`, SMTP creds, Turnstile keys, integration keys, etc., via `.env` (never commit them).
- After first login, immediately enable MFA in the admin UI.
- Periodically rotate `JWT_SECRET` / `INTEGRATION_ENCRYPTION_KEY` (requires volume backup strategy — old encrypted rows become unreadable without the prior key).
- Backup the entire `infini-data` volume regularly.

### 4. Host OS & Docker Hardening (code cannot enforce this)

- Keep the host kernel, Docker daemon, and base OS packages patched.
- Run Docker in rootless mode if feasible.
- Add security options to the container (read-only filesystem, seccomp profile, `cap_drop: [ALL]`, `pids_limit`, memory limits) — these require editing `docker-compose.yml` or using an override file.
- Consider separating Cowrie into its own container (recommended for stronger isolation; current design shares the `infini` user + `/data` volume).
- Install host-level intrusion detection / runtime security (e.g., Falco, auditd) and monitor for container escapes.
- Set up fail2ban or equivalent on the host SSH port itself (the honeypot ports are intentionally attractive).

### 5. Blog & Content Operations

- When creating posts via the admin editor, be mindful that `cover_image_url` accepts arbitrary external URLs (no server-side allow-listing).
- Use the page-visibility controls and blog publishing workflow responsibly.

### 6. Ongoing Maintenance & Compliance

- Monitor the Security Hub, alerts, and host logs.
- Update the stack (`docker compose pull && docker compose up -d --build`).
- Review jurisdiction-specific laws around honeypots, logging, and data retention.
- Test lures and verify that hits appear in the admin interface after initial deployment.

## Quick Reference Table

| Area                        | Automated by Infini (container)                          | Must be done manually by host operator                          |
|-----------------------------|----------------------------------------------------------|-----------------------------------------------------------------|
| Secrets generation          | Yes (JWT + encryption key on first boot)                 | Provide strong admin password, API keys, SMTP, etc. in .env    |
| Auth & middleware           | Full (rate limits, CSRF, MFA, helmet, etc.)              | Enable MFA after login; configure HTTPS proxy                  |
| Database / schema           | Automatic migrations                                     | Backup the volume; plan for key rotation                       |
| Honeypot lures + logging    | All built-in + Cowrie ingestion                          | Firewall the ports; decide whether to enable Cowrie            |
| Networking / isolation      | None (uses default bridge)                               | Firewall, reverse proxy, VLAN/subnet, egress rules, TLS        |
| Container hardening         | Non-root `infini` user                                   | read_only, seccomp, resource limits, separate Cowrie container |
| Host OS / Docker            | None                                                     | Patching, rootless Docker, runtime monitoring, backups         |
| Blog content                | Slug sanitization, client-side HTML sanitization         | Trusted cover images, responsible publishing                   |
| Updates & operations        | Healthchecks, smoke tests, auto-start                    | Regular updates, log monitoring, legal review                  |

**Bottom line**: The container makes the *honeypot/blog application* turnkey and self-contained. Everything that touches the actual security posture of the **host device and network** (firewalling, TLS, isolation, host hardening, egress control) must be implemented by the person setting up the server. The security assessment highlighted exactly these gaps; the code does not (and cannot) enforce them.

For production use, treat the current `docker-compose.yml` as a convenient starting point and layer the manual controls on top.

## Related Documentation

- [Getting Started](getting-started.md) — First run instructions
- [Security & Deployment](security-deployment.md) — HTTPS, CORS, disclaimers
- [Cowrie Honeypot Details](honeypot-cowrie.md) — Optional SSH/Telnet honeypot
- [Operations](operations.md) — Backups, updates, health checks
