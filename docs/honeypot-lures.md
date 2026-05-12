# Honeypot Lures Inventory

This document catalogs every decoy surface in Infini, the exact `source` discriminator written to `ai_honeypot_hits`, and the response style. The goal is maximum scanner coverage with realistic interactive feedback on every endpoint.

The infinite data-room maze (`/api/secrets/explore/*`) is deliberately excluded from this table — it lives in `maze_hits` and is designed to never terminate.

## Monitored Endpoints (standalone paths)

| Path(s) | Source discriminator | Response style |
|---------|----------------------|----------------|
| `/.env*`, `/api/.env` | `env_probe` | Plain-text fake environment file |
| `/.git/config` | `git_config_probe` | Git config with internal remote |
| `/.git/HEAD` | `git_head_probe` | `ref: refs/heads/main` |
| `/.aws/credentials`, `/.aws/config` | `aws_creds_probe` | AWS credential file snippet |
| `/.docker/config.json` | `docker_config_probe` | Docker auths JSON |
| `/wp-admin*`, `/wp-login.php`, `/xmlrpc.php` | `wp_admin_probe` | WordPress login form (POST returns form) |
| `/phpmyadmin*` | `phpmyadmin_probe` | phpMyAdmin login form |
| `/adminer*` | `adminer_probe` | Adminer login form |
| `/openapi.json`, `/swagger.json`, `/api/docs.json` | `openapi_probe` | OpenAPI 3.0 document |
| `/api/keys*`, `/api/admin/api-keys` | `api_keys_probe` | 401 JSON with hint |
| `/api/internal/debug*` | `internal_debug_probe` | 401 JSON uptime/memory |
| `/backup*`, `/backups/*`, `/dump.sql` | `backup_probe` | JSON list of backup files |
| `/.well-known/security.txt` | `security_txt_probe` | Valid security.txt + canary |
| `/robots.txt` | `robots_probe` | robots.txt pointing to disallowed internal paths |

## Internal Secrets Routes (`/api/secrets/*`)

| Path | Source | Response |
|------|--------|----------|
| `/api/secrets/system-prompt` | `system_prompt_probe` | JSON policy object (slow) |
| `/api/secrets/internal/dossier-dump` | `dossier_dump_probe` | JSON partial dump (slow) |
| `/api/secrets/eval` (POST) | `eval_probe` | 202 queued job (slow) |
| `/api/secrets/eval/results` | `eval_results_probe` | 404 run_id not found (slow) |

## Easy High-Coverage HTTP Lures (added 2026)

All provide interactive feedback: login forms accept POST and return plausible error pages or refreshed forms.

| Path(s) | Source | Response style |
|---------|--------|----------------|
| `/jenkins*`, `/jenkins/j_acegi_security_check` (POST) | `jenkins_probe` | Jenkins login form → "Invalid username or password" |
| `/users/sign_in*`, `/gitlab/` | `gitlab_probe` | GitLab sign-in form → invalid login message |
| `/login`, `/grafana/` | `grafana_probe` | Grafana login → invalid credentials |
| `/actuator*` (`/env`, `/health`, `/beans`) | `actuator_probe` | Spring Boot Actuator JSON (beans, health, env with secrets) |
| `/owa*`, `/owa/auth.owa` (POST) | `owa_probe` | Outlook Web App login → auth failed |
| `/solr*` | `solr_probe` | Solr admin JSON response |
| `/console*`, `/signin` | `aws_console_probe` | AWS Console sign-in form |
| `/ecp*`, `/ecp/default.aspx` | `ecp_probe` | Exchange Admin Center login form |

## Corporate Intranet (`/intranet/*` — finite, non-maze)

| Path | Source | Response style |
|------|--------|----------------|
| `/intranet`, `/intranet/login` (GET+POST) | `intranet_login_probe` | APC-branded login form → "Invalid credentials" |
| `/intranet/dashboard` (GET+POST) | `intranet_dashboard_probe` | Dashboard with links to HR/Finance/IT + session refresh |
| `/intranet/hr/employees*` | `intranet_hr_probe` | Employee table + search form |
| `/intranet/hr/benefits*` | `intranet_hr_probe` | Benefits update form → "Update submitted" |
| `/intranet/finance/ledgers*` | `intranet_finance_probe` | Ledger table + reconciliation request |
| `/intranet/it/tickets*` | `intranet_it_probe` | Ticket form → "Ticket #IT-xxx created" |

## Network Banner Sidecar (ports 21, 3306, 5432)

The sidecar container (`honeypot-sidecar`) now includes a full MySQL protocol responder on 3306 (in addition to simple banners on 21/5432). It does **not** write to `ai_honeypot_hits` yet — connections and queries appear only in container logs (future Security Hub integration planned).

| Port | Service banner / behavior (nmap -sV) | Notes |
|------|--------------------------------------|-------|
| 21 | `220 ProFTPD 1.3.9` | FTP banner |
| 3306 | `5.5.23-0ubuntu0.14.04.1` (old vulnerable) + full pharma infinite dataset + leaked bcrypt hashes | MySQL honeypot (VitaForge Pharmaceuticals). Accepts any creds. Never-ending `SELECT` results with real drug names, doctors, invoices, and expensive password hashes. See [honeypot-mysql-pharma.md](honeypot-mysql-pharma.md) |
| 5432 | `PostgreSQL 16.2` | Postgres banner |

**Port mapping for production lures**: Use `MYSQL_HONEYPOT_PORT=3306` in compose **after** moving your real SSH/MySQL/Postgres to high ports (see docs/honeypot-mysql-pharma.md for exact steps). Dev defaults to high random port 33306.

Run `docker compose up -d honeypot-sidecar`. Low ports may require `--privileged`, `cap_add: NET_BIND_SERVICE`, or iptables REDIRECT.

## Design Notes

- Every listed endpoint returns a non-empty, realistic body or form — no silent 404s or empty 200s.
- The data-room maze (`/api/secrets/explore`) remains untouched and infinite; the intranet is a small, finite complement under its own path prefix.
- New lures were chosen for high automated-scanner hit rate while staying cheap to maintain.
- All `*_probe` values are stable and used by the Security Hub aggregations and alerts.

Update this file whenever a new lure or source discriminator is added.