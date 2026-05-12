# Lures and Surfaces

Complete inventory of every decoy endpoint, with both simple descriptions and detailed technical information.

## Contents

- [Simple Overview](#simple-overview)
- [Monitored Endpoints](#monitored-endpoints)
- [Internal Secrets Routes](#internal-secrets-routes)
- [Corporate Intranet](#corporate-intranet)
- [Data Room Maze](#data-room-maze)
- [Network Banners](#network-banners)
- [Design Notes](#design-notes)

## Simple Overview

Every lure is designed to look completely real. Attackers get plausible content and their activity is recorded.

## Monitored Endpoints

| Path(s)                        | What It Pretends To Be                          | Simple Description |
|--------------------------------|-------------------------------------------------|---------------------|
| `/.env*`, `/api/.env`          | Environment configuration file                  | Fake .env with "secrets" |
| `/.git/config`, `/.git/HEAD`   | Git repository metadata                         | Looks like private source code repo |
| `/.aws/credentials`            | AWS cloud credentials                           | Fake Amazon keys |
| `/.docker/config.json`         | Docker registry auth                            | Docker login info |
| `/wp-admin*`, `/wp-login.php`  | WordPress admin                                 | Classic WordPress login |
| `/phpmyadmin*`                 | Database admin tool                             | phpMyAdmin login |
| `/adminer*`                    | Database admin tool                             | Adminer login |
| `/openapi.json`, `/swagger*`   | API documentation                               | OpenAPI spec |
| `/api/keys*`                   | API key management                              | 401 error hinting at keys |
| `/api/internal/debug*`         | Server debug info                               | Uptime/memory JSON |
| `/backup*`, `/dump.sql`        | Database backups                                | List of backup files |
| `/.well-known/security.txt`    | Security contact file                           | Valid security.txt + trap |
| `/robots.txt`                  | Crawler instructions                            | Points to "private" paths |
| `/jenkins*`                    | CI/CD server                                    | Jenkins login form |
| `/grafana/`, `/login`          | Monitoring dashboard                            | Grafana login |
| `/gitlab/`, `/users/sign_in*`  | Code hosting                                    | GitLab sign-in |
| `/actuator*`                   | Spring Boot internals                           | Health, beans, env data |
| `/owa*`                        | Email web access                                | Outlook Web App login |
| `/solr*`                       | Search engine admin                             | Solr JSON response |
| `/console*`, `/signin`         | Cloud console                                   | AWS sign-in form |
| `/ecp*`                        | Exchange admin                                  | ECP login form |

## Internal Secrets Routes

| Path                              | Simple Description |
|-----------------------------------|--------------------|
| `/api/secrets/system-prompt`      | Fake AI system prompt |
| `/api/secrets/internal/dossier-dump` | "Company internal records" dump |
| `/api/secrets/eval` (POST)        | Evaluation job submission |
| `/api/secrets/eval/results`       | Job results lookup |

## Corporate Intranet

A small, finite fake internal company site at `/intranet/*`:

- Login page (accepts POST, shows invalid creds)
- Dashboard with HR / Finance / IT links
- Employee lists, benefits forms, ledgers, support tickets

All activity is logged with session tracking.

## Data Room Maze

`/api/secrets/explore/*` — Procedurally generated infinite document tree (1M+ pages). 

- Gated by Cloudflare Turnstile for repeat IPs
- Self-identification via APC-ACCESS-ID token
- Never ends — designed to keep scanners occupied

Stored separately in `maze_hits`.

## Network Banners

Optional sidecar container exposes:
- Simple banners on 21 (FTP) and 5432 (Postgres)
- Full MySQL protocol honeypot on 3306 advertising old vulnerable 5.5.23 + infinite deterministic pharmaceutical manufacturing dataset (real drug names, doctor/researcher names, multi-million invoices, lab results) + table of 500k+ high-cost fake bcrypt password hashes designed to waste cracking time.

See [honeypot-mysql-pharma.md](honeypot-mysql-pharma.md) for port mapping instructions, operator steps to move real services off standard ports, and query examples. Connections logged to container stdout (future `mysql_pharma_probe` integration).

## Design Notes

- Every endpoint returns non-empty realistic content (no silent 404s).
- All `*_probe` source values are stable for Security Hub aggregations and alerts.
- The intranet is a lightweight complement to the infinite maze.

Update this document when adding new lures.