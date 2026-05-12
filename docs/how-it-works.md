# How It Works

This document explains the architecture and data flow of Infini at a high level.

## Contents

- [High-Level Architecture](#high-level-architecture)
- [Security Monitoring Layers](#security-monitoring-layers)
- [Data Flow Example](#data-flow-example)
- [Key Components](#key-components)
- [AI Log Review](#ai-log-review)

## High-Level Architecture

Infini runs as a **single Docker container** containing:

- Node.js 20 + Express backend
- Static Single Page Application (SPA) frontend
- SQLite database (via better-sqlite3 with WAL mode)
- Optional Cowrie SSH/Telnet honeypot (when enabled)

No external services required.

## Security Monitoring Layers

| Layer                  | Description                                      | Storage Table             |
|------------------------|--------------------------------------------------|---------------------------|
| Network Sensor (Cowrie)| Optional real SSH/Telnet interactions            | network_sensor_events     |
| Monitored Endpoints    | All the fake files, logins, and internal paths   | ai_honeypot_hits          |
| Data Room Activity     | Infinite maze of documents under /explore        | maze_hits                 |
| Input Guard            | Detects prompt injection / SQL / XSS attempts    | ai_input_flags            |
| Access Log             | Public page visits + hidden beacon               | access_log                |
| Alerts Engine          | Rules-based notifications                        | security_alert_rules + deliveries |

## Data Flow Example

1. Attacker requests `/.git/config`
2. Express route matches → returns realistic Git config
3. Hit is logged to `ai_honeypot_hits` with `source: "git_config_probe"`
4. Background enrichment (ipinfo, AbuseIPDB, GreyNoise) adds geo/ASN/reputation
5. If rules match, an alert is delivered (email/Discord/etc.)
6. Everything appears in the Security Hub UI with export options

## Key Components

- **server/index.js** — Main Express app, route registration for all lures and APIs.
- **server/security-hub.js** — Aggregation queries and enrichment logic.
- **server/security-alerts.js** — Cron-based alert evaluation and delivery.
- **server/monitored-endpoints.js** — Definition of all decoy routes.
- **src/** — React SPA (Vite built to dist/).

## AI Log Review

Select rows or alerts in the Security Hub → sends structured prompt to xAI Grok for analysis. Keys are stored encrypted.

For more technical detail, see the original architecture notes or source code.