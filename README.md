# Infini

[LIVE DEMO AT INFINI.WIN](https://infini.win)

**Self-hosted honeypot and security monitoring made simple.** One Docker container. No complex setup.

## What is Infini?

Infini turns your server into a smart trap for hackers, bots, and scanners. It creates realistic-looking fake files, login pages, admin tools, and even an endless "data room" full of documents. 

When someone tries to break in or steal information, Infini quietly records:
- Who they are (IP address, location, organization)
- What they tried to access
- When it happened

You get a clean dashboard (the Security Hub) to review everything, with maps, charts, alerts, and even optional AI help to analyze the activity.

It's designed for learning, research, or adding an extra layer of visibility to your own servers — all self-hosted and private.

## Why Run Infini?

- **Catches real attacks** — Automated scanners hit these lures constantly.
- **See the full picture** — IP enrichment, repeat offender tracking, firewall export tools.
- **Alerts when it matters** — Email, Discord, Telegram, or webhooks.
- **Optional extras** — Real SSH/Telnet honeypot (Cowrie), blog, multi-factor auth.
- **Zero hassle** — Single Docker container with SQLite. No Postgres, Redis, or separate services.

## Quick Start (5 Minutes)

```bash
git clone https://github.com/ThatRetiredDude/Infini.git
cd Infini
cp .env.example .env
docker compose up -d --build
```

Open **http://localhost:3000**

**First login:**
- Username: `admin`
- Password: `ChangeMeImmediately!` (include the exclamation mark)

The system will immediately force you to set a new password (12+ characters). After that, the admin area unlocks.

New env controls for login hardening (see .env.example): MAX_LOGIN_FAILURES, ENFORCE_SESSION_IP_BINDING.

That's it. Your honeypot is live and logging.

## Every Lure Explained Simply

Infini includes dozens of realistic traps. Here they are in plain English:

**Fake Secret Files (scanners love these)**
- `/.env` — Pretends to be your app's hidden configuration file with passwords.
- `/.git/config` — Looks like a real Git code repository with private links.
- `/.aws/credentials` — Fake Amazon Web Services keys.
- `/.docker/config.json` — Docker login credentials.
- `/backup*` and `/dump.sql` — Lists of fake database backup files.

**Admin & Database Logins**
- `/wp-admin`, `/wp-login.php` — WordPress admin login page.
- `/phpmyadmin*` — Popular database management tool.
- `/adminer*` — Another database admin login.
- `/jenkins*` — Jenkins build server login.
- `/grafana/`, `/login` — Grafana monitoring dashboard.
- `/gitlab/`, `/users/sign_in*` — GitLab code hosting login.
- `/actuator*` — Spring Boot internal debug pages (health, beans, env).
- `/owa*` — Outlook Web App email login.
- `/solr*` — Solr search engine admin console.
- `/console*`, `/signin` — AWS web console login.
- `/ecp*` — Microsoft Exchange admin center.

**API & Internal Endpoints**
- `/api/keys*` — API key management that returns "unauthorized".
- `/api/internal/debug*` — Fake server debug information.
- `/api/secrets/system-prompt` — Looks like an AI model's hidden instructions.
- `/api/secrets/internal/dossier-dump` — "Internal company records" dump.
- `/api/secrets/eval` (and results) — Job evaluation endpoints.

**Info & Security Files**
- `/.well-known/security.txt` — Security contact file (contains a hidden trap).
- `/robots.txt` — Tells bots about "private" paths they shouldn't visit.

**Fake Corporate Intranet**
- `/intranet/login` — Company employee login page.
- `/intranet/dashboard` — Dashboard with links to HR, Finance, and IT.
- `/intranet/hr/*`, `/intranet/finance/*`, `/intranet/it/*` — Realistic internal pages that accept forms and log everything.

**The Infinite Data Room Maze**
- `/api/secrets/explore/*` — Over a million procedurally generated pages. Looks like a real private data room. Repeat visitors get a CAPTCHA. Designed to waste attackers' time indefinitely.

**Bonus Network Services (optional)**
- Ports 21 (FTP), 3306 (MySQL), 5432 (PostgreSQL) — Fake service banners that log connection attempts.

Every single one of these returns realistic content and records the visit with full details.

## Next Steps & Full Documentation

For complete guides including:
- Detailed configuration options
- How the Security Hub, alerts, and AI review work
- Enabling the SSH honeypot (Cowrie)
- Blog and page visibility features
- Security hardening and deployment behind proxies

Visit the **[Documentation](docs/README.md)** — it has hyperlinked tables of contents and step-by-step instructions for every feature.

## Important Notes

Infini is **research and educational** software. It is not a complete security solution. Always follow the law in your jurisdiction and combine it with proper firewalls, rate limiting, and other protections.

Provided as-is under the Apache 2.0 license. See [LICENSE](LICENSE) for details.

---

**Ready to explore?** Start the container, log in, and check out the Security Hub to see your first lure hits!
