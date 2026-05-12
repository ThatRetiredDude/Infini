# Getting Started

Welcome! This guide walks you through installing and running Infini for the first time.

## Contents

- [Prerequisites](#prerequisites)
- [Quick Docker Setup](#quick-docker-setup)
- [First Login & Password Change](#first-login--password-change)
- [Verifying Everything Works](#verifying-everything-works)
- [Next Steps](#next-steps)

## Prerequisites

- Docker and Docker Compose installed (recommended for beginners)
- Basic terminal knowledge (copy-paste commands)
- A machine or VPS with ports 3000 (web) available (and optionally 2222/2223 for SSH/Telnet honeypot)

No database or Redis installation needed — everything runs inside the container.

## Quick Docker Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/ThatRetiredDude/Infini.git
   cd Infini
   ```

2. Copy the example environment file:

   ```bash
   cp .env.example .env
   ```

3. (Optional) Open `.env` and customize. For most users, the defaults are fine. Secrets like `JWT_SECRET` are automatically generated on first boot if missing.

4. Start the stack:

   ```bash
   docker compose up -d --build
   ```

5. The web interface is now available at **http://localhost:3000** (or the port you set via `HOST_PORT` in `.env`).

> **Production deployment**: For a real domain with TLS and maximum honeypot visibility, see the new [Production Deployment](production-deployment.md) guide. It covers Caddy/nginx reverse proxies and Cloudflare Tunnel options with the required `.env` changes (`PUBLIC_BASE_URL`, `ENFORCE_HTTPS`, `COOKIE_SECURE`).

## First Login & Password Change

- Username: `admin`
- Password: `ChangeMeImmediately!` (include the `!`)

Upon first successful login, you will be required to set a new password that is at least **12 characters** long. This is enforced before you can access the admin area.

After changing your password, the Security Hub and all admin features become available.

## Verifying Everything Works

- Visit the homepage — you should see the public site.
- Try accessing a lure like `http://localhost:3000/.env` — it should return fake content and the hit appears in the Security Hub.
- Check `/api/health` for a JSON status response.

## Next Steps

- Explore the **[Security Hub](/admin)** after logging in.
- Read [Configuration](configuration.md) for all options.
- Learn [How It Works](how-it-works.md) to understand the data flow.
- See the full list of lures in [Lures and Surfaces](lures-and-surfaces.md).
- Understand your responsibilities as the host operator in [Host Operator Responsibilities](host-operator-responsibilities.md).

You're now running a fully functional honeypot!