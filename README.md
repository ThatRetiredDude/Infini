# Infini

Self-hosted honeypot / monitoring stack (SPA + Express + SQLite). **Work in progress** — behavior and APIs can change; treat production deployments as experimental until you’ve reviewed config.

## Purpose

Decoy and instrumented routes, data-room-style exploration, access logging, enrichment, **Security Hub**, and alerts. Shipped as **one Docker container** with SQLite on disk—no Postgres, no Redis, no separate auth service.

Internally the codename **Maxwell International (MI)** still shows up in tokens (`mi_session`, etc.); the public name is **Infini**.

## Features (short)

- **Security & monitoring** — Honeypot-style endpoints, data room, logging, alerts, optional AI log review (details in [docs/architecture.md](docs/architecture.md)).
- **Blog** — Optional; casual content—or pad the site with nonsense if you want a busier-looking surface.
- **Public cover** — Donations-style page is shell only, not the point of the project.

More surfaces over time. **Full detail:** [Documentation](docs/README.md).

## How to run (Docker)

For a honeypot on your own machine / lab network:

```bash
git clone https://github.com/ThatRetiredDude/Infini.git
cd Infini
cp .env.example .env
```

Edit `.env` — at minimum set **`JWT_SECRET`** and **`INTEGRATION_ENCRYPTION_KEY`** (see [docs/configuration.md](docs/configuration.md)).

```bash
docker compose up -d --build
```

Open **http://localhost:3000** unless you set **`HOST_PORT`** in `.env` for a port conflict.

## How to log in

| | |
| --- | --- |
| **Bootstrap** | **`admin`** / **`ChangeMeImmediately!`** (include the **`!`**) unless you set **`SEED_ADMIN_PASSWORD`** in `.env`. |
| **Right after login** | The app forces **Set your password** in the UI. New password must be **at least 12 characters**. Until you finish that step, **`/admin`** and **`/api/admin/*`** return **403** with `password_change_required`. |

## Documentation

- [Configuration (`env`)](docs/configuration.md)
- [Architecture & monitoring](docs/architecture.md)
- [Operations (health, smoke)](docs/operations.md)
- [Security & deployment (CORS, cookies, proxies)](docs/security-and-deployment.md)

## Disclaimer

Infini is **research / educational** software—not a complete security or compliance program, and not a substitute for WAFs, edge rate limits, or lawful use policies. **Provided as-is, without warranty of any kind.** You are solely responsible for your deployment and for complying with applicable laws. Authors and contributors are **not liable** for damages or losses arising from use of this software.

## License

[Apache License 2.0](LICENSE).
