# Infini Documentation

Welcome to the full documentation for Infini — a self-hosted honeypot and security monitoring stack.

This is the complete reference. The [root README](../README.md) provides a quick beginner introduction.

## Contents

- [Getting Started](getting-started.md) — Install, first run, login
- [Configuration](configuration.md) — All environment variables explained
- [How It Works](how-it-works.md) — Architecture, data flows, monitoring layers
- [Lures and Surfaces](lures-and-surfaces.md) — Every decoy endpoint with simple + technical details
- [Optional Features](optional-features.md) — Cowrie, Blog, MFA, AI Review, Alerts
- [Operations](operations.md) — Health checks, smoke tests, backups, updates
- [Security & Deployment](security-deployment.md) — CORS, HTTPS, hardening, disclaimers
- [Host Operator Responsibilities](host-operator-responsibilities.md) — What the container does vs. what you must do on the host (firewall, isolation, hardening)
- [Advanced / Legacy](architecture.md) — Original technical architecture notes
- [Cowrie Honeypot Details](honeypot-cowrie.md) — Licensing, ports, retention for the optional TCP honeypot

## Quick Navigation by Goal

**I just want to run it:** → [Getting Started](getting-started.md)

**I need to configure something:** → [Configuration](configuration.md)

**I want to understand what all the lures do:** → [Lures and Surfaces](lures-and-surfaces.md)

**Something is wrong or I want to monitor:** → [Operations](operations.md)

**I want to enable SSH honeypot or blog:** → [Optional Features](optional-features.md)

**I want to understand my responsibilities as the host operator:** → [Host Operator Responsibilities](host-operator-responsibilities.md)

All documents include hyperlinked tables of contents for easy navigation.

---

*Documentation is kept up to date with the codebase. Contributions welcome via pull requests.*