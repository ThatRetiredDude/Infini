# Optional Features

Infini includes several powerful optional capabilities.

## Contents

- [Cowrie SSH/Telnet Honeypot](#cowrie-sshtelnet-honeypot)
- [Blog & Carousel](#blog--carousel)
- [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
- [AI Log Review](#ai-log-review)
- [Alerts & Integrations](#alerts--integrations)

## Cowrie SSH/Telnet Honeypot

**Enabled by default** (`INFINI_NETWORK_HONEYPOT_ENABLED=1`).

- Interactive SSH honeypot on port 2222 and Telnet on 2223 (powered by Cowrie, GPL-2.0).
- Events ingested into `network_sensor_events` table.
- Visible in Security Hub → Network Sensors tab.
- Artifact retention (default 14 days) for downloaded files.
- Set `INFINI_NETWORK_HONEYPOT_ENABLED=0` to disable.
- See [honeypot-cowrie.md](honeypot-cowrie.md) for licensing and configuration details.

**Note:** Cowrie is GPL. If you redistribute the image, understand the combined-work implications.

## Blog & Carousel

- Optional public blog with rich-text editor (Tiptap).
- Carousel for featured posts or images.
- Page visibility controls (public / hidden).
- Publish webhooks for notifications.
- Great for "content marketing" that can also serve as additional lure surface.

## Multi-Factor Authentication (MFA)

- TOTP-based 2FA for admin accounts.
- Setup via Security Hub → MFA tab.
- Issuer label configurable (`MFA_ISSUER`).

## AI Log Review

- Select any rows or alerts in Security Hub.
- Sends structured analysis request to xAI Grok (default `grok-4.3-latest`).
- Encrypted API keys stored via Integrations UI or `XAI_API_KEY`.
- Fallback model supported.

## Alerts & Integrations

- Rule-based alerts (email, Discord, Telegram, generic webhooks).
- Encrypted credentials for third-party services.
- Cron scheduler (can be disabled for testing).

All optional features are configured via environment variables or the admin UI.