# Security & Deployment

Hardening, proxy considerations, and important disclaimers.

## Contents

- [CORS Configuration](#cors-configuration)
- [Trust Proxy & IP Handling](#trust-proxy--ip-handling)
- [Cookies and HTTPS](#cookies-and-https)
- [Default Credentials & Hardening](#default-credentials--hardening)
- [Disclaimer](#disclaimer)

## CORS Configuration

The API reflects every `Origin` and allows credentials. This works well when the SPA and API share the same origin (standard Docker deployment).

Tightening CORS requires a code change.

## Trust Proxy & IP Handling

`app.set('trust proxy', 1)` is enabled. 

If you place more than one reverse proxy in front, adjust this value so `X-Forwarded-For` headers are trusted correctly. Misconfiguration can allow IP spoofing in audits and alerts.

## Cookies and HTTPS

- `COOKIE_SECURE=false` by default (allows HTTP login on localhost).
- Set to `true` only when serving exclusively over HTTPS.
- `COOKIE_SAMESITE=lax` is the default.

## Default Credentials & Hardening

The bootstrap `admin` / `ChangeMeImmediately!` account is intentional for local/lab use.

**For any internet-facing deployment:**
- Set a strong `SEED_ADMIN_PASSWORD` in `.env`
- Enable MFA
- Place behind a reverse proxy with rate limiting and WAF
- Consider `ENFORCE_HTTPS=true`
- Review the full list of host responsibilities in [Host Operator Responsibilities](host-operator-responsibilities.md)

## Disclaimer

Infini is research/educational software. It is **not** a substitute for proper edge security controls. You are responsible for lawful use and compliance in your jurisdiction.

See the full disclaimer in the root [README](../README.md).