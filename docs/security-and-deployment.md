# Security & deployment

## CORS

In [`server/index.js`](../server/index.js), CORS is configured to **reflect every `Origin`** and allow **`credentials: true`**:

```js
cors({
  origin: (origin, cb) => cb(null, true),
  credentials: true,
})
```

Any browser origin can talk to your API **if** it can reach the host and attach cookies on your domain—typical when the SPA is served from the same origin as the API (production Docker) or explicitly trusted in dev setups. **Tightening CORS** to a single explicit origin requires a code change plus env (not currently exposed).

## Trust proxy

`app.set('trust proxy', 1)` is enabled so **`X-Forwarded-For`** (and related headers) behind one reverse-proxy hop affect IP-derived behavior (audit, enrichment, alerts). Align this with **how many** proxies sit in front of the app (nginx, CDN, Kubernetes ingress); wrong trust settings can spoof client IPs.

## Cookies and HTTPS

- **`COOKIE_SECURE`** (`false` in `.env.example`) — Session cookies omit the `Secure` flag so logins work on **HTTP** (e.g. `http://localhost:3000`).  
- Set **`COOKIE_SECURE=true`** only when the site is **HTTPS-only**, or browsers may refuse to send the session cookie.

## Default credentials

The documented bootstrap **`admin` / `ChangeMeImmediately!`** is intentional for **local / lab** installs. Anything internet-facing needs a strong **`SEED_ADMIN_PASSWORD`** and normal hardening.

## Disclaimer (full reminder)

Same spirit as the [README](../README.md): Infini is **research / educational** software. Monitoring is **not** a substitute for edge WAF, rate limits, robots policy for legitimate bots, or legal review where you operate.

**Provided as-is, without warranty.** You are solely responsible for lawful deployment and compliance. See the **[LICENSE](../LICENSE)** (Apache License 2.0).
