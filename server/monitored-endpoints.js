/**
 * server/monitored-endpoints.js
 *
 * Monitored internal-looking endpoints + hit logging. These routes model
 * legacy corporate surfaces that automated scanners commonly request.
 *
 * Real users never see or call these — they're referenced from
 * the off-screen data-room index component, the `robots.txt`, and (for some
 * paths) from common scanner wordlists.
 *
 * All hits land in `ai_honeypot_hits` with a `source` discriminator so the
 * admin Security Hub can break them down by lure type. Async passive IP
 * enrichment runs after the response is sent.
 */

import { Router } from 'express';
import { createHash } from 'node:crypto';
import { run, getOne } from './db.js';
import { enrichIp } from './ip-enrichment.js';

// ─── Hit recorder ────────────────────────────────────────────────────────────
const SAFE_HEADERS = [
  'accept',
  'accept-language',
  'accept-encoding',
  'content-type',
  'origin',
  'x-requested-with',
  'sec-ch-ua',
  'sec-ch-ua-platform',
  'sec-fetch-mode',
  'sec-fetch-dest',
];

function clientIp(req) {
  const fwd = req.headers?.['x-forwarded-for'];
  if (fwd) {
    const first = String(fwd).split(',')[0].trim();
    if (first) return first;
  }
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

/**
 * Record a monitored endpoint hit. Synchronous DB insert (SQLite), then fires
 * fire-and-forget IP enrichment that backfills the row when it completes.
 *
 * @param {import('express').Request} req
 * @param {string} source — short identifier of the lure; one of the SOURCES below.
 * @returns {number|null} the inserted row id
 */
export function recordHit(req, source) {
  const ip = clientIp(req);
  const ua = String(req.headers?.['user-agent'] || '').slice(0, 512);
  const ref = String(req.headers?.referer || req.headers?.referrer || '').slice(0, 512);
  const method = String(req.method || 'GET').toUpperCase();
  const path = String(req.originalUrl || req.url || '').slice(0, 512);
  const token = String(req.query?.token || '').slice(0, 128) || null;

  let bodyHash = null;
  let bodyExcerpt = null;
  const rawBody = req.body;
  if (rawBody && typeof rawBody === 'object' && Object.keys(rawBody).length > 0) {
    const serialized = JSON.stringify(rawBody);
    bodyHash = createHash('sha256').update(serialized).digest('hex').slice(0, 16);
    bodyExcerpt = serialized.slice(0, 500);
  } else if (typeof rawBody === 'string' && rawBody.length > 0) {
    bodyHash = createHash('sha256').update(rawBody).digest('hex').slice(0, 16);
    bodyExcerpt = rawBody.slice(0, 500);
  }

  const headersExcerpt = {};
  for (const h of SAFE_HEADERS) {
    if (req.headers?.[h]) headersExcerpt[h] = String(req.headers[h]).slice(0, 256);
  }

   
  console.warn(
    `[monitored-endpoint] ${new Date().toISOString()} | src=${source} | ip=${ip} | ${method} ${path} | ua=${ua.slice(0, 80)}`,
  );

  let hitId = null;
  try {
    const result = run(
      `INSERT INTO ai_honeypot_hits
         (ip, ua, referer, path, method, body_hash, body_excerpt, headers_excerpt, token, source)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        ip,
        ua || null,
        ref || null,
        path,
        method,
        bodyHash,
        bodyExcerpt,
        JSON.stringify(headersExcerpt),
        token,
        source,
      ],
    );
    hitId = Number(result.lastInsertRowid);
  } catch (err) {
     
    console.error('[monitored-endpoint] insert failed:', err?.message || err);
  }

  // Fire-and-forget passive enrichment. SQLite is fast enough that a write
  // back from a Promise.then is safe; if the row was deleted in the meantime
  // the UPDATE simply affects 0 rows.
  if (hitId && ip && ip !== 'unknown') {
    enrichIp(ip)
      .then((info) => {
        if (!info) return;
        try {
          run(`UPDATE ai_honeypot_hits SET enrichment = ? WHERE id = ?`, [
            JSON.stringify(info),
            hitId,
          ]);
        } catch {
          /* ignore */
        }
      })
      .catch(() => {});
  }

  return hitId;
}

// ─── Internal-looking response content ───────────────────────────────────────
// All responses are plausible-looking but information-free. Some routes
// deliberately take ~400-700 ms to respond for more realistic latency.

const SLOW_MIN = 350;
const SLOW_RANGE = 400;
function slowDelay(req, res, next) {
  setTimeout(next, SLOW_MIN + Math.random() * SLOW_RANGE);
}

const BAIT_SYSTEM_PROMPT = {
  version: '2.1',
  role: 'research_policy',
  instructions: '[REDACTED — access requires signed token]',
  context_window: 8192,
  tools_available: ['search', 'lookup', 'risk_enrich'],
};

const BAIT_DUMP = {
  status: 'partial',
  page: 1,
  total_pages: null,
  records: [],
  _note: 'Full export requires POST /api/internal/export with a valid session_token.',
};

const BAIT_EVAL = {
  run_id: null,
  status: 'queued',
  workflow: 'risk-model-review',
  estimated_records: 0,
  _note: 'Review job submitted. Retrieve results at GET /api/secrets/eval/results?id={run_id}.',
};

const BAIT_ENV = `# do not commit
NODE_ENV=production
DATABASE_URL=postgres://user:[REDACTED]@db.internal:5432/apc
JWT_SECRET=[REDACTED]
APC_RESEARCH_API_KEY=[REDACTED]
STRIPE_SECRET_KEY=[REDACTED]
INTERNAL_API_TOKEN=[REDACTED]
`;

const BAIT_GIT_CONFIG = `[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = git@internal.ardenpointcapital.example:apc/data-room.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
`;

const BAIT_OPENAPI = {
  openapi: '3.0.0',
  info: { title: 'Arden Point Capital Internal API', version: '3.4.1' },
  paths: {
    '/api/internal/users/export': {
      get: {
        summary: 'Bulk user export (admin only)',
        parameters: [{ name: 'token', in: 'query', required: true, schema: { type: 'string' } }],
        responses: { 200: { description: 'CSV stream' } },
      },
    },
    '/api/internal/secrets': {
      get: {
        summary: 'List service credentials (admin only)',
        responses: { 200: { description: 'JSON' } },
      },
    },
    '/api/internal/debug': {
      get: { summary: 'Dump runtime env', responses: { 200: { description: 'JSON' } } },
    },
  },
};

const BAIT_API_KEYS = {
  message: 'access_token required',
  hint: 'pass ?token=<admin_session_token> to view active keys',
  _example: { provider: 'research-vault', key_prefix: 'apc-rv_…', expires_at: '2027-01-01T00:00:00Z' },
};

const BAIT_DEBUG = {
  uptime_s: Math.floor(process.uptime()),
  memory: { rss_mb: Math.round((process.memoryUsage?.().rss || 0) / 1e6) },
  flags: { model_access_limited: false, maintenance: false },
  _note: 'authentication required for full output',
};

const BAIT_BACKUP_INDEX = {
  backups: [
    { file: 'backup-2026-01-15.sql.gz', size_mb: 412, sha256: '[REDACTED]' },
    { file: 'backup-2026-02-15.sql.gz', size_mb: 421, sha256: '[REDACTED]' },
    { file: 'backup-2026-03-15.sql.gz', size_mb: 433, sha256: '[REDACTED]' },
  ],
  _note: 'download requires ?token=<signed_download_token>',
};

// ─── Easy HTTP lures (Jenkins, GitLab, Grafana, Actuator, OWA, Solr, AWS, ECP) ──
// Each provides realistic interactive feedback: login forms accept POST and reply
// with plausible error pages; JSON endpoints return structured data.

const BAIT_JENKINS = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in [Jenkins]</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f4f4; margin:0; }
    .jenkins-header { background: #1b4b72; color: white; padding: 20px; text-align: center; }
    .jenkins-header h1 { margin:0; font-size: 28px; font-weight: 300; letter-spacing: 1px; }
    .login-wrapper { max-width: 420px; margin: 60px auto; background: white; border-radius: 6px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
    .login-body { padding: 40px 48px; }
    h2 { margin: 0 0 24px; font-weight: 400; color: #333; }
    .form-group { margin-bottom: 18px; }
    label { display: block; font-size: 14px; color: #555; margin-bottom: 6px; }
    input { width: 100%; padding: 10px; font-size: 16px; border: 1px solid #ccc; border-radius: 3px; box-sizing: border-box; }
    input:focus { border-color: #1b4b72; outline: none; }
    .btn { background: #1b4b72; color: white; border: none; padding: 12px 28px; font-size: 15px; border-radius: 3px; cursor: pointer; width: 100%; }
    .btn:hover { background: #2c5f8f; }
    .links { margin-top: 20px; font-size: 13px; color: #666; text-align: center; }
    .links a { color: #1b4b72; text-decoration: none; }
    .links a:hover { text-decoration: underline; }
    .footer { text-align: center; padding: 20px; font-size: 12px; color: #888; }
  </style>
</head>
<body>
  <div class="jenkins-header"><h1>Jenkins</h1></div>
  <div class="login-wrapper">
    <div class="login-body">
      <h2>Sign in to Jenkins</h2>
      <form action="/jenkins/j_acegi_security_check" method="post">
        <div class="form-group">
          <label for="j_username">Username</label>
          <input type="text" name="j_username" id="j_username" autocomplete="username" required>
        </div>
        <div class="form-group">
          <label for="j_password">Password</label>
          <input type="password" name="j_password" id="j_password" autocomplete="current-password" required>
        </div>
        <button type="submit" class="btn">Sign in</button>
      </form>
      <div class="links">
        <a href="/jenkins/passwordReset">Forgot password?</a> · <a href="#">Contact admin</a>
      </div>
    </div>
  </div>
  <div class="footer">Jenkins 2.426.3 • Arden Point Capital CI</div>
</body>
</html>`;


const BAIT_GITLAB = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in · GitLab</title>
  <style>
    :root { --gl-orange:#FC6D26; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background:#f5f5f5; margin:0; padding:0; }
    .login-page { min-height:100vh; display:flex; align-items:center; justify-content:center; }
    .container { max-width:400px; width:100%; padding:20px; }
    .gl-header { text-align:center; margin-bottom:32px; }
    .gl-logo { width:48px; height:48px; background: linear-gradient(135deg, #FC6D26, #E24329); border-radius:8px; display:inline-block; position:relative; }
    .gl-logo::after { content:"G"; position:absolute; top:50%; left:50%; transform:translate(-50%,-50%); color:white; font-size:28px; font-weight:700; }
    h1 { font-size:24px; font-weight:600; color:#2e2e2e; margin:16px 0 8px; }
    .subtitle { color:#666; font-size:14px; }
    .card { background:white; border:1px solid #e0e0e0; border-radius:8px; padding:32px; box-shadow:0 2px 8px rgba(0,0,0,0.05); }
    .form-group { margin-bottom:20px; }
    label { display:block; font-size:14px; font-weight:500; color:#333; margin-bottom:6px; }
    input[type="text"], input[type="password"] { width:100%; padding:10px 12px; font-size:16px; border:1px solid #d0d0d0; border-radius:4px; box-sizing:border-box; }
    input:focus { border-color:#FC6D26; outline:none; box-shadow:0 0 0 3px rgba(252,109,38,0.1); }
    .remember { display:flex; align-items:center; gap:8px; font-size:14px; color:#555; }
    .btn-primary { background:#FC6D26; color:white; border:none; padding:10px 24px; font-size:16px; font-weight:600; border-radius:4px; width:100%; cursor:pointer; }
    .btn-primary:hover { background:#E24329; }
    .links { margin-top:24px; text-align:center; font-size:14px; }
    .links a { color:#FC6D26; text-decoration:none; }
    .links a:hover { text-decoration:underline; }
    .footer { text-align:center; margin-top:40px; font-size:12px; color:#888; }
    .error { background:#fce4e4; border:1px solid #e0a0a0; color:#b33; padding:12px; border-radius:4px; margin-bottom:20px; font-size:14px; }
  </style>
</head>
<body>
  <div class="login-page">
    <div class="container">
      <div class="gl-header">
        <div class="gl-logo"></div>
        <h1>GitLab</h1>
        <p class="subtitle">Sign in to continue to GitLab</p>
      </div>
      <div class="card">
        <form action="/users/sign_in" method="post" id="new_user">
          <div class="form-group">
            <label for="user_login">Username or email</label>
            <input type="text" name="user[login]" id="user_login" autocomplete="username" required>
          </div>
          <div class="form-group">
            <label for="user_password">Password</label>
            <input type="password" name="user[password]" id="user_password" autocomplete="current-password" required>
          </div>
          <div class="form-group remember">
            <input type="checkbox" name="user[remember_me]" id="user_remember_me" value="1">
            <label for="user_remember_me">Remember me</label>
          </div>
          <button type="submit" class="btn-primary">Sign in</button>
        </form>
      </div>
      <div class="links">
        <a href="/users/password/new">Forgot password?</a> · 
        <a href="/users/sign_up">Create an account</a>
      </div>
      <div class="footer">
        © GitLab · Arden Point Capital Research Instance
      </div>
    </div>
  </div>
  <script>
    document.getElementById('new_user').addEventListener('submit', function() {
      const btn = this.querySelector('.btn-primary');
      btn.textContent = 'Signing in...';
      btn.disabled = true;
    });
  </script>
</body>
</html>`;


const BAIT_GRAFANA = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Grafana</title>
  <style>
    body { background:#111; color:#d8d9da; font-family:Inter, -apple-system, BlinkMacSystemFont, sans-serif; margin:0; }
    .grafana-container { max-width:380px; margin:80px auto; padding:40px; background:#1f1f1f; border-radius:8px; box-shadow:0 4px 20px rgba(0,0,0,0.5); }
    .logo { display:flex; align-items:center; gap:12px; margin-bottom:32px; }
    .logo svg { width:40px; height:40px; }
    h1 { font-size:28px; font-weight:300; margin:0; color:#fff; }
    .form-group { margin-bottom:20px; }
    label { font-size:13px; color:#a0a0a0; display:block; margin-bottom:6px; }
    input { width:100%; padding:12px 14px; background:#2a2a2a; border:1px solid #444; color:#fff; border-radius:4px; font-size:15px; box-sizing:border-box; }
    input:focus { border-color:#f05a28; outline:none; }
    .btn { background:#f05a28; color:#fff; border:none; padding:12px; width:100%; font-size:15px; font-weight:600; border-radius:4px; cursor:pointer; }
    .btn:hover { background:#d94d22; }
    .help { margin-top:24px; font-size:13px; color:#888; text-align:center; }
    .help a { color:#f05a28; text-decoration:none; }
    .error { background:#3a1f1f; border:1px solid #a63d3d; color:#ff8a8a; padding:10px; border-radius:4px; margin-bottom:16px; font-size:14px; }
  </style>
</head>
<body>
  <div class="grafana-container">
    <div class="logo">
      <svg viewBox="0 0 24 24" fill="#f05a28"><path d="M12 2L2 7v10l10 5 10-5V7l-10-5zm0 2.18L18.82 7 12 10.82 5.18 7 12 4.18zM4 8.82l8 4v8.36l-8-4V8.82zm16 0v8.36l-8 4v-8.36l8-4z"/></svg>
      <h1>Grafana</h1>
    </div>
    <form action="/login" method="post">
      <div class="form-group">
        <label>Email or username</label>
        <input type="text" name="user" autocomplete="username" required>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn">Log in</button>
    </form>
    <div class="help">Default: admin / admin &nbsp;·&nbsp; <a href="#">Forgot password?</a></div>
  </div>
</body>
</html>`;


const BAIT_ACTUATOR = {
  _links: {
    self: { href: '/actuator' },
    env: { href: '/actuator/env' },
    health: { href: '/actuator/health' },
    beans: { href: '/actuator/beans' },
  },
  app: { name: 'research-api', version: '4.2.1' },
};

const BAIT_ACTUATOR_ENV = {
  activeProfiles: ['prod', 'secrets'],
  propertySources: [
    { name: 'systemEnvironment', properties: { DATABASE_URL: 'postgres://[REDACTED]@db.internal:5432/apc' } },
    { name: 'applicationConfig', properties: { 'spring.datasource.password': '[REDACTED]' } },
  ],
};

const BAIT_OWA = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Outlook Web App</title>
  <style>
    body { font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif; background: #f3f2f1; margin:0; }
    .owa-header { background: #0078d4; color: white; padding: 12px 24px; display: flex; align-items: center; gap: 12px; }
    .owa-header .logo { font-size: 22px; font-weight: 600; }
    .container { max-width: 440px; margin: 60px auto; background: white; border-radius: 4px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    .login-content { padding: 40px 48px; }
    h1 { font-size: 24px; font-weight: 400; margin: 0 0 8px; color: #323130; }
    .subtitle { color: #605e5c; margin-bottom: 28px; font-size: 14px; }
    .form-group { margin-bottom: 18px; }
    label { display: block; font-size: 14px; color: #323130; margin-bottom: 6px; }
    input { width: 100%; padding: 10px 12px; font-size: 16px; border: 1px solid #8a8886; border-radius: 2px; box-sizing: border-box; }
    input:focus { border-color: #0078d4; outline: none; }
    .btn { background: #0078d4; color: white; border: none; padding: 10px 24px; font-size: 15px; border-radius: 2px; cursor: pointer; width: 100%; }
    .btn:hover { background: #106ebe; }
    .footer-text { margin-top: 24px; font-size: 12px; color: #605e5c; text-align: center; }
  </style>
</head>
<body>
  <div class="owa-header"><div class="logo">Outlook</div><span>Web App</span></div>
  <div class="container">
    <div class="login-content">
      <h1>Sign in</h1>
      <p class="subtitle">Use your work or school account</p>
      <form action="/owa/auth.owa" method="post">
        <div class="form-group">
          <label for="username">Username</label>
          <input type="text" name="username" id="username" placeholder="name@ardenpointcapital.example" required>
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" name="password" id="password" required>
        </div>
        <button type="submit" class="btn">Sign in</button>
      </form>
      <div class="footer-text">Secure access for Arden Point Capital staff only.</div>
    </div>
  </div>
</body>
</html>`;


const BAIT_SOLR = { responseHeader: { status: 0, QTime: 1 }, status: 'OK', note: 'Authentication required for admin core' };

const BAIT_AWS_CONSOLE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AWS Management Console</title>
  <style>
    body { font-family: "Amazon Ember", "Helvetica Neue", Arial, sans-serif; background: #232f3e; color: #fff; margin:0; }
    .aws-header { background: #161e2d; padding: 18px 24px; display: flex; align-items: center; gap: 10px; }
    .aws-logo { font-size: 22px; font-weight: 700; color: #ff9900; }
    .container { max-width: 380px; margin: 60px auto; background: #1a2533; border-radius: 8px; padding: 32px; box-shadow: 0 8px 24px rgba(0,0,0,0.4); }
    h1 { font-size: 24px; font-weight: 300; margin: 0 0 24px; }
    .form-group { margin-bottom: 18px; }
    label { font-size: 13px; color: #ccc; display: block; margin-bottom: 6px; }
    input { width: 100%; padding: 11px 14px; background: #0f1a2a; border: 1px solid #445; color: #fff; border-radius: 4px; font-size: 15px; box-sizing: border-box; }
    input:focus { border-color: #ff9900; outline: none; }
    .btn { background: #ff9900; color: #232f3e; font-weight: 600; border: none; padding: 12px; width: 100%; border-radius: 4px; font-size: 15px; cursor: pointer; }
    .btn:hover { background: #e68a00; }
    .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #888; }
  </style>
</head>
<body>
  <div class="aws-header"><div class="aws-logo">AWS</div><span>Management Console</span></div>
  <div class="container">
    <h1>Sign In</h1>
    <form action="/signin" method="post">
      <div class="form-group">
        <label>Account ID or alias</label>
        <input type="text" name="account" placeholder="123456789012 or ardenpointcapital" required>
      </div>
      <div class="form-group">
        <label>IAM user name</label>
        <input type="text" name="username" autocomplete="username" required>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn">Sign In</button>
    </form>
    <div class="footer">Arden Point Capital • Research AWS Account</div>
  </div>
</body>
</html>`;


const BAIT_ECP = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Exchange Admin Center</title>
  <style>
    body { font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif; background: #f3f2f1; margin:0; }
    .ms-header { background: #0078d4; color: #fff; padding: 12px 24px; display: flex; align-items: center; gap: 12px; }
    .ms-header .logo { font-weight: 600; font-size: 18px; }
    .container { max-width: 420px; margin: 60px auto; background: white; border-radius: 4px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    .login-content { padding: 36px 44px; }
    h1 { font-size: 22px; font-weight: 400; margin: 0 0 6px; color: #323130; }
    .subtitle { color: #605e5c; font-size: 14px; margin-bottom: 28px; }
    .form-group { margin-bottom: 18px; }
    label { display: block; font-size: 14px; color: #323130; margin-bottom: 5px; }
    input { width: 100%; padding: 10px 12px; font-size: 16px; border: 1px solid #8a8886; border-radius: 2px; box-sizing: border-box; }
    input:focus { border-color: #0078d4; outline: none; }
    .btn { background: #0078d4; color: white; border: none; padding: 10px 24px; font-size: 15px; border-radius: 2px; cursor: pointer; width: 100%; }
    .btn:hover { background: #106ebe; }
    .footer { margin-top: 24px; font-size: 12px; color: #605e5c; text-align: center; }
  </style>
</head>
<body>
  <div class="ms-header"><div class="logo">Exchange</div><span>Admin Center</span></div>
  <div class="container">
    <div class="login-content">
      <h1>Sign in</h1>
      <p class="subtitle">Use your work or school account</p>
      <form action="/ecp/default.aspx" method="post">
        <div class="form-group">
          <label for="username">Username</label>
          <input type="text" name="username" id="username" placeholder="user@ardenpointcapital.example" required>
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" name="password" id="password" required>
        </div>
        <button type="submit" class="btn">Sign in</button>
      </form>
      <div class="footer">Microsoft Exchange Control Panel — Internal only</div>
    </div>
  </div>
</body>
</html>`;


// ─── Internal route router ───────────────────────────────────────────────────
const router = Router();

// Secret / credential-looking routes (mounted under /api/secrets, see server/index.js)
router.get('/system-prompt', slowDelay, (req, res) => {
  recordHit(req, 'system_prompt_probe');
  res.status(200).json(BAIT_SYSTEM_PROMPT);
});

router.get('/internal/dossier-dump', slowDelay, (req, res) => {
  recordHit(req, 'dossier_dump_probe');
  res.status(200).json(BAIT_DUMP);
});

router.post('/eval', slowDelay, (req, res) => {
  recordHit(req, 'eval_probe');
  res.status(202).json({ ...BAIT_EVAL, run_id: `risk_${Date.now().toString(36)}` });
});

router.get('/eval/results', slowDelay, (req, res) => {
  recordHit(req, 'eval_results_probe');
  res.status(404).json({ error: 'run_id_not_found_or_expired' });
});

export default router;

// ─── Standalone monitored handlers (wired directly in server/index.js) ───────
// These do not live under /api/secrets — they sit at the URLs scanners look for.
// Centralized here so all monitored response shapes are in one file.

export function envFileHandler(req, res) {
  recordHit(req, 'env_probe');
  res.status(200).type('text/plain').send(BAIT_ENV);
}

export function gitConfigHandler(req, res) {
  recordHit(req, 'git_config_probe');
  res.status(200).type('text/plain').send(BAIT_GIT_CONFIG);
}

export function gitHeadHandler(req, res) {
  recordHit(req, 'git_head_probe');
  res.status(200).type('text/plain').send('ref: refs/heads/main\n');
}

export function wpAdminHandler(req, res) {
  recordHit(req, 'wp_admin_probe');
  const wpLoginHtml = `<!DOCTYPE html>
<html lang="en-US">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Log In ‹ Arden Point Capital — WordPress</title>
  <style>
    body.login { background:#f0f0f1; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif; }
    #login { width:320px; padding:8% 0 0; margin:auto; }
    .login h1 { text-align:center; }
    .login h1 a { background-image:url('data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 24 24%22%3E%3Cpath fill=%22%23333%22 d=%22M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z%22/%3E%3C/svg%3E'); background-size:contain; width:84px; height:84px; display:block; margin:0 auto 25px; text-indent:-9999px; overflow:hidden; }
    .login form { margin-top:20px; margin-left:0; padding:26px 24px 46px; background:#fff; box-shadow:0 1px 3px rgba(0,0,0,.04); border:1px solid #c3c4c7; }
    .login label { color:#3c434a; font-size:14px; display:block; margin-bottom:4px; }
    .login input[type=text], .login input[type=password] { font-size:24px; width:100%; padding:3px; margin:2px 6px 16px 0; background:#fbfbfb; border:1px solid #8c8f94; box-shadow:inset 0 1px 2px rgba(0,0,0,.07); color:#2c3338; }
    .login .forgetmenot { float:left; margin-top:3px; }
    .login .submit { float:right; }
    .login .wp-submit { background:#2271b1; border-color:#2271b1; color:#fff; text-decoration:none; text-shadow:0 -1px 1px #2271b1; padding:0 12px 2px; border-radius:3px; font-size:13px; line-height:2.15384615; min-height:30px; cursor:pointer; }
    .login .wp-submit:hover { background:#135e96; border-color:#135e96; }
    .login .lostpassword { text-align:center; margin-top:16px; font-size:13px; }
    .login .lostpassword a { color:#50575e; text-decoration:none; }
    .login .lostpassword a:hover { color:#2271b1; }
    .login #nav, .login #backtoblog { text-align:center; margin-top:24px; font-size:13px; }
    .login #nav a, .login #backtoblog a { color:#50575e; text-decoration:none; }
    .login #nav a:hover, .login #backtoblog a:hover { color:#2271b1; }
    .login .message { border-left:4px solid #72aee6; background:#f0f6fc; padding:12px; margin-bottom:20px; }
    .login .error { border-left:4px solid #d63638; background:#fcf0f1; padding:12px; }
  </style>
</head>
<body class="login">
  <div id="login">
    <h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
    <form id="loginform" name="loginform" action="/wp-login.php" method="post">
      <p>
        <label for="user_login">Username or Email Address</label>
        <input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" required>
      </p>
      <div class="user-pass-wrap">
        <label for="user_pass">Password</label>
        <div class="wp-pwd">
          <input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" required>
          <button type="button" class="button button-secondary wp-hide-pw" aria-label="Show password" onclick="togglePw(this)"><span class="dashicons dashicons-visibility"></span></button>
        </div>
      </div>
      <p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever"> <label for="rememberme">Remember Me</label></p>
      <p class="submit">
        <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary wp-submit" value="Log In">
        <input type="hidden" name="redirect_to" value="/wp-admin/">
      </p>
    </form>
    <p class="lostpassword"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
    <p id="nav">
      <a href="https://wordpress.org/register">Create an account</a> • 
      <a href="https://wordpress.org/">Go to WordPress.org</a>
    </p>
    <p id="backtoblog"><a href="https://wordpress.org/">&larr; Go to Arden Point Capital</a></p>
  </div>
  <script>
    function togglePw(btn) {
      const inp = btn.parentNode.querySelector('input');
      if (inp.type === 'password') { inp.type = 'text'; btn.setAttribute('aria-label','Hide password'); } else { inp.type = 'password'; btn.setAttribute('aria-label','Show password'); }
    }
    // Fake JS to mimic real behavior
    document.getElementById('loginform').addEventListener('submit', function(e) {
      const btn = document.getElementById('wp-submit');
      btn.value = 'Logging in...';
      btn.disabled = true;
    });
  </script>
</body>
</html>`;
  res.status(200).type('text/html').send(wpLoginHtml);
}

export function openApiHandler(req, res) {
  recordHit(req, 'openapi_probe');
  res.status(200).json(BAIT_OPENAPI);
}

export function apiKeysHandler(req, res) {
  recordHit(req, 'api_keys_probe');
  res.status(401).json(BAIT_API_KEYS);
}

export function internalDebugHandler(req, res) {
  recordHit(req, 'internal_debug_probe');
  res.status(401).json(BAIT_DEBUG);
}

export function backupIndexHandler(req, res) {
  recordHit(req, 'backup_probe');
  res.status(200).json(BAIT_BACKUP_INDEX);
}

export function awsCredsHandler(req, res) {
  recordHit(req, 'aws_creds_probe');
  res
    .status(200)
    .type('text/plain')
    .send(
      `[default]\naws_access_key_id = AKIA[REDACTED]\naws_secret_access_key = [REDACTED]\nregion = us-east-1\n`,
    );
}

export function dockerConfigHandler(req, res) {
  recordHit(req, 'docker_config_probe');
  res.status(200).json({
    auths: {
      'registry.internal.ardenpointcapital.example': {
        auth: '[REDACTED]',
      },
    },
  });
}

export function phpmyadminHandler(req, res) {
  recordHit(req, 'phpmyadmin_probe');
  const pmaHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>phpMyAdmin</title>
  <style>
    body { font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; background: #f0f0f0; margin:0; color:#333; }
    .pma-header { background:#3a7ca5; color:white; padding:10px 20px; font-size:22px; font-weight:600; display:flex; align-items:center; gap:8px; }
    .container { max-width:380px; margin:60px auto; background:white; border:1px solid #ccc; border-radius:4px; box-shadow:0 2px 6px rgba(0,0,0,0.1); }
    .login-box { padding:30px 36px; }
    h1 { font-size:18px; margin:0 0 20px; color:#3a7ca5; font-weight:600; }
    .form-row { margin-bottom:14px; }
    label { display:block; font-size:13px; margin-bottom:4px; color:#555; }
    input, select { width:100%; padding:7px 9px; font-size:14px; border:1px solid #aaa; border-radius:3px; box-sizing:border-box; }
    input:focus { border-color:#3a7ca5; outline:none; }
    .btn { background:#3a7ca5; color:white; border:1px solid #2d5f7f; padding:8px 20px; font-size:14px; border-radius:3px; cursor:pointer; }
    .btn:hover { background:#2d5f7f; }
    .note { font-size:11px; color:#777; margin-top:16px; }
    .footer { text-align:center; font-size:11px; color:#888; margin-top:30px; }
  </style>
</head>
<body>
  <div class="pma-header">phpMyAdmin</div>
  <div class="container">
    <div class="login-box">
      <h1>Log in</h1>
      <form action="index.php" method="post">
        <div class="form-row">
          <label>Server:</label>
          <select name="pma_server"><option>localhost</option><option>db.internal.ardenpointcapital.example</option></select>
        </div>
        <div class="form-row">
          <label>Username:</label>
          <input type="text" name="pma_username" required>
        </div>
        <div class="form-row">
          <label>Password:</label>
          <input type="password" name="pma_password" required>
        </div>
        <div class="form-row">
          <label>Language:</label>
          <select><option>English</option><option>Deutsch</option><option>Français</option></select>
        </div>
        <button type="submit" class="btn">Go</button>
      </form>
      <div class="note">You are using phpMyAdmin 5.2.1</div>
    </div>
  </div>
  <div class="footer">Arden Point Capital • Internal Database</div>
</body>
</html>`;
  res.status(200).type('text/html').send(pmaHtml);
}

export function adminerHandler(req, res) {
  recordHit(req, 'adminer_probe');
  const adminerHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login - Adminer</title>
  <style>
    body { font-family: "Segoe UI", system-ui, sans-serif; background: #f8f9fa; margin:0; }
    .adminer-header { background: #1e3a5f; color: #fff; padding: 14px 24px; font-size: 20px; font-weight: 600; }
    .container { max-width: 360px; margin: 60px auto; background: #fff; border: 1px solid #e0e0e0; border-radius: 6px; box-shadow: 0 4px 12px rgba(0,0,0,0.06); }
    .login { padding: 32px; }
    h1 { font-size: 18px; margin: 0 0 22px; color: #1e3a5f; }
    .form-group { margin-bottom: 16px; }
    label { font-size: 13px; color: #555; display: block; margin-bottom: 5px; }
    input, select { width: 100%; padding: 9px 11px; font-size: 15px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
    input:focus { border-color: #1e3a5f; outline: none; }
    .btn { background: #1e3a5f; color: #fff; border: none; padding: 9px 22px; font-size: 14px; border-radius: 4px; cursor: pointer; }
    .btn:hover { background: #2c4f7a; }
    .note { font-size: 12px; color: #888; margin-top: 18px; }
  </style>
</head>
<body>
  <div class="adminer-header">Adminer</div>
  <div class="container">
    <div class="login">
      <h1>Login</h1>
      <form method="post">
        <div class="form-group">
          <label>System</label>
          <select name="auth[driver]"><option>MySQL</option><option>PostgreSQL</option><option>SQLite</option></select>
        </div>
        <div class="form-group">
          <label>Server</label>
          <input type="text" name="auth[server]" value="localhost" required>
        </div>
        <div class="form-group">
          <label>Username</label>
          <input type="text" name="auth[username]" required>
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="auth[password]">
        </div>
        <div class="form-group">
          <label>Database</label>
          <input type="text" name="auth[db]">
        </div>
        <button type="submit" class="btn">Login</button>
      </form>
      <div class="note">Adminer 4.8.1 • APC Internal</div>
    </div>
  </div>
</body>
</html>`;
  res.status(200).type('text/html').send(adminerHtml);
}

export function securityTxtHandler(req, res) {
  // This one is genuine-ish and includes a neutral canary marker for review.
  recordHit(req, 'security_txt_probe');
  const canary = `APC-CASE-${Date.now().toString(36)}`;
  res
    .status(200)
    .type('text/plain')
    .send(
      `Contact: https://x.com/ThatRetiredDude\nExpires: 2099-01-01T00:00:00Z\nPolicy: No denial of service - intrusive scans allowed. Authorized pentesters: include header X-Pentest: authorized\n# canary: ${canary}\n`,
    );
}

export function accessPolicyRobotsHandler(req, res) {
  recordHit(req, 'robots_probe');
  res.status(200).type('text/plain').send(
    `User-agent: *
Disallow: /api/secrets/explore/
Disallow: /api/secrets/internal/
Disallow: /api/internal/
Disallow: /.env
Disallow: /.git/
Disallow: /backups/
Disallow: /admin/
Disallow: /openapi.json

# Internal data room, administrative, and backup paths are not public indexes.
`,
  );
}

// ─── Easy lure handlers (provide interactive feedback on GET/POST) ───────────
export function jenkinsLoginHandler(req, res) {
  recordHit(req, 'jenkins_probe');
  if (req.method === 'POST') {
    const jenkinsError = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in [Jenkins]</title>
<style>
  body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background:#f4f4f4; margin:0; }
  .jenkins-header { background:#1b4b72; color:white; padding:20px; text-align:center; } .jenkins-header h1 { margin:0; font-size:28px; font-weight:300; letter-spacing:1px; }
  .login-wrapper { max-width:420px; margin:60px auto; background:white; border-radius:6px; box-shadow:0 2px 10px rgba(0,0,0,0.1); overflow:hidden; }
  .login-body { padding:40px 48px; }
  .alert { background:#fff3cd; border:1px solid #ffcc00; color:#856404; padding:12px 16px; border-radius:3px; margin-bottom:20px; font-size:14px; }
  h2 { margin:0 0 24px; font-weight:400; color:#333; }
  .form-group { margin-bottom:18px; } label { display:block; font-size:14px; color:#555; margin-bottom:6px; }
  input { width:100%; padding:10px; font-size:16px; border:1px solid #ccc; border-radius:3px; box-sizing:border-box; }
  input:focus { border-color:#1b4b72; outline:none; }
  .btn { background:#1b4b72; color:white; border:none; padding:12px 28px; font-size:15px; border-radius:3px; cursor:pointer; width:100%; }
  .btn:hover { background:#2c5f8f; }
  .links { margin-top:20px; font-size:13px; color:#666; text-align:center; }
  .links a { color:#1b4b72; text-decoration:none; } .links a:hover { text-decoration:underline; }
</style></head><body>
<div class="jenkins-header"><h1>Jenkins</h1></div>
<div class="login-wrapper"><div class="login-body">
  <div class="alert"><strong>Invalid username or password.</strong> Please try again.</div>
  <h2>Sign in to Jenkins</h2>
  <form action="/jenkins/j_acegi_security_check" method="post">
    <div class="form-group"><label for="j_username">Username</label><input type="text" name="j_username" id="j_username" autocomplete="username" required></div>
    <div class="form-group"><label for="j_password">Password</label><input type="password" name="j_password" id="j_password" autocomplete="current-password" required></div>
    <button type="submit" class="btn">Sign in</button>
  </form>
  <div class="links"><a href="/jenkins/passwordReset">Forgot password?</a> · <a href="#">Contact admin</a></div>
</div></div></body></html>`;
    res.status(200).type('text/html').send(jenkinsError);
  } else {
    res.status(200).type('text/html').send(BAIT_JENKINS);
  }
}

export function gitlabSignInHandler(req, res) {
  recordHit(req, 'gitlab_probe');
  if (req.method === 'POST') {
    const errorHtml = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in · GitLab</title>
<style>
  :root { --gl-orange:#FC6D26; } body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background:#f5f5f5; }
  .login-page { min-height:100vh; display:flex; align-items:center; justify-content:center; }
  .container { max-width:400px; width:100%; padding:20px; }
  .gl-header { text-align:center; margin-bottom:32px; }
  .gl-logo { width:48px;height:48px;background:linear-gradient(135deg,#FC6D26,#E24329);border-radius:8px;display:inline-block;position:relative; }
  .gl-logo::after { content:"G"; position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:white;font-size:28px;font-weight:700; }
  h1 { font-size:24px;font-weight:600;color:#2e2e2e;margin:16px 0 8px; }
  .subtitle { color:#666;font-size:14px; }
  .card { background:white;border:1px solid #e0e0e0;border-radius:8px;padding:32px;box-shadow:0 2px 8px rgba(0,0,0,0.05); }
  .alert { background:#fce4e4; border:1px solid #e0a0a0; color:#b33; padding:12px 16px; border-radius:4px; margin-bottom:20px; font-size:14px; }
  .form-group { margin-bottom:20px; } label { display:block; font-size:14px; font-weight:500; color:#333; margin-bottom:6px; }
  input { width:100%; padding:10px 12px; font-size:16px; border:1px solid #d0d0d0; border-radius:4px; box-sizing:border-box; }
  input:focus { border-color:#FC6D26; outline:none; box-shadow:0 0 0 3px rgba(252,109,38,0.1); }
  .remember { display:flex; align-items:center; gap:8px; font-size:14px; color:#555; }
  .btn-primary { background:#FC6D26; color:white; border:none; padding:10px 24px; font-size:16px; font-weight:600; border-radius:4px; width:100%; cursor:pointer; }
  .btn-primary:hover { background:#E24329; }
  .links { margin-top:24px; text-align:center; font-size:14px; }
  .links a { color:#FC6D26; text-decoration:none; }
  .links a:hover { text-decoration:underline; }
</style></head><body>
<div class="login-page"><div class="container">
  <div class="gl-header"><div class="gl-logo"></div><h1>GitLab</h1><p class="subtitle">Sign in to continue to GitLab</p></div>
  <div class="card">
    <div class="alert"><strong>Invalid Login or password.</strong></div>
    <form action="/users/sign_in" method="post" id="new_user">
      <div class="form-group"><label for="user_login">Username or email</label><input type="text" name="user[login]" id="user_login" autocomplete="username" required></div>
      <div class="form-group"><label for="user_password">Password</label><input type="password" name="user[password]" id="user_password" autocomplete="current-password" required></div>
      <div class="form-group remember"><input type="checkbox" name="user[remember_me]" id="user_remember_me" value="1"><label for="user_remember_me">Remember me</label></div>
      <button type="submit" class="btn-primary">Sign in</button>
    </form>
  </div>
  <div class="links"><a href="/users/password/new">Forgot password?</a> · <a href="/users/sign_up">Create an account</a></div>
</div></div></body></html>`;
    res.status(200).type('text/html').send(errorHtml);
  } else {
    res.status(200).type('text/html').send(BAIT_GITLAB);
  }
}

export function grafanaLoginHandler(req, res) {
  recordHit(req, 'grafana_probe');
  if (req.method === 'POST') {
    const grafanaError = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Grafana</title>
<style>
  body { background:#111; color:#d8d9da; font-family:Inter,-apple-system,BlinkMacSystemFont,sans-serif; margin:0; }
  .grafana-container { max-width:380px; margin:80px auto; padding:40px; background:#1f1f1f; border-radius:8px; box-shadow:0 4px 20px rgba(0,0,0,0.5); }
  .logo { display:flex; align-items:center; gap:12px; margin-bottom:32px; }
  .logo svg { width:40px; height:40px; }
  h1 { font-size:28px; font-weight:300; margin:0; color:#fff; }
  .form-group { margin-bottom:20px; } label { font-size:13px; color:#a0a0a0; display:block; margin-bottom:6px; }
  input { width:100%; padding:12px 14px; background:#2a2a2a; border:1px solid #444; color:#fff; border-radius:4px; font-size:15px; box-sizing:border-box; }
  input:focus { border-color:#f05a28; outline:none; }
  .btn { background:#f05a28; color:#fff; border:none; padding:12px; width:100%; font-size:15px; font-weight:600; border-radius:4px; cursor:pointer; }
  .btn:hover { background:#d94d22; }
  .help { margin-top:24px; font-size:13px; color:#888; text-align:center; }
  .help a { color:#f05a28; text-decoration:none; }
  .error { background:#3a1f1f; border:1px solid #a63d3d; color:#ff8a8a; padding:10px; border-radius:4px; margin-bottom:16px; font-size:14px; }
</style></head><body>
<div class="grafana-container">
  <div class="logo">
    <svg viewBox="0 0 24 24" fill="#f05a28"><path d="M12 2L2 7v10l10 5 10-5V7l-10-5zm0 2.18L18.82 7 12 10.82 5.18 7 12 4.18zM4 8.82l8 4v8.36l-8-4V8.82zm16 0v8.36l-8 4v-8.36l8-4z"/></svg>
    <h1>Grafana</h1>
  </div>
  <div class="error"><strong>Invalid username or password.</strong></div>
  <form action="/login" method="post">
    <div class="form-group"><label>Email or username</label><input type="text" name="user" autocomplete="username" required></div>
    <div class="form-group"><label>Password</label><input type="password" name="password" autocomplete="current-password" required></div>
    <button type="submit" class="btn">Log in</button>
  </form>
  <div class="help">Default: admin / admin &nbsp;·&nbsp; <a href="#">Forgot password?</a></div>
</div></body></html>`;
    res.status(200).type('text/html').send(grafanaError);
  } else {
    res.status(200).type('text/html').send(BAIT_GRAFANA);
  }
}

export function actuatorEnvHandler(req, res) {
  recordHit(req, 'actuator_probe');
  const p = req.path || '';
  if (p.includes('/beans')) {
    res.status(200).json({ beans: { 'dataSource': { scope: 'singleton', type: 'com.zaxxer.hikari.HikariDataSource' } } });
  } else if (p.includes('/health')) {
    res.status(200).json({ status: 'UP', components: { db: { status: 'UP' } } });
  } else if (p.includes('/env')) {
    res.status(200).json(BAIT_ACTUATOR_ENV);
  } else {
    res.status(200).json(BAIT_ACTUATOR);
  }
}

export function owaHandler(req, res) {
  recordHit(req, 'owa_probe');
  if (req.method === 'POST') {
    const owaError = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Outlook Web App</title>
<style>
  body { font-family:"Segoe UI",-apple-system,BlinkMacSystemFont,sans-serif; background:#f3f2f1; margin:0; }
  .owa-header { background:#0078d4; color:white; padding:12px 24px; display:flex; align-items:center; gap:12px; }
  .owa-header .logo { font-size:22px; font-weight:600; }
  .container { max-width:440px; margin:60px auto; background:white; border-radius:4px; box-shadow:0 2px 8px rgba(0,0,0,0.1); }
  .login-content { padding:40px 48px; }
  h1 { font-size:24px; font-weight:400; margin:0 0 8px; color:#323130; }
  .subtitle { color:#605e5c; margin-bottom:28px; font-size:14px; }
  .form-group { margin-bottom:18px; } label { display:block; font-size:14px; color:#323130; margin-bottom:6px; }
  input { width:100%; padding:10px 12px; font-size:16px; border:1px solid #8a8886; border-radius:2px; box-sizing:border-box; }
  input:focus { border-color:#0078d4; outline:none; }
  .btn { background:#0078d4; color:white; border:none; padding:10px 24px; font-size:15px; border-radius:2px; cursor:pointer; width:100%; }
  .btn:hover { background:#106ebe; }
  .alert { background:#fde7e9; border:1px solid #f4a3a8; color:#a80000; padding:12px; border-radius:2px; margin-bottom:20px; font-size:14px; }
  .footer-text { margin-top:24px; font-size:12px; color:#605e5c; text-align:center; }
</style></head><body>
<div class="owa-header"><div class="logo">Outlook</div><span>Web App</span></div>
<div class="container"><div class="login-content">
  <h1>Sign in</h1><p class="subtitle">Use your work or school account</p>
  <div class="alert"><strong>Authentication failed.</strong> The username or password is incorrect.</div>
  <form action="/owa/auth.owa" method="post">
    <div class="form-group"><label for="username">Username</label><input type="text" name="username" id="username" placeholder="name@ardenpointcapital.example" required></div>
    <div class="form-group"><label for="password">Password</label><input type="password" name="password" id="password" required></div>
    <button type="submit" class="btn">Sign in</button>
  </form>
  <div class="footer-text">Secure access for Arden Point Capital staff only.</div>
</div></div></body></html>`;
    res.status(200).type('text/html').send(owaError);
  } else {
    res.status(200).type('text/html').send(BAIT_OWA);
  }
}

export function solrHandler(req, res) {
  recordHit(req, 'solr_probe');
  res.status(200).json(BAIT_SOLR);
}

export function awsConsoleHandler(req, res) {
  recordHit(req, 'aws_console_probe');
  if (req.method === 'POST') {
    const awsError = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>AWS Management Console</title>
<style>
  body { font-family:"Amazon Ember","Helvetica Neue",Arial,sans-serif; background:#232f3e; color:#fff; margin:0; }
  .aws-header { background:#161e2d; padding:18px 24px; display:flex; align-items:center; gap:10px; }
  .aws-logo { font-size:22px; font-weight:700; color:#ff9900; }
  .container { max-width:380px; margin:60px auto; background:#1a2533; border-radius:8px; padding:32px; box-shadow:0 8px 24px rgba(0,0,0,0.4); }
  h1 { font-size:24px; font-weight:300; margin:0 0 24px; }
  .form-group { margin-bottom:18px; } label { font-size:13px; color:#ccc; display:block; margin-bottom:6px; }
  input { width:100%; padding:11px 14px; background:#0f1a2a; border:1px solid #445; color:#fff; border-radius:4px; font-size:15px; box-sizing:border-box; }
  input:focus { border-color:#ff9900; outline:none; }
  .btn { background:#ff9900; color:#232f3e; font-weight:600; border:none; padding:12px; width:100%; border-radius:4px; font-size:15px; cursor:pointer; }
  .btn:hover { background:#e68a00; }
  .alert { background:#3a2a1f; border:1px solid #a66d2e; color:#ffcc99; padding:10px; border-radius:4px; margin-bottom:18px; font-size:14px; }
  .footer { text-align:center; margin-top:20px; font-size:12px; color:#888; }
</style></head><body>
<div class="aws-header"><div class="aws-logo">AWS</div><span>Management Console</span></div>
<div class="container">
  <h1>Sign In</h1>
  <div class="alert"><strong>Authentication failed for user.</strong> The credentials you provided are incorrect.</div>
  <form action="/signin" method="post">
    <div class="form-group"><label>Account ID or alias</label><input type="text" name="account" placeholder="123456789012 or ardenpointcapital" required></div>
    <div class="form-group"><label>IAM user name</label><input type="text" name="username" autocomplete="username" required></div>
    <div class="form-group"><label>Password</label><input type="password" name="password" autocomplete="current-password" required></div>
    <button type="submit" class="btn">Sign In</button>
  </form>
  <div class="footer">Arden Point Capital • Research AWS Account</div>
</div></body></html>`;
    res.status(200).type('text/html').send(awsError);
  } else {
    res.status(200).type('text/html').send(BAIT_AWS_CONSOLE);
  }
}

export function exchangeEcpHandler(req, res) {
  recordHit(req, 'ecp_probe');
  if (req.method === 'POST') {
    const ecpError = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Exchange Admin Center</title>
<style>
  body { font-family:"Segoe UI",-apple-system,BlinkMacSystemFont,sans-serif; background:#f3f2f1; margin:0; }
  .ms-header { background:#0078d4; color:#fff; padding:12px 24px; display:flex; align-items:center; gap:12px; }
  .ms-header .logo { font-weight:600; font-size:18px; }
  .container { max-width:420px; margin:60px auto; background:white; border-radius:4px; box-shadow:0 2px 8px rgba(0,0,0,0.1); }
  .login-content { padding:36px 44px; }
  h1 { font-size:22px; font-weight:400; margin:0 0 6px; color:#323130; }
  .subtitle { color:#605e5c; font-size:14px; margin-bottom:28px; }
  .form-group { margin-bottom:18px; } label { display:block; font-size:14px; color:#323130; margin-bottom:5px; }
  input { width:100%; padding:10px 12px; font-size:16px; border:1px solid #8a8886; border-radius:2px; box-sizing:border-box; }
  input:focus { border-color:#0078d4; outline:none; }
  .btn { background:#0078d4; color:white; border:none; padding:10px 24px; font-size:15px; border-radius:2px; cursor:pointer; width:100%; }
  .btn:hover { background:#106ebe; }
  .alert { background:#fde7e9; border:1px solid #f4a3a8; color:#a80000; padding:12px; border-radius:2px; margin-bottom:20px; font-size:14px; }
  .footer { margin-top:24px; font-size:12px; color:#605e5c; text-align:center; }
</style></head><body>
<div class="ms-header"><div class="logo">Exchange</div><span>Admin Center</span></div>
<div class="container"><div class="login-content">
  <h1>Sign in</h1><p class="subtitle">Use your work or school account</p>
  <div class="alert"><strong>The user name or password is incorrect.</strong></div>
  <form action="/ecp/default.aspx" method="post">
    <div class="form-group"><label for="username">Username</label><input type="text" name="username" id="username" placeholder="user@ardenpointcapital.example" required></div>
    <div class="form-group"><label for="password">Password</label><input type="password" name="password" id="password" required></div>
    <button type="submit" class="btn">Sign in</button>
  </form>
  <div class="footer">Microsoft Exchange Control Panel — Internal only</div>
</div></div></body></html>`;
    res.status(200).type('text/html').send(ecpError);
  } else {
    res.status(200).type('text/html').send(BAIT_ECP);
  }
}

// ─── Aggregations used by the admin UI ───────────────────────────────────────
export function countByLureLast24h() {
  return getOne(`
    SELECT COUNT(*) AS n FROM ai_honeypot_hits
    WHERE hit_at > strftime('%Y-%m-%dT%H:%M:%fZ','now','-1 day')
  `)?.n ?? 0;
}
