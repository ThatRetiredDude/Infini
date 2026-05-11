/**
 * server/ai-honeypot.js
 *
 * Decoy endpoints + hit logging. Every route here exists only to catch
 * automated scrapers and LLM crawlers that follow every URL they find.
 *
 * Real users never see or call these — they're referenced exclusively from
 * the hidden `<HoneypotBait>` SPA component, the `robots.txt`, and (for some
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
 * Record a honeypot hit. Synchronous DB insert (SQLite), then fires
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
    `[honeypot] ${new Date().toISOString()} | src=${source} | ip=${ip} | ${method} ${path} | ua=${ua.slice(0, 80)}`,
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
     
    console.error('[honeypot] insert failed:', err?.message || err);
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

// ─── Bait content ────────────────────────────────────────────────────────────
// All bait is plausible-looking but information-free. Some lures deliberately
// take ~400-700 ms to respond to burn scraper time.

const SLOW_MIN = 350;
const SLOW_RANGE = 400;
function slowDelay(req, res, next) {
  setTimeout(next, SLOW_MIN + Math.random() * SLOW_RANGE);
}

const BAIT_SYSTEM_PROMPT = {
  version: '2.1',
  role: 'analyst',
  instructions: '[REDACTED — access requires signed token]',
  context_window: 8192,
  tools_available: ['search', 'lookup', 'enrich'],
};

const BAIT_DUMP = {
  status: 'partial',
  page: 1,
  total_pages: null,
  records: [],
  _note: 'Full export requires POST /api/internal/export with a valid session_token.',
};

const BAIT_EVAL = {
  eval_id: null,
  status: 'queued',
  model: 'grok-4.3-latest',
  estimated_tokens: 0,
  _note: 'Eval submitted. Retrieve results at GET /api/ai/eval/results?id={eval_id}.',
};

const BAIT_ENV = `# do not commit
NODE_ENV=production
DATABASE_URL=postgres://user:[REDACTED]@db.internal:5432/mi
JWT_SECRET=[REDACTED]
XAI_API_KEY=[REDACTED]
STRIPE_SECRET_KEY=[REDACTED]
INTERNAL_API_TOKEN=[REDACTED]
`;

const BAIT_GIT_CONFIG = `[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = git@internal.maxwellinternational:mi/archive.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
`;

const BAIT_OPENAPI = {
  openapi: '3.0.0',
  info: { title: 'InfiniPot Internal API', version: '0.0.0-decoy' },
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
  _example: { provider: 'xai', key_prefix: 'xai-1k_…', expires_at: '2027-01-01T00:00:00Z' },
};

const BAIT_DEBUG = {
  uptime_s: Math.floor(process.uptime()),
  memory: { rss_mb: Math.round((process.memoryUsage?.().rss || 0) / 1e6) },
  flags: { ai_disabled: false, maintenance: false },
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

// ─── Decoy router ────────────────────────────────────────────────────────────
const router = Router();

// AI / LLM lures (mounted under /api/ai, see server/index.js)
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
  res.status(202).json({ ...BAIT_EVAL, eval_id: `eval_${Date.now().toString(36)}` });
});

router.get('/eval/results', slowDelay, (req, res) => {
  recordHit(req, 'eval_results_probe');
  res.status(404).json({ error: 'eval_id_not_found_or_expired' });
});

export default router;

// ─── Standalone decoy handlers (wired directly in server/index.js) ───────────
// These do not live under /api/ai — they sit at the URLs scanners look for.
// Centralized here so all bait response shapes are in one file.

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
  res
    .status(200)
    .type('text/html')
    .send(
      `<!doctype html><html><head><title>Log In ‹ Archive — WordPress</title></head><body><form id="loginform" action="/wp-login.php" method="post"><label>Username<input type="text" name="log" /></label><label>Password<input type="password" name="pwd" /></label><input type="submit" name="wp-submit" value="Log In" /></form></body></html>`,
    );
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
      'registry.internal.maxwellinternational': {
        auth: '[REDACTED]',
      },
    },
  });
}

export function phpmyadminHandler(req, res) {
  recordHit(req, 'phpmyadmin_probe');
  res
    .status(200)
    .type('text/html')
    .send(
      `<!doctype html><html><head><title>phpMyAdmin</title></head><body><form action="index.php" method="post"><input name="pma_username" /><input name="pma_password" type="password" /></form></body></html>`,
    );
}

export function adminerHandler(req, res) {
  recordHit(req, 'adminer_probe');
  res
    .status(200)
    .type('text/html')
    .send(`<!doctype html><html><head><title>Login - Adminer</title></head><body><form action="" method="post"></form></body></html>`);
}

export function securityTxtHandler(req, res) {
  // This one is genuine-ish — points to honeypot-aware contact, with a bait
  // canary in the comment so any scraper that follows the canary is logged.
  recordHit(req, 'security_txt_probe');
  const canary = `MI-CANARY-${Date.now().toString(36)}`;
  res
    .status(200)
    .type('text/plain')
    .send(
      `Contact: mailto:security@example.invalid\nExpires: 2099-01-01T00:00:00Z\nPolicy: https://example.invalid/security-policy\n# canary: ${canary}\n`,
    );
}

export function honeypotRobotsHandler(req, res) {
  recordHit(req, 'robots_probe');
  res.status(200).type('text/plain').send(
    `User-agent: *
Disallow: /api/ai/explore/
Disallow: /api/ai/internal/
Disallow: /api/internal/
Disallow: /.env
Disallow: /.git/
Disallow: /backups/
Disallow: /admin/
Disallow: /openapi.json

# AI-specific signals
User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

User-agent: anthropic-ai
Disallow: /

User-agent: cohere-ai
Disallow: /

# noai / noimageai everywhere — see meta tags + X-Robots-Tag
`,
  );
}

// ─── Aggregations used by the admin UI ───────────────────────────────────────
export function countByLureLast24h() {
  return getOne(`
    SELECT COUNT(*) AS n FROM ai_honeypot_hits
    WHERE hit_at > strftime('%Y-%m-%dT%H:%M:%fZ','now','-1 day')
  `)?.n ?? 0;
}
