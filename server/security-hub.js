/**
 * server/security-hub.js
 *
 * Admin-only routes that power the Security Hub UI. All endpoints return
 * filtered + paginated views over the honeypot / tarpit / access / AI-flag
 * tables, plus stats rollups, alert-rule CRUD, and the on-demand share
 * helper.
 *
 * Mounted at /api/admin/security in server/index.js.
 */

import { Router } from 'express';
import { getAll, getOne, run } from './db.js';
import { requireAdmin } from './auth.js';
import { auditReq } from './audit.js';
import { sendShare } from './security-alerts.js';

const router = Router();
router.use(requireAdmin);

// ─── Helpers ────────────────────────────────────────────────────────────────
function parsePage(req) {
  const limit = Math.max(1, Math.min(500, parseInt(req.query.limit, 10) || 50));
  const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
  return { limit, offset };
}

function rangeCutoff(req, fallbackHours = 24) {
  const hours = Math.max(1, Math.min(24 * 90, parseInt(req.query.hours, 10) || fallbackHours));
  return `strftime('%Y-%m-%dT%H:%M:%fZ','now','-${hours} hours')`;
}

function jsonParseSafe(s, fallback = null) {
  try {
    return JSON.parse(s);
  } catch {
    return fallback;
  }
}

// ─── Overview ───────────────────────────────────────────────────────────────
router.get('/overview', (req, res) => {
  const since = rangeCutoff(req, 24);

  const counts = {
    honeypot_hits: Number(
      getOne(`SELECT COUNT(*) AS n FROM ai_honeypot_hits WHERE hit_at > ${since}`)?.n || 0,
    ),
    maze_hits: Number(
      getOne(`SELECT COALESCE(SUM(hit_count),0) AS n FROM maze_hits WHERE last_seen > ${since}`)?.n || 0,
    ),
    access_hits: Number(
      getOne(`SELECT COUNT(*) AS n FROM access_log WHERE hit_at > ${since}`)?.n || 0,
    ),
    ai_flags: Number(
      getOne(`SELECT COUNT(*) AS n FROM ai_input_flags WHERE created_at > ${since}`)?.n || 0,
    ),
    ai_flags_high: Number(
      getOne(
        `SELECT COUNT(*) AS n FROM ai_input_flags WHERE created_at > ${since} AND severity = 'high'`,
      )?.n || 0,
    ),
    unique_ips: Number(
      getOne(
        `SELECT COUNT(DISTINCT ip) AS n FROM (
           SELECT ip FROM ai_honeypot_hits WHERE hit_at > ${since}
           UNION SELECT ip FROM maze_hits WHERE last_seen > ${since}
           UNION SELECT ip FROM access_log WHERE hit_at > ${since} AND token IS NULL
         )`,
      )?.n || 0,
    ),
    decoys_active: Number(
      getOne(`SELECT COUNT(DISTINCT source) AS n FROM ai_honeypot_hits WHERE hit_at > ${since}`)?.n ||
        0,
    ),
  };

  // Per-hour sparkline (last 24h) for each source
  const buildSparkline = (sql) =>
    getAll(sql).map((r) => ({ hour: r.hour, n: Number(r.n) }));

  const sparklines = {
    honeypot: buildSparkline(
      `SELECT strftime('%Y-%m-%dT%H:00:00Z', hit_at) AS hour, COUNT(*) AS n
       FROM ai_honeypot_hits WHERE hit_at > ${since} GROUP BY hour ORDER BY hour`,
    ),
    maze: buildSparkline(
      `SELECT strftime('%Y-%m-%dT%H:00:00Z', last_seen) AS hour, SUM(hit_count) AS n
       FROM maze_hits WHERE last_seen > ${since} GROUP BY hour ORDER BY hour`,
    ),
    access: buildSparkline(
      `SELECT strftime('%Y-%m-%dT%H:00:00Z', hit_at) AS hour, COUNT(*) AS n
       FROM access_log WHERE hit_at > ${since} GROUP BY hour ORDER BY hour`,
    ),
    ai_flags: buildSparkline(
      `SELECT strftime('%Y-%m-%dT%H:00:00Z', created_at) AS hour, COUNT(*) AS n
       FROM ai_input_flags WHERE created_at > ${since} GROUP BY hour ORDER BY hour`,
    ),
  };

  const top_lures = getAll(
    `SELECT source, COUNT(*) AS hits FROM ai_honeypot_hits
     WHERE hit_at > ${since} GROUP BY source ORDER BY hits DESC LIMIT 10`,
  ).map((r) => ({ source: r.source, hits: Number(r.hits) }));

  const top_ips = getAll(
    `SELECT ip, COUNT(*) AS hits FROM ai_honeypot_hits
     WHERE hit_at > ${since} AND ip IS NOT NULL GROUP BY ip ORDER BY hits DESC LIMIT 10`,
  ).map((r) => ({ ip: r.ip, hits: Number(r.hits) }));

  res.json({ window_hours: Number(req.query.hours) || 24, counts, sparklines, top_lures, top_ips });
});

// ─── Honeypot tab ───────────────────────────────────────────────────────────
router.get('/honeypot', (req, res) => {
  const since = rangeCutoff(req, 24);
  const { limit, offset } = parsePage(req);
  const where = [`hit_at > ${since}`];
  const params = [];
  if (req.query.source) {
    where.push(`source = ?`);
    params.push(String(req.query.source));
  }
  if (req.query.ip) {
    where.push(`ip = ?`);
    params.push(String(req.query.ip));
  }
  const rows = getAll(
    `SELECT id, hit_at, ip, ua, method, path, source, token, body_hash, body_excerpt,
            headers_excerpt, enrichment
     FROM ai_honeypot_hits
     WHERE ${where.join(' AND ')}
     ORDER BY hit_at DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset],
  ).map((r) => ({
    ...r,
    headers_excerpt: jsonParseSafe(r.headers_excerpt, {}),
    enrichment: jsonParseSafe(r.enrichment, null),
  }));
  const total = Number(
    getOne(`SELECT COUNT(*) AS n FROM ai_honeypot_hits WHERE ${where.join(' AND ')}`, params)?.n || 0,
  );
  res.json({ rows, total, limit, offset });
});

// ─── Maze (tarpit) tab ──────────────────────────────────────────────────────
router.get('/maze', (req, res) => {
  const since = rangeCutoff(req, 24 * 7);
  const { limit, offset } = parsePage(req);
  const rows = getAll(
    `SELECT id, ip, ua, date, first_seen, last_seen, hit_count, max_depth,
            paths_visited, self_id_token, self_id_raw, enrichment
     FROM maze_hits
     WHERE last_seen > ${since}
     ORDER BY hit_count DESC, last_seen DESC LIMIT ? OFFSET ?`,
    [limit, offset],
  ).map((r) => ({
    ...r,
    paths_visited: jsonParseSafe(r.paths_visited, []),
    enrichment: jsonParseSafe(r.enrichment, null),
  }));
  const total = Number(
    getOne(`SELECT COUNT(*) AS n FROM maze_hits WHERE last_seen > ${since}`)?.n || 0,
  );
  res.json({ rows, total, limit, offset });
});

router.get('/maze/stats', (req, res) => {
  const since = rangeCutoff(req, 24 * 7);
  const totals = getOne(
    `SELECT COUNT(*) AS unique_ips,
            COALESCE(SUM(hit_count),0) AS total_hits,
            COALESCE(MAX(max_depth),0) AS deepest,
            COUNT(self_id_token) AS self_id_count
     FROM maze_hits WHERE last_seen > ${since}`,
  );
  const depthHistogram = getAll(
    `SELECT max_depth AS depth, COUNT(*) AS n FROM maze_hits
     WHERE last_seen > ${since} GROUP BY max_depth ORDER BY depth`,
  ).map((r) => ({ depth: Number(r.depth), n: Number(r.n) }));
  // crude token+cost estimate: assume avg ~500 tokens per page, $0.0001/1k (very rough)
  const totalHits = Number(totals?.total_hits || 0);
  const estimated_tokens = totalHits * 500;
  const estimated_cost_usd = estimated_tokens * 0.0001 / 1000;
  res.json({
    window_hours: Number(req.query.hours) || 24 * 7,
    unique_ips: Number(totals?.unique_ips || 0),
    total_hits: totalHits,
    deepest: Number(totals?.deepest || 0),
    self_id_count: Number(totals?.self_id_count || 0),
    estimated_tokens,
    estimated_cost_usd,
    depth_histogram: depthHistogram,
  });
});

// ─── Access log tab ─────────────────────────────────────────────────────────
router.get('/access', (req, res) => {
  const since = rangeCutoff(req, 24);
  const { limit, offset } = parsePage(req);
  const where = [`hit_at > ${since}`];
  const params = [];
  if (req.query.token_null === '1') where.push(`token IS NULL`);
  if (req.query.ip) {
    where.push(`ip = ?`);
    params.push(String(req.query.ip));
  }
  const rows = getAll(
    `SELECT id, hit_at, ip, user_agent, referer, token, path
     FROM access_log WHERE ${where.join(' AND ')}
     ORDER BY hit_at DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset],
  );
  const total = Number(
    getOne(`SELECT COUNT(*) AS n FROM access_log WHERE ${where.join(' AND ')}`, params)?.n || 0,
  );
  res.json({ rows, total, limit, offset });
});

// ─── AI flags tab ───────────────────────────────────────────────────────────
router.get('/ai-flags', (req, res) => {
  const since = rangeCutoff(req, 24 * 7);
  const { limit, offset } = parsePage(req);
  const where = [`created_at > ${since}`];
  const params = [];
  if (req.query.severity) {
    where.push(`severity = ?`);
    params.push(String(req.query.severity));
  }
  if (req.query.user_id) {
    where.push(`user_id = ?`);
    params.push(String(req.query.user_id));
  }
  const rows = getAll(
    `SELECT id, user_id, username, route, channel, severity, reasons, input_excerpt,
            ip, ua, path, action_taken, created_at
     FROM ai_input_flags WHERE ${where.join(' AND ')}
     ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset],
  ).map((r) => ({ ...r, reasons: jsonParseSafe(r.reasons, []) }));
  const total = Number(
    getOne(`SELECT COUNT(*) AS n FROM ai_input_flags WHERE ${where.join(' AND ')}`, params)?.n || 0,
  );
  res.json({ rows, total, limit, offset });
});

// ─── Flagged IPs derived from enrichment ────────────────────────────────────
router.get('/flagged', (req, res) => {
  const since = rangeCutoff(req, 24 * 7);
  // Pull enrichment from all sources, group by IP, surface the worst flags
  const honeypotRows = getAll(
    `SELECT ip, COUNT(*) AS hits, MAX(enrichment) AS enrichment
     FROM ai_honeypot_hits WHERE hit_at > ${since} AND ip IS NOT NULL AND enrichment IS NOT NULL
     GROUP BY ip`,
  );
  const mazeRows = getAll(
    `SELECT ip, SUM(hit_count) AS hits, MAX(enrichment) AS enrichment
     FROM maze_hits WHERE last_seen > ${since} AND ip IS NOT NULL AND enrichment IS NOT NULL
     GROUP BY ip`,
  );
  const byIp = new Map();
  for (const r of honeypotRows) {
    byIp.set(r.ip, {
      ip: r.ip,
      hits: Number(r.hits),
      enrichment: jsonParseSafe(r.enrichment, null),
      sources: ['honeypot'],
    });
  }
  for (const r of mazeRows) {
    const existing = byIp.get(r.ip);
    if (existing) {
      existing.hits += Number(r.hits);
      existing.sources.push('maze');
    } else {
      byIp.set(r.ip, {
        ip: r.ip,
        hits: Number(r.hits),
        enrichment: jsonParseSafe(r.enrichment, null),
        sources: ['maze'],
      });
    }
  }

  const rows = [...byIp.values()].map((entry) => {
    const flags = entry.enrichment?.summary?.flags || [];
    const threat = entry.enrichment?.summary?.threat_level || 'unknown';
    const country = entry.enrichment?.summary?.country || null;
    const org = entry.enrichment?.summary?.org || null;
    return { ...entry, threat_level: threat, flags, country, org };
  });

  rows.sort((a, b) => b.hits - a.hits);
  res.json({ rows });
});

// ─── Honeypot lure inventory ────────────────────────────────────────────────
router.get('/lures', (_req, res) => {
  // Static manifest of currently-mounted lures + any historical sources we've
  // seen in ai_honeypot_hits. Keeps the admin UI honest about what's deployed.
  const known = [
    { source: 'system_prompt_probe', path: 'GET /api/ai/system-prompt' },
    { source: 'dossier_dump_probe', path: 'GET /api/ai/internal/dossier-dump' },
    { source: 'eval_probe', path: 'POST /api/ai/eval' },
    { source: 'eval_results_probe', path: 'GET /api/ai/eval/results' },
    { source: 'env_probe', path: 'GET /.env (+ .local/.production)' },
    { source: 'git_config_probe', path: 'GET /.git/config' },
    { source: 'git_head_probe', path: 'GET /.git/HEAD' },
    { source: 'aws_creds_probe', path: 'GET /.aws/credentials' },
    { source: 'docker_config_probe', path: 'GET /.docker/config.json' },
    { source: 'wp_admin_probe', path: 'GET /wp-admin, /wp-login.php, /xmlrpc.php' },
    { source: 'phpmyadmin_probe', path: 'GET /phpmyadmin' },
    { source: 'adminer_probe', path: 'GET /adminer.php' },
    { source: 'openapi_probe', path: 'GET /openapi.json, /swagger.json' },
    { source: 'api_keys_probe', path: 'GET /api/keys, /api/admin/api-keys' },
    { source: 'internal_debug_probe', path: 'GET /api/internal/debug' },
    { source: 'backup_probe', path: 'GET /backup.sql, /dump.sql, /db_backup.zip' },
    { source: 'security_txt_probe', path: 'GET /.well-known/security.txt' },
    { source: 'robots_probe', path: 'GET /robots.txt' },
  ];

  const seen = getAll(
    `SELECT source, COUNT(*) AS hits, MAX(hit_at) AS last_hit FROM ai_honeypot_hits GROUP BY source`,
  );
  const seenMap = Object.fromEntries(
    seen.map((r) => [r.source, { hits: Number(r.hits), last_hit: r.last_hit }]),
  );

  const rows = known.map((l) => ({
    ...l,
    hits: seenMap[l.source]?.hits || 0,
    last_hit: seenMap[l.source]?.last_hit || null,
  }));

  // Surface any unknown sources we've seen but don't have in the manifest
  const knownIds = new Set(known.map((l) => l.source));
  for (const r of seen) {
    if (!knownIds.has(r.source)) {
      rows.push({
        source: r.source,
        path: '(unknown — manifest mismatch)',
        hits: Number(r.hits),
        last_hit: r.last_hit,
      });
    }
  }

  res.json({ rows });
});

// ─── Alert rules CRUD ───────────────────────────────────────────────────────
router.get('/alerts', (_req, res) => {
  const rules = getAll(
    `SELECT * FROM security_alert_rules ORDER BY id`,
  ).map((r) => ({ ...r, predicate: jsonParseSafe(r.predicate, {}), enabled: !!r.enabled }));
  const deliveries = getAll(
    `SELECT id, rule_id, fired_at, payload_excerpt, ok, error
     FROM security_alert_deliveries ORDER BY fired_at DESC LIMIT 50`,
  ).map((r) => ({ ...r, payload_excerpt: jsonParseSafe(r.payload_excerpt, null), ok: !!r.ok }));
  res.json({ rules, deliveries });
});

const VALID_SOURCES = new Set(['ai_flags', 'access_log', 'honeypot', 'maze']);
const VALID_CHANNELS = new Set(['email', 'discord', 'telegram', 'webhook']);

function validateRulePayload(body) {
  const errs = [];
  if (!body || typeof body !== 'object') errs.push('body_must_be_object');
  if (!body.name || typeof body.name !== 'string') errs.push('name_required');
  if (!VALID_SOURCES.has(body.source)) errs.push(`source_must_be_one_of_${[...VALID_SOURCES].join('|')}`);
  if (!VALID_CHANNELS.has(body.channel)) errs.push(`channel_must_be_one_of_${[...VALID_CHANNELS].join('|')}`);
  if (!body.recipient || typeof body.recipient !== 'string') errs.push('recipient_required');
  return errs;
}

router.post('/alerts', (req, res) => {
  const errs = validateRulePayload(req.body);
  if (errs.length) return res.status(400).json({ error: 'invalid_payload', details: errs });
  const cooldown = Number(req.body.cooldown_min) || 5;
  const enabled = req.body.enabled === false ? 0 : 1;
  const result = run(
    `INSERT INTO security_alert_rules
       (name, source, predicate, channel, recipient, enabled, cooldown_min, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      String(req.body.name).slice(0, 200),
      req.body.source,
      JSON.stringify(req.body.predicate || {}),
      req.body.channel,
      String(req.body.recipient).slice(0, 500),
      enabled,
      cooldown,
      req.user?.id || null,
    ],
  );
  auditReq(req, {
    actionType: 'security_alert_rule.create',
    targetType: 'security_alert_rule',
    targetId: String(result.lastInsertRowid),
    payload: { name: req.body.name, source: req.body.source, channel: req.body.channel },
  });
  res.json({ ok: true, id: Number(result.lastInsertRowid) });
});

router.put('/alerts/:id', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
  const existing = getOne(`SELECT * FROM security_alert_rules WHERE id = ?`, [id]);
  if (!existing) return res.status(404).json({ error: 'not_found' });
  const errs = validateRulePayload({ ...existing, ...req.body });
  if (errs.length) return res.status(400).json({ error: 'invalid_payload', details: errs });
  run(
    `UPDATE security_alert_rules SET
       name = ?, source = ?, predicate = ?, channel = ?, recipient = ?, enabled = ?, cooldown_min = ?
     WHERE id = ?`,
    [
      String(req.body.name || existing.name).slice(0, 200),
      req.body.source || existing.source,
      JSON.stringify(req.body.predicate || jsonParseSafe(existing.predicate, {})),
      req.body.channel || existing.channel,
      String(req.body.recipient || existing.recipient).slice(0, 500),
      req.body.enabled === false ? 0 : req.body.enabled === true ? 1 : existing.enabled,
      Number(req.body.cooldown_min) || existing.cooldown_min,
      id,
    ],
  );
  auditReq(req, {
    actionType: 'security_alert_rule.update',
    targetType: 'security_alert_rule',
    targetId: String(id),
  });
  res.json({ ok: true });
});

router.delete('/alerts/:id', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
  const result = run(`DELETE FROM security_alert_rules WHERE id = ?`, [id]);
  if (result.changes === 0) return res.status(404).json({ error: 'not_found' });
  auditReq(req, {
    actionType: 'security_alert_rule.delete',
    targetType: 'security_alert_rule',
    targetId: String(id),
  });
  res.json({ ok: true });
});

// ─── Share helper ───────────────────────────────────────────────────────────
router.post('/share', async (req, res) => {
  try {
    const { source, channel, recipient, subject, format } = req.body || {};
    if (!VALID_CHANNELS.has(channel)) {
      return res.status(400).json({ error: 'invalid_channel' });
    }
    const hours = Math.max(1, Math.min(24 * 90, Number(req.body.hours) || 24));
    let rows = [];
    if (source === 'honeypot') {
      rows = getAll(
        `SELECT hit_at, source, ip, ua, method, path FROM ai_honeypot_hits
         WHERE hit_at > strftime('%Y-%m-%dT%H:%M:%fZ','now','-${hours} hours')
         ORDER BY hit_at DESC LIMIT 500`,
      );
    } else if (source === 'maze') {
      rows = getAll(
        `SELECT ip, ua, hit_count, max_depth, last_seen FROM maze_hits
         WHERE last_seen > strftime('%Y-%m-%dT%H:%M:%fZ','now','-${hours} hours')
         ORDER BY hit_count DESC LIMIT 500`,
      );
    } else if (source === 'access_log') {
      rows = getAll(
        `SELECT hit_at, ip, user_agent, path, token FROM access_log
         WHERE hit_at > strftime('%Y-%m-%dT%H:%M:%fZ','now','-${hours} hours')
         ORDER BY hit_at DESC LIMIT 500`,
      );
    } else if (source === 'ai_flags') {
      rows = getAll(
        `SELECT created_at, severity, username, ip, input_excerpt, reasons, action_taken
         FROM ai_input_flags
         WHERE created_at > strftime('%Y-%m-%dT%H:%M:%fZ','now','-${hours} hours')
         ORDER BY created_at DESC LIMIT 500`,
      );
    } else {
      return res.status(400).json({ error: 'invalid_source' });
    }

    await sendShare({
      channel,
      recipient,
      subject: subject || `InfiniPot · ${source} (${hours}h)`,
      rows,
      format: format || 'csv',
    });
    auditReq(req, {
      actionType: 'security.share',
      payload: { source, channel, row_count: rows.length },
    });
    res.json({ ok: true, row_count: rows.length });
  } catch (err) {
    res.status(500).json({ error: err?.message || 'share_failed' });
  }
});

export default router;
