/**
 * server/security-hub.js
 *
 * Admin-only routes that power the Security Hub UI. All endpoints return
 * filtered + paginated views over monitored endpoint / data-room / access / AI-flag
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
import { filterTorExits, getTorFeedStats } from './tor-feed.js';

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

function sqlHoursAgo(h) {
  const n = Math.max(1, Math.min(24 * 90, h));
  return `strftime('%Y-%m-%dT%H:%M:%fZ','now','-${n} hours')`;
}

function uaFamily(ua) {
  const u = (ua || '').toLowerCase();
  if (/gptbot/.test(u)) return 'GPTBot (OpenAI)';
  if (/chatgpt/.test(u)) return 'ChatGPT-User';
  if (/claudebot/.test(u) || /anthropic/.test(u)) return 'ClaudeBot (Anthropic)';
  if (/gemini/.test(u) || /googlebot/.test(u)) return 'Google / Gemini';
  if (/perplexity/.test(u)) return 'PerplexityBot';
  if (/python-requests/.test(u)) return 'python-requests';
  if (/python/.test(u)) return 'Python (other)';
  if (/curl\//.test(u)) return 'curl';
  if (/wget/.test(u)) return 'wget';
  if (/scrapy/.test(u)) return 'Scrapy';
  if (/go-http/.test(u)) return 'Go HTTP client';
  if (/java/.test(u)) return 'Java HTTP';
  if (/httpx/.test(u)) return 'httpx';
  if (/aiohttp/.test(u)) return 'aiohttp';
  if (!u) return '(no UA)';
  return 'Other';
}

function csvEscapeVal(val) {
  const s = String(val ?? '').replace(/"/g, '""');
  return /[",\n\r]/.test(s) ? `"${s}"` : s;
}
function rowsToCsv(rows) {
  if (!rows.length) return '';
  const headers = Object.keys(rows[0]);
  const lines = [headers.map(csvEscapeVal).join(',')];
  for (const row of rows) {
    lines.push(
      headers
        .map((h) => csvEscapeVal(typeof row[h] === 'object' ? JSON.stringify(row[h]) : row[h]))
        .join(','),
    );
  }
  return lines.join('\r\n');
}

// ─── Overview (legacy-compatible shape + extra counts for InfiniPot) ─────────
router.get('/overview', (req, res) => {
  const since24 = sqlHoursAgo(24);
  const since7d = sqlHoursAgo(24 * 7);
  const cutoff168 = sqlHoursAgo(24 * 7);

  const ai_flags_row = getOne(
    `SELECT
       SUM(CASE WHEN created_at > ${since24} THEN 1 ELSE 0 END) AS flags_24h,
       SUM(CASE WHEN created_at > ${since7d} THEN 1 ELSE 0 END) AS flags_7d,
       SUM(CASE WHEN severity = 'high' AND created_at > ${since24} THEN 1 ELSE 0 END) AS high_24h,
       SUM(CASE WHEN severity = 'medium' AND created_at > ${since24} THEN 1 ELSE 0 END) AS medium_24h,
       SUM(CASE WHEN severity = 'low' AND created_at > ${since24} THEN 1 ELSE 0 END) AS low_24h
     FROM ai_input_flags`,
  );
  const mi_access_row = getOne(
    `SELECT
       SUM(CASE WHEN hit_at > ${since24} THEN 1 ELSE 0 END) AS hits_24h,
       SUM(CASE WHEN hit_at > ${since7d} THEN 1 ELSE 0 END) AS hits_7d,
       SUM(CASE WHEN token IS NULL AND hit_at > ${since24} THEN 1 ELSE 0 END) AS honeypot_24h
     FROM access_log`,
  );
  const honeypot_row = getOne(
    `SELECT
       SUM(CASE WHEN hit_at > ${since24} THEN 1 ELSE 0 END) AS hits_24h,
       SUM(CASE WHEN hit_at > ${since7d} THEN 1 ELSE 0 END) AS hits_7d
     FROM ai_honeypot_hits`,
  );
  const maze_tot = getOne(`
    SELECT
      (SELECT COUNT(DISTINCT ip) FROM maze_hits) AS unique_ips_all,
      (SELECT COUNT(DISTINCT ip) FROM maze_hits WHERE date >= date('now', '-6 days')) AS unique_ips_7d,
      COALESCE((SELECT SUM(hit_count) FROM maze_hits), 0) AS total_hits_all,
      COALESCE((SELECT SUM(hit_count) FROM maze_hits WHERE date = date('now')), 0) AS hits_today,
      COALESCE((SELECT SUM(hit_count) FROM maze_hits WHERE date >= date('now', '-6 days')), 0) AS hits_7d,
      COALESCE((SELECT SUM(CASE WHEN self_id_token IS NOT NULL THEN 1 ELSE 0 END) FROM maze_hits), 0) AS self_ids_all
     `);

  const top_ips = getAll(`
    SELECT ip, CAST(SUM(n) AS INTEGER) AS n FROM (
      SELECT ip, COUNT(*) AS n FROM ai_input_flags WHERE ip IS NOT NULL AND created_at > ${since24}
      GROUP BY ip
      UNION ALL
      SELECT ip, COUNT(*) AS n FROM access_log WHERE ip IS NOT NULL AND hit_at > ${since24}
      GROUP BY ip
      UNION ALL
      SELECT ip, COUNT(*) AS n FROM ai_honeypot_hits WHERE ip IS NOT NULL AND hit_at > ${since24}
      GROUP BY ip
      UNION ALL
      SELECT ip, hit_count AS n FROM maze_hits WHERE ip IS NOT NULL AND date = date('now')
    ) t GROUP BY ip ORDER BY n DESC LIMIT 10`);

  const sparkFlags = getAll(`
    SELECT date(created_at) AS day, COUNT(*) AS n FROM ai_input_flags
    WHERE created_at > ${cutoff168} GROUP BY 1 ORDER BY 1`).map((r) => ({ day: r.day, n: Number(r.n) }));
  const sparkMi = getAll(`
    SELECT date(hit_at) AS day, COUNT(*) AS n FROM access_log
    WHERE hit_at > ${cutoff168} GROUP BY 1 ORDER BY 1`).map((r) => ({ day: r.day, n: Number(r.n) }));
  const sparkMaze = getAll(`
    SELECT date AS day, CAST(SUM(hit_count) AS INTEGER) AS n FROM maze_hits
    WHERE date >= date('now', '-6 days') GROUP BY date ORDER BY date`).map((r) => ({
    day: r.day,
    n: Number(r.n),
  }));

  const since = rangeCutoff(req, 24);
  const counts = {
    honeypot_hits: Number(getOne(`SELECT COUNT(*) AS n FROM ai_honeypot_hits WHERE hit_at > ${since}`)?.n || 0),
    maze_hits: Number(
      getOne(`SELECT COALESCE(SUM(hit_count),0) AS n FROM maze_hits WHERE last_seen > ${since}`)?.n ||
        0,
    ),
    access_hits: Number(getOne(`SELECT COUNT(*) AS n FROM access_log WHERE hit_at > ${since}`)?.n || 0),
    ai_flags: Number(getOne(`SELECT COUNT(*) AS n FROM ai_input_flags WHERE created_at > ${since}`)?.n || 0),
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

  const top_lures = getAll(
    `SELECT source, COUNT(*) AS hits FROM ai_honeypot_hits
     WHERE hit_at > ${since} GROUP BY source ORDER BY hits DESC LIMIT 10`,
  ).map((r) => ({ source: r.source, hits: Number(r.hits) }));

  res.json({
    ai_flags: {
      flags_24h: Number(ai_flags_row?.flags_24h || 0),
      flags_7d: Number(ai_flags_row?.flags_7d || 0),
      high_24h: Number(ai_flags_row?.high_24h || 0),
      medium_24h: Number(ai_flags_row?.medium_24h || 0),
      low_24h: Number(ai_flags_row?.low_24h || 0),
    },
    mi_access: {
      hits_24h: Number(mi_access_row?.hits_24h || 0),
      hits_7d: Number(mi_access_row?.hits_7d || 0),
      honeypot_24h: Number(mi_access_row?.honeypot_24h || 0),
    },
    honeypot: {
      hits_24h: Number(honeypot_row?.hits_24h || 0),
      hits_7d: Number(honeypot_row?.hits_7d || 0),
    },
    maze: {
      unique_ips_all: Number(maze_tot?.unique_ips_all || 0),
      unique_ips_7d: Number(maze_tot?.unique_ips_7d || 0),
      hits_today: Number(maze_tot?.hits_today || 0),
      hits_7d: Number(maze_tot?.hits_7d || 0),
      self_ids_all: Number(maze_tot?.self_ids_all || 0),
    },
    top_ips,
    sparklines: { flags: sparkFlags, mi_access: sparkMi, maze: sparkMaze },
    counts,
    top_lures,
  });
});

router.get('/overview/geo', (req, res) => {
  const mazeRows = getAll(`SELECT ip, enrichment, hit_count FROM maze_hits WHERE enrichment IS NOT NULL`);
  const hpRows = getAll(`SELECT ip, enrichment, 1 AS hit_count FROM ai_honeypot_hits WHERE enrichment IS NOT NULL`);
  const byCountry = new Map();
  const byOrg = new Map();
  for (const r of [...mazeRows, ...hpRows]) {
    const e = jsonParseSafe(r.enrichment, {});
    const c = e?.summary?.country || e?.ipinfo?.country || null;
    const org = e?.summary?.org || e?.ipinfo?.org || null;
    const w = Number(r.hit_count) || 1;
    const ipKey = r.ip;
    if (c) {
      const x = byCountry.get(c) || { country: c, ips: new Set(), hits: 0 };
      x.ips.add(ipKey);
      x.hits += w;
      byCountry.set(c, x);
    }
    if (org) {
      const x = byOrg.get(org) || { org, ips: new Set(), hits: 0 };
      x.ips.add(ipKey);
      x.hits += w;
      byOrg.set(org, x);
    }
  }
  const countries = [...byCountry.values()]
    .map((x) => ({ country: x.country, ips: x.ips.size, hits: x.hits }))
    .sort((a, b) => b.hits - a.hits)
    .slice(0, 30);
  const asns = [...byOrg.values()]
    .map((x) => ({ org: x.org, ips: x.ips.size, hits: x.hits }))
    .sort((a, b) => b.hits - a.hits)
    .slice(0, 20);
  res.json({ countries, asns });
});

// ─── Monitored endpoint aggregate stats (for Security Hub dashboards) ────────
router.get('/honeypot/stats', (_req, res) => {
  const since24 = sqlHoursAgo(24);
  const since168 = sqlHoursAgo(24 * 7);
  const totals = getOne(`
    SELECT
      (SELECT COUNT(*) FROM ai_honeypot_hits) AS hits_all,
      (SELECT COUNT(*) FROM ai_honeypot_hits WHERE hit_at > ${since24}) AS hits_24h,
      (SELECT COUNT(*) FROM ai_honeypot_hits WHERE hit_at > ${since168}) AS hits_7d,
      (SELECT COUNT(DISTINCT ip) FROM ai_honeypot_hits WHERE ip IS NOT NULL AND hit_at > ${since24}) AS distinct_ips_24h,
      (SELECT COUNT(DISTINCT ip) FROM ai_honeypot_hits WHERE ip IS NOT NULL) AS distinct_ips_all,
      (SELECT COUNT(DISTINCT source) FROM ai_honeypot_hits WHERE source IS NOT NULL) AS distinct_sources_seen
  `);
  const by_source = getAll(`
    SELECT source, COUNT(*) AS hits
      FROM ai_honeypot_hits
      WHERE hit_at > ${since168}
      GROUP BY source
      ORDER BY hits DESC LIMIT 50
  `).map((r) => ({
    ...r,
    hits: Number(r.hits || 0),
  }));
  const top_paths = getAll(`
    SELECT path, COUNT(*) AS hits
      FROM ai_honeypot_hits
      WHERE hit_at > ${since24} AND path IS NOT NULL AND path <> ''
      GROUP BY path
      ORDER BY hits DESC LIMIT 25
  `).map((r) => ({
    ...r,
    hits: Number(r.hits || 0),
  }));
  res.json({
    totals: {
      hits_all: Number(totals?.hits_all || 0),
      hits_24h: Number(totals?.hits_24h || 0),
      hits_7d: Number(totals?.hits_7d || 0),
      distinct_ips_24h: Number(totals?.distinct_ips_24h || 0),
      distinct_ips_all: Number(totals?.distinct_ips_all || 0),
      distinct_sources_seen: Number(totals?.distinct_sources_seen || 0),
    },
    by_source,
    top_paths,
  });
});

// ─── Monitored endpoints tab ────────────────────────────────────────────────
router.get('/honeypot', (req, res) => {
  if (req.query.since || req.query.until) {
    const clauses = [];
    const sp = [];
    if (req.query.since) {
      clauses.push(`hit_at >= ?`);
      sp.push(`${String(req.query.since).slice(0, 10)}T00:00:00.000Z`);
    }
    if (req.query.until) {
      clauses.push(`hit_at <= ?`);
      sp.push(`${String(req.query.until).slice(0, 10)}T23:59:59.999Z`);
    }
    return finishHoneypot(req, res, clauses.join(' AND '), sp);
  }
  return finishHoneypot(req, res, `hit_at > ${rangeCutoff(req, 24)}`, []);
});

function finishHoneypot(req, res, hitClause, baseParams = []) {
  const { limit, offset } = parsePage(req);
  const where = [hitClause];
  const params = [...baseParams];
  if (req.query.source) {
    where.push(`source = ?`);
    params.push(String(req.query.source));
  }
  if (req.query.ip) {
    where.push(`ip = ?`);
    params.push(String(req.query.ip));
  }
  if (req.query.ua_like) {
    where.push(`LOWER(IFNULL(ua,'')) LIKE ?`);
    params.push(`%${String(req.query.ua_like).slice(0, 200).toLowerCase()}%`);
  }
  const wc = where.join(' AND ');
  const rows = getAll(
    `SELECT id, hit_at, ip, ua, method, path, source, token, body_hash, body_excerpt,
            headers_excerpt, enrichment
     FROM ai_honeypot_hits
     WHERE ${wc}
     ORDER BY hit_at DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset],
  ).map((r) => ({
    ...r,
    headers_excerpt: jsonParseSafe(r.headers_excerpt, {}),
    enrichment: jsonParseSafe(r.enrichment, null),
  }));
  const total = Number(getOne(`SELECT COUNT(*) AS n FROM ai_honeypot_hits WHERE ${wc}`, params)?.n || 0);
  res.json({ rows, total, totalCount: total, limit, offset });
}

// ─── Data room activity ────────────────────────────────────────────────────
router.get('/maze/live', (_req, res) => {
  const rowsRaw = getAll(
    `SELECT ip, ua, date, last_seen, hit_count, max_depth, self_id_token, enrichment
     FROM maze_hits ORDER BY last_seen DESC LIMIT 20`,
  );
  const rows = rowsRaw.map((r) => {
    const e = jsonParseSafe(r.enrichment, null);
    return {
      ...r,
      enrich_summary: e?.summary || null,
      enrichment: e,
    };
  });
  res.json({ rows });
});

router.get('/maze/ip/:ip', (req, res) => {
  const ip = String(req.params.ip || '').slice(0, 128);
  if (!ip) return res.status(400).json({ error: 'ip required' });

  const daysRows = getAll(
    `SELECT * FROM maze_hits WHERE ip = ? ORDER BY date DESC LIMIT 90`,
    [ip],
  ).map((r) => ({
    ...r,
    paths_visited: jsonParseSafe(r.paths_visited, []),
    enrichment: jsonParseSafe(r.enrichment, null),
  }));

  const summary = getOne(
    `SELECT
       COUNT(*) AS total_days,
       COALESCE(SUM(hit_count),0) AS total_hits,
       MAX(hit_count) AS peak_hits_day,
       MAX(max_depth) AS deepest,
       MIN(first_seen) AS first_ever,
       MAX(last_seen) AS last_ever,
       SUM(CASE WHEN self_id_token IS NOT NULL THEN 1 ELSE 0 END) AS self_id_days
     FROM maze_hits WHERE ip = ?`,
    [ip],
  );

  const topUaRow = getOne(
    `SELECT ua FROM maze_hits WHERE ip = ? ORDER BY hit_count DESC LIMIT 1`,
    [ip],
  );
  let enrichAgg = null;
  const enrichedRow = getOne(
    `SELECT enrichment FROM maze_hits WHERE ip = ? AND enrichment IS NOT NULL ORDER BY hit_count DESC LIMIT 1`,
    [ip],
  );
  if (enrichedRow?.enrichment) enrichAgg = jsonParseSafe(enrichedRow.enrichment, null);

  const totalHits = Number(summary?.total_hits || 0);
  const tokens_generated = totalHits * 1000;
  const tokens_pipeline_est = totalHits * 2000;
  const cost_usd_est =
    Math.round(((tokens_pipeline_est / 1_000_000) * 15 + Number.EPSILON) * 100) / 100;

  res.json({
    ip,
    summary: {
      ...summary,
      total_hits: totalHits,
      tokens_generated,
      tokens_pipeline_est,
      cost_usd_est,
      time_ms_est: totalHits * 1800,
      enrichment: enrichAgg,
      top_ua: topUaRow?.ua || null,
    },
    days: daysRows,
  });
});

router.get('/maze', (req, res) => {
  const clauses = [`1=1`];
  const params = [];
  if (req.query.since) {
    clauses.push(`date >= ?`);
    params.push(String(req.query.since).slice(0, 10));
  }
  if (req.query.until) {
    clauses.push(`date <= ?`);
    params.push(String(req.query.until).slice(0, 10));
  }
  if (req.query.ip) {
    clauses.push(`ip = ?`);
    params.push(String(req.query.ip));
  }
  if (req.query.self_id_only === 'true') {
    clauses.push(`self_id_token IS NOT NULL`);
  }

  let sinceRolling = '';
  if (!req.query.since && !req.query.until && !req.query.ip && req.query.self_id_only !== 'true') {
    sinceRolling = rangeCutoff(req, 24 * 7);
    clauses.push(`last_seen > ${sinceRolling}`);
  }

  const where = clauses.join(' AND ');
  const { limit, offset } = parsePage(req);

  let selectSql = `SELECT mh.*`;
  if (!req.query.ip) {
    selectSql += `, (SELECT COUNT(DISTINCT date) FROM maze_hits mh2 WHERE mh2.ip = mh.ip) AS distinct_days`;
  } else {
    selectSql += `, NULL AS distinct_days`;
  }
  selectSql += ` FROM maze_hits mh WHERE ${where}`;

  const rows = getAll(
    `${selectSql} ORDER BY hit_count DESC, last_seen DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset],
  ).map((r) => ({
    ...r,
    paths_visited: jsonParseSafe(r.paths_visited, []),
    enrichment: jsonParseSafe(r.enrichment, null),
  }));

  const total = Number(getOne(`SELECT COUNT(*) AS n FROM maze_hits mh WHERE ${where}`, params)?.n || 0);
  res.json({ rows, total, totalCount: total, limit, offset });
});

router.get('/maze/stats', (_req, res) => {
  const depth_histogram = getAll(
    `SELECT max_depth AS max_depth,
            CAST(COUNT(DISTINCT ip) AS INTEGER) AS ips,
            CAST(SUM(hit_count) AS INTEGER) AS hits
     FROM maze_hits GROUP BY max_depth ORDER BY max_depth`,
  );

  const mazeRowsUa = getAll(`SELECT ua, ip, COALESCE(hit_count,0) AS hc FROM maze_hits`);
  const uaFamMap = new Map();
  for (const row of mazeRowsUa) {
    const family = uaFamily(row.ua);
    if (!uaFamMap.has(family)) {
      uaFamMap.set(family, { family, ips: new Set(), hits: 0 });
    }
    const b = uaFamMap.get(family);
    b.hits += Number(row.hc) || 0;
    b.ips.add(row.ip);
  }
  const ua_summary = [...uaFamMap.values()]
    .map(({ family, ips, hits }) => ({ family, ips: ips.size, hits }))
    .sort((a, b) => b.hits - a.hits)
    .slice(0, 15);

  const totals = getOne(
    `SELECT
       COALESCE(SUM(hit_count),0) AS total_hits,
       COUNT(DISTINCT ip) AS unique_ips,
       SUM(CASE WHEN self_id_token IS NOT NULL THEN 1 ELSE 0 END) AS self_ids,
       COALESCE(MAX(hit_count),0) AS max_hits_single_ip
     FROM maze_hits`,
  );
  const totalHits = Number(totals?.total_hits || 0);
  const tokensGenerated = totalHits * 1000;
  const tokensPipelineEst = totalHits * 2000;
  const costUsdEst = Math.round(((tokensPipelineEst / 1_000_000) * 15 + Number.EPSILON) * 100) / 100;
  const timeMsEst = totalHits * 1800;

  res.json({
    depth_histogram,
    ua_summary,
    totals: {
      ...totals,
      total_hits: totalHits,
      tokens_generated: tokensGenerated,
      tokens_pipeline_est: tokensPipelineEst,
      cost_usd_est: costUsdEst,
      time_ms_est: timeMsEst,
    },
  });
});

router.get('/tor-feed', async (req, res) => {
  try {
    const stats = getTorFeedStats();
    const ipsParam = req.query.ips;
    if (ipsParam) {
      const ips = String(ipsParam)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
        .slice(0, 200);
      const torSet = await filterTorExits(ips);
      return res.json({ ...stats, checked: ips.length, tor_ips: [...torSet] });
    }
    res.json(stats);
  } catch (e) {
    res.status(500).json({ error: e?.message || 'tor_feed_error' });
  }
});

// ─── Access log (MI access) ─────────────────────────────────────────────────
function listAccessLog(req, res) {
  const clauses = [];
  const p2 = [];
  if (!(req.query.since || req.query.until)) {
    clauses.push(`hit_at > ${rangeCutoff(req, 24)}`);
  } else {
    if (req.query.since) {
      clauses.push(`hit_at >= ?`);
      p2.push(`${String(req.query.since).slice(0, 10)}T00:00:00.000Z`);
    }
    if (req.query.until) {
      clauses.push(`hit_at <= ?`);
      p2.push(`${String(req.query.until).slice(0, 10)}T23:59:59.999Z`);
    }
  }
  if (req.query.token_null === 'true' || req.query.token_null === '1') clauses.push(`token IS NULL`);
  if (req.query.token_null === 'false') clauses.push(`token IS NOT NULL`);
  if (req.query.ip) {
    clauses.push(`ip = ?`);
    p2.push(String(req.query.ip));
  }
  if (req.query.ua_like) {
    clauses.push(`LOWER(IFNULL(user_agent,'')) LIKE ?`);
    p2.push(`%${String(req.query.ua_like).slice(0, 200).toLowerCase()}%`);
  }
  if (req.query.referer_like) {
    clauses.push(`LOWER(IFNULL(referer,'')) LIKE ?`);
    p2.push(`%${String(req.query.referer_like).slice(0, 200).toLowerCase()}%`);
  }

  const { limit, offset } = parsePage(req);
  const wc = clauses.join(' AND ');
  const rows = getAll(
    `SELECT id, hit_at, ip, user_agent, referer, token, path
     FROM access_log WHERE ${wc}
     ORDER BY hit_at DESC LIMIT ? OFFSET ?`,
    [...p2, limit, offset],
  );
  const total = Number(getOne(`SELECT COUNT(*) AS n FROM access_log WHERE ${wc}`, p2)?.n || 0);
  const fmt = req.query.format;
  if (fmt === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="mi-access.csv"');
    return res.send(rowsToCsv(rows));
  }
  if (fmt === 'json') {
    res.setHeader('Content-Disposition', 'attachment; filename="mi-access.json"');
    return res.json(rows);
  }
  res.json({ rows, total, totalCount: total, limit, offset });
}

router.get('/access', listAccessLog);
router.get('/mi-access', listAccessLog);

// ─── AI flags tab ───────────────────────────────────────────────────────────
router.get('/ai-flags', (req, res) => {
  const since = req.query.days
    ? `strftime('%Y-%m-%dT%H:%M:%fZ','now','-${Math.min(365, Number(req.query.days) || 7) * 24} hours')`
    : rangeCutoff(req, 24 * 7);
  const { limit, offset } = parsePage(req);
  const where = [`created_at > ${since}`];
  const params = [];
  if (req.query.severity) {
    where.push(`severity = ?`);
    params.push(String(req.query.severity));
  }
  if (req.query.route) {
    where.push(`route = ?`);
    params.push(String(req.query.route));
  }
  if (req.query.channel) {
    where.push(`channel = ?`);
    params.push(String(req.query.channel));
  }
  if (req.query.user_id) {
    where.push(`user_id = ?`);
    params.push(String(req.query.user_id));
  }
  if (req.query.ip) {
    where.push(`ip = ?`);
    params.push(String(req.query.ip));
  }
  if (req.query.date_from) {
    where.push(`date(created_at) >= date(?)`);
    params.push(String(req.query.date_from).slice(0, 10));
  }
  if (req.query.date_to) {
    where.push(`date(created_at) <= date(?)`);
    params.push(String(req.query.date_to).slice(0, 10));
  }
  const wc = where.join(' AND ');
  const flagsRows = getAll(
    `SELECT id, user_id, username, route, channel, severity, reasons, input_excerpt,
            ip, ua, path, action_taken, created_at
     FROM ai_input_flags WHERE ${wc}
     ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset],
  ).map((r) => ({ ...r, reasons: jsonParseSafe(r.reasons, []) }));
  const totalCount = Number(getOne(`SELECT COUNT(*) AS n FROM ai_input_flags WHERE ${wc}`, params)?.n || 0);

  const format = req.query.format;
  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="ai-flags.csv"');
    return res.send(rowsToCsv(flagsRows));
  }
  if (format === 'json') {
    res.setHeader('Content-Disposition', 'attachment; filename="ai-flags.json"');
    return res.json(flagsRows);
  }
  res.json({ flags: flagsRows, rows: flagsRows, totalCount, total: totalCount, limit, offset });
});

// ─── Flagged IPs (legacy UI: repeat offenders, abuse, Tor) ───────────────────
router.get('/flagged', async (req, res) => {
  try {
    const cutoff = sqlHoursAgo(24 * 90);

    const repeatRows = getAll(
      `SELECT ip, CAST(COUNT(DISTINCT day) AS INTEGER) AS days,
              CAST(SUM(hits) AS INTEGER) AS total_hits,
              MAX(last_seen) AS last_seen,
              MAX(enrichment) AS enrichment
       FROM (
         SELECT ip, date AS day, hit_count AS hits, last_seen, enrichment FROM maze_hits WHERE last_seen > ${cutoff}
         UNION ALL
         SELECT ip, date(hit_at) AS day, 1 AS hits, hit_at AS last_seen, enrichment
         FROM ai_honeypot_hits WHERE ip IS NOT NULL AND hit_at > ${cutoff}
       ) x
       GROUP BY ip HAVING COUNT(DISTINCT day) >= 5
       ORDER BY total_hits DESC LIMIT 200`,
    ).map((r) => ({
      ...r,
      enrichment: typeof r.enrichment === 'string' ? jsonParseSafe(r.enrichment, null) : r.enrichment,
    }));

    const highAbuse = [];
    const seenAbuseIp = new Set();
    for (const r of getAll(`
      SELECT ip, enrichment, last_seen, source FROM (
        SELECT ip, enrichment, last_seen, 'maze' AS source FROM maze_hits
          WHERE enrichment IS NOT NULL AND last_seen > ${cutoff}
        UNION ALL
        SELECT ip, enrichment, hit_at AS last_seen, 'honeypot' FROM ai_honeypot_hits
          WHERE ip IS NOT NULL AND enrichment IS NOT NULL AND hit_at > ${cutoff}
      )`)) {
      const e = typeof r.enrichment === 'string' ? jsonParseSafe(r.enrichment, {}) : r.enrichment;
      const score = Number(e?.abuseipdb?.abuse_confidence);
      if (!Number.isFinite(score) || score < 50) continue;
      if (seenAbuseIp.has(r.ip)) continue;
      seenAbuseIp.add(r.ip);
      highAbuse.push({
        ip: r.ip,
        enrichment: e,
        last_seen: r.last_seen,
        source: r.source,
      });
    }

    const allForTor = getAll(`
      SELECT ip FROM maze_hits WHERE ip IS NOT NULL
      UNION SELECT ip FROM ai_honeypot_hits WHERE ip IS NOT NULL
      UNION SELECT ip FROM access_log WHERE ip IS NOT NULL`);
    const uniqueIps = [...new Set(allForTor.map((x) => x.ip))];
    const torSet = await filterTorExits(uniqueIps);

    let torHits = [];
    for (const ip of torSet) {
      const mh = getOne(
        `SELECT enrichment, last_seen FROM maze_hits WHERE ip = ? ORDER BY last_seen DESC LIMIT 1`,
        [ip],
      );
      const pick =
        mh ||
        getOne(
          `SELECT enrichment, hit_at AS last_seen FROM ai_honeypot_hits WHERE ip = ? ORDER BY hit_at DESC LIMIT 1`,
          [ip],
        );
      if (pick) {
        torHits.push({
          ip,
          enrichment: jsonParseSafe(pick.enrichment, null),
          last_seen: pick.last_seen,
          flags: ['tor'],
        });
      }
    }

    torHits.sort((a, b) =>
      String(b.last_seen || '').localeCompare(String(a.last_seen || '')),
    );
    torHits = torHits.slice(0, 500);

    const mapRepeat = repeatRows.map((r) => ({
      ...r,
      is_tor: torSet.has(r.ip),
      flags: ['repeat', torSet.has(r.ip) ? 'tor' : null].filter(Boolean),
      enrichment: typeof r.enrichment === 'object' ? r.enrichment : r.enrichment,
    }));

    const mapAbuse = highAbuse.map((r) => ({
      ip: r.ip,
      enrichment: r.enrichment,
      last_seen: r.last_seen,
      source: r.source,
      is_tor: torSet.has(r.ip),
      flags: ['high-abuse', torSet.has(r.ip) ? 'tor' : null].filter(Boolean),
    }));

    res.json({
      repeat_offenders: mapRepeat,
      high_abuse: mapAbuse,
      tor_hits: torHits,
      tor_feed: getTorFeedStats(),
    });
  } catch (e) {
    res.status(500).json({ error: e?.message || 'flagged_error' });
  }
});

// ─── Monitored endpoint inventory ───────────────────────────────────────────
router.get('/lures', (_req, res) => {
  // Static manifest of currently-mounted lures + any historical sources we've
  // seen in ai_honeypot_hits. Keeps the admin UI honest about what's deployed.
  const known = [
    { source: 'system_prompt_probe', path: 'GET /api/secrets/system-prompt' },
    { source: 'dossier_dump_probe', path: 'GET /api/secrets/internal/dossier-dump' },
    { source: 'eval_probe', path: 'POST /api/secrets/eval' },
    { source: 'eval_results_probe', path: 'GET /api/secrets/eval/results' },
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
  const rules = getAll(`SELECT * FROM security_alert_rules ORDER BY id`).map((r) => ({
    ...r,
    source: r.source === 'access_log' ? 'mi_access' : r.source,
    predicate: jsonParseSafe(r.predicate, {}),
    enabled: !!r.enabled,
  }));
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

function coerceAlertPayload(body = {}) {
  const out = { ...body };
  if (out.source === 'mi_access') out.source = 'access_log';
  return out;
}

router.post('/alerts', (req, res) => {
  const body = coerceAlertPayload(req.body);
  const errs = validateRulePayload(body);
  if (errs.length) return res.status(400).json({ error: 'invalid_payload', details: errs });
  const cooldown = Number(body.cooldown_min) || 5;
  const enabled = body.enabled === false ? 0 : 1;
  const result = run(
    `INSERT INTO security_alert_rules
       (name, source, predicate, channel, recipient, enabled, cooldown_min, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      String(body.name).slice(0, 200),
      body.source,
      JSON.stringify(body.predicate || {}),
      body.channel,
      String(body.recipient).slice(0, 500),
      enabled,
      cooldown,
      req.user?.id || null,
    ],
  );
  auditReq(req, {
    actionType: 'security_alert_rule.create',
    targetType: 'security_alert_rule',
    targetId: String(result.lastInsertRowid),
    payload: { name: body.name, source: body.source, channel: body.channel },
  });
  res.json({ ok: true, id: Number(result.lastInsertRowid) });
});

router.put('/alerts/:id', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
  const existing = getOne(`SELECT * FROM security_alert_rules WHERE id = ?`, [id]);
  if (!existing) return res.status(404).json({ error: 'not_found' });
  const merged = coerceAlertPayload({
    name: req.body.name ?? existing.name,
    source: req.body.source ?? existing.source,
    channel: req.body.channel ?? existing.channel,
    recipient: req.body.recipient ?? existing.recipient,
    enabled:
      typeof req.body.enabled === 'boolean' ? req.body.enabled : Boolean(Number(existing.enabled)),
    cooldown_min: req.body.cooldown_min ?? existing.cooldown_min,
    predicate:
      req.body.predicate !== undefined ? req.body.predicate : jsonParseSafe(existing.predicate, {}),
  });
  const errs = validateRulePayload(merged);
  if (errs.length) return res.status(400).json({ error: 'invalid_payload', details: errs });
  const predObj =
    typeof merged.predicate === 'object' && merged.predicate !== null
      ? merged.predicate
      : jsonParseSafe(String(merged.predicate || '{}'), {});
  run(
    `UPDATE security_alert_rules SET
       name = ?, source = ?, predicate = ?, channel = ?, recipient = ?, enabled = ?, cooldown_min = ?
     WHERE id = ?`,
    [
      String(merged.name).slice(0, 200),
      merged.source,
      JSON.stringify(predObj),
      merged.channel,
      String(merged.recipient).slice(0, 500),
      merged.enabled === false ? 0 : 1,
      Number(merged.cooldown_min) || existing.cooldown_min,
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
    } else if (source === 'access_log' || source === 'mi_access') {
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
      format: ['csv', 'json'].includes(format) ? format : format || 'summary',
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
