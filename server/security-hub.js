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
import { auditReq } from './audit.js';
import { sendShare } from './security-alerts.js';
import { filterTorExits, getTorFeedStats } from './tor-feed.js';

const router = Router();

// Allow admins full access; guests (demo) get read-only (GET only) to showcase monitoring.
router.use((req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'authentication_required' });
  const isAdmin = req.user.role === 'admin' || req.user.is_admin;
  const isGuest = req.user.role === 'guest';
  if (isAdmin || isGuest) {
    if (isGuest && req.method !== 'GET') {
      return res.status(403).json({ error: 'read_only_demo_account' });
    }
    return next();
  }
  return res.status(403).json({ error: 'admin_required' });
});

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

function decoyEventWhere(req, { suspiciousOnly = false } = {}) {
  const where = [];
  const params = [];
  if (suspiciousOnly) where.push(`suspicious = 1`);
  if (!(req.query.since || req.query.until)) {
    where.push(`created_at > ${rangeCutoff(req, suspiciousOnly ? 24 * 7 : 24)}`);
  } else {
    if (req.query.since) {
      where.push(`created_at >= ?`);
      params.push(`${String(req.query.since).slice(0, 10)}T00:00:00.000Z`);
    }
    if (req.query.until) {
      where.push(`created_at <= ?`);
      params.push(`${String(req.query.until).slice(0, 10)}T23:59:59.999Z`);
    }
  }
  for (const [queryKey, col] of [
    ['source', 'source'],
    ['decoy_id', 'decoy_id'],
    ['action', 'action'],
    ['severity', 'severity'],
    ['method', 'method'],
    ['protocol', 'protocol'],
    ['event_type', 'event_type'],
    ['ip', 'ip'],
  ]) {
    if (req.query[queryKey]) {
      where.push(`${col} = ?`);
      params.push(String(req.query[queryKey]).slice(0, 256));
    }
  }
  if (req.query.path_contains) {
    where.push(`LOWER(IFNULL(path,'')) LIKE ?`);
    params.push(`%${String(req.query.path_contains).slice(0, 200).toLowerCase()}%`);
  }
  if (req.query.has_payload === 'true') where.push(`(body_excerpt IS NOT NULL OR payload_json IS NOT NULL)`);
  if (req.query.has_payload === 'false') where.push(`body_excerpt IS NULL AND payload_json IS NULL`);
  if (req.query.has_body === 'true') where.push(`body_excerpt IS NOT NULL`);
  if (req.query.has_body === 'false') where.push(`body_excerpt IS NULL`);
  return { where: where.length ? where.join(' AND ') : '1=1', params };
}

function normalizeDecoyEventRow(r) {
  return {
    ...r,
    suspicious: !!r.suspicious,
    reasons: jsonParseSafe(r.reasons, []),
    query: jsonParseSafe(r.query, {}),
    headers_excerpt: jsonParseSafe(r.headers_excerpt, {}),
    payload_json: jsonParseSafe(r.payload_json, r.payload_json || null),
    enrichment: jsonParseSafe(r.enrichment, null),
  };
}

function decoyEventOrder(req) {
  const sort = String(req.query.sort || 'newest');
  if (sort === 'oldest') return 'created_at ASC';
  if (sort === 'severity') {
    return `CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC, created_at DESC`;
  }
  if (sort === 'payload_size') return 'payload_size DESC, created_at DESC';
  if (sort === 'action') return 'action ASC, created_at DESC';
  if (sort === 'ip_frequency') {
    return `(SELECT COUNT(*) FROM decoy_access_events d2 WHERE d2.ip = decoy_access_events.ip) DESC, created_at DESC`;
  }
  return 'created_at DESC';
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

// ─── Overview (legacy-compatible shape + extra counts for Infini) ─────────
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
  const network_row = getOne(
    `SELECT
       SUM(CASE WHEN hit_at > ${since24} THEN 1 ELSE 0 END) AS events_24h,
       SUM(CASE WHEN hit_at > ${since7d} THEN 1 ELSE 0 END) AS events_7d
     FROM network_sensor_events`,
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
      SELECT peer_ip AS ip, COUNT(*) AS n FROM network_sensor_events
        WHERE peer_ip IS NOT NULL AND hit_at > ${since24}
      GROUP BY peer_ip
      UNION ALL
      SELECT ip, hit_count AS n FROM maze_hits WHERE ip IS NOT NULL AND date = date('now')
    ) t GROUP BY ip ORDER BY n DESC LIMIT 10`);

  const sparkFlags = getAll(`
    SELECT date(created_at) AS day, COUNT(*) AS n FROM ai_input_flags
    WHERE created_at > ${cutoff168} GROUP BY 1 ORDER BY 1`).map((r) => ({ day: r.day, n: Number(r.n) }));
  const sparkMi = getAll(`
    SELECT date(hit_at) AS day, COUNT(*) AS n FROM access_log
    WHERE hit_at > ${cutoff168} GROUP BY 1 ORDER BY 1`).map((r) => ({ day: r.day, n: Number(r.n) }));
  const sparkNetwork = getAll(`
    SELECT date(hit_at) AS day, COUNT(*) AS n FROM network_sensor_events
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
           UNION SELECT peer_ip AS ip FROM network_sensor_events WHERE hit_at > ${since} AND peer_ip IS NOT NULL
         )`,
      )?.n || 0,
    ),
    network_events: Number(
      getOne(`SELECT COUNT(*) AS n FROM network_sensor_events WHERE hit_at > ${since}`)?.n || 0,
    ),
    network_distinct_ips: Number(
      getOne(
        `SELECT COUNT(DISTINCT peer_ip) AS n FROM network_sensor_events WHERE hit_at > ${since} AND peer_ip IS NOT NULL`,
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
    network_sensor: {
      events_24h: Number(network_row?.events_24h || 0),
      events_7d: Number(network_row?.events_7d || 0),
    },
    maze: {
      unique_ips_all: Number(maze_tot?.unique_ips_all || 0),
      unique_ips_7d: Number(maze_tot?.unique_ips_7d || 0),
      hits_today: Number(maze_tot?.hits_today || 0),
      hits_7d: Number(maze_tot?.hits_7d || 0),
      self_ids_all: Number(maze_tot?.self_ids_all || 0),
    },
    top_ips,
    sparklines: {
      flags: sparkFlags,
      mi_access: sparkMi,
      network_sensor: sparkNetwork,
      maze: sparkMaze,
    },
    counts,
    top_lures,
  });
});

function latLngFromEnrichment(e) {
  if (!e || typeof e !== 'object') return null;
  const info = e.ipinfo;
  if (!info) return null;
  if (typeof info.latitude === 'number' && typeof info.longitude === 'number') {
    return { lat: info.latitude, lng: info.longitude };
  }
  if (info.loc && typeof info.loc === 'string') {
    const parts = info.loc.split(',').map((x) => parseFloat(String(x).trim()));
    if (parts.length >= 2 && Number.isFinite(parts[0]) && Number.isFinite(parts[1])) {
      return { lat: parts[0], lng: parts[1] };
    }
  }
  return null;
}

function countryFromEnrichment(e) {
  if (!e || typeof e !== 'object') return null;
  return e.summary?.country || e.ipinfo?.country || e.abuseipdb?.country_code || null;
}

const COUNTRY_CENTROIDS = {
  AD: [42.5, 1.6], AE: [24.0, 54.0], AF: [33.0, 65.0], AG: [17.05, -61.8], AI: [18.25, -63.17],
  AL: [41.0, 20.0], AM: [40.0, 45.0], AO: [-12.5, 18.5], AR: [-34.0, -64.0], AS: [-14.33, -170.0],
  AT: [47.33, 13.33], AU: [-27.0, 133.0], AW: [12.5, -69.97], AZ: [40.5, 47.5], BA: [44.0, 18.0],
  BB: [13.17, -59.53], BD: [24.0, 90.0], BE: [50.83, 4.0], BF: [13.0, -2.0], BG: [43.0, 25.0],
  BH: [26.0, 50.55], BI: [-3.5, 30.0], BJ: [9.5, 2.25], BM: [32.33, -64.75], BN: [4.5, 114.67],
  BO: [-17.0, -65.0], BR: [-10.0, -55.0], BS: [24.25, -76.0], BT: [27.5, 90.5], BW: [-22.0, 24.0],
  BY: [53.0, 28.0], BZ: [17.25, -88.75], CA: [60.0, -95.0], CD: [0.0, 25.0], CF: [7.0, 21.0],
  CG: [-1.0, 15.0], CH: [47.0, 8.0], CI: [8.0, -5.0], CK: [-21.23, -159.77], CL: [-30.0, -71.0],
  CM: [6.0, 12.0], CN: [35.0, 105.0], CO: [4.0, -72.0], CR: [10.0, -84.0], CU: [21.5, -80.0],
  CV: [16.0, -24.0], CY: [35.0, 33.0], CZ: [49.75, 15.5], DE: [51.0, 9.0], DJ: [11.5, 43.0],
  DK: [56.0, 10.0], DM: [15.42, -61.33], DO: [19.0, -70.67], DZ: [28.0, 3.0], EC: [-2.0, -77.5],
  EE: [59.0, 26.0], EG: [27.0, 30.0], ER: [15.0, 39.0], ES: [40.0, -4.0], ET: [8.0, 38.0],
  FI: [64.0, 26.0], FJ: [-18.0, 175.0], FK: [-51.75, -59.0], FM: [6.92, 158.25], FO: [62.0, -7.0],
  FR: [46.0, 2.0], GA: [-1.0, 11.75], GB: [54.0, -2.0], GD: [12.12, -61.67], GE: [42.0, 43.5],
  GF: [4.0, -53.0], GH: [8.0, -2.0], GI: [36.18, -5.37], GL: [72.0, -40.0], GM: [13.47, -16.57],
  GN: [11.0, -10.0], GP: [16.25, -61.58], GQ: [2.0, 10.0], GR: [39.0, 22.0], GT: [15.5, -90.25],
  GU: [13.47, 144.78], GW: [12.0, -15.0], GY: [5.0, -59.0], HK: [22.25, 114.17], HN: [15.0, -86.5],
  HR: [45.17, 15.5], HT: [19.0, -72.42], HU: [47.0, 20.0], ID: [-5.0, 120.0], IE: [53.0, -8.0],
  IL: [31.5, 34.75], IN: [20.0, 77.0], IQ: [33.0, 44.0], IR: [32.0, 53.0], IS: [65.0, -18.0],
  IT: [42.83, 12.83], JM: [18.25, -77.5], JO: [31.0, 36.0], JP: [36.0, 138.0], KE: [1.0, 38.0],
  KG: [41.0, 75.0], KH: [13.0, 105.0], KI: [1.42, 173.0], KM: [-12.17, 44.25], KN: [17.33, -62.75],
  KP: [40.0, 127.0], KR: [37.0, 127.5], KW: [29.34, 47.66], KY: [19.5, -80.5], KZ: [48.0, 68.0],
  LA: [18.0, 105.0], LB: [33.83, 35.83], LC: [13.88, -61.13], LI: [47.17, 9.53], LK: [7.0, 81.0],
  LR: [6.5, -9.5], LS: [-29.5, 28.5], LT: [56.0, 24.0], LU: [49.75, 6.17], LV: [57.0, 25.0],
  LY: [25.0, 17.0], MA: [32.0, -5.0], MC: [43.73, 7.4], MD: [47.0, 29.0], ME: [42.5, 19.3],
  MG: [-20.0, 47.0], MH: [9.0, 168.0], MK: [41.83, 22.0], ML: [17.0, -4.0], MM: [22.0, 98.0],
  MN: [46.0, 105.0], MO: [22.17, 113.55], MP: [15.2, 145.75], MQ: [14.67, -61.0], MR: [20.0, -12.0],
  MS: [16.75, -62.2], MT: [35.83, 14.58], MU: [-20.28, 57.55], MV: [3.25, 73.0], MW: [-13.5, 34.0],
  MX: [23.0, -102.0], MY: [2.5, 112.5], MZ: [-18.25, 35.0], NA: [-22.0, 17.0], NC: [-21.5, 165.5],
  NE: [16.0, 8.0], NG: [10.0, 8.0], NI: [13.0, -85.0], NL: [52.5, 5.75], NO: [62.0, 10.0],
  NP: [28.0, 84.0], NR: [-0.53, 166.92], NU: [-19.03, -169.87], NZ: [-41.0, 174.0], OM: [21.0, 57.0],
  PA: [9.0, -80.0], PE: [-10.0, -76.0], PF: [-15.0, -140.0], PG: [-6.0, 147.0], PH: [13.0, 122.0],
  PK: [30.0, 70.0], PL: [52.0, 20.0], PR: [18.25, -66.5], PS: [32.0, 35.25], PT: [39.5, -8.0],
  PW: [7.5, 134.5], PY: [-23.0, -58.0], QA: [25.5, 51.25], RE: [-21.1, 55.6], RO: [46.0, 25.0],
  RS: [44.0, 21.0], RU: [60.0, 100.0], RW: [-2.0, 30.0], SA: [25.0, 45.0], SB: [-8.0, 159.0],
  SC: [-4.58, 55.67], SD: [15.0, 30.0], SE: [62.0, 15.0], SG: [1.37, 103.8], SH: [-15.93, -5.7],
  SI: [46.0, 15.0], SK: [48.67, 19.5], SL: [8.5, -11.5], SM: [43.77, 12.42], SN: [14.0, -14.0],
  SO: [10.0, 49.0], SR: [4.0, -56.0], SS: [7.0, 30.0], ST: [1.0, 7.0], SV: [13.83, -88.92],
  SY: [35.0, 38.0], SZ: [-26.5, 31.5], TC: [21.75, -71.58], TD: [15.0, 19.0], TG: [8.0, 1.17],
  TH: [15.0, 100.0], TJ: [39.0, 71.0], TL: [-8.83, 125.92], TM: [40.0, 60.0], TN: [34.0, 9.0],
  TO: [-20.0, -175.0], TR: [39.0, 35.0], TT: [11.0, -61.0], TV: [-8.0, 178.0], TW: [23.5, 121.0],
  TZ: [-6.0, 35.0], UA: [49.0, 32.0], UG: [1.0, 32.0], US: [39.83, -98.58], UY: [-33.0, -56.0],
  UZ: [41.0, 64.0], VA: [41.9, 12.45], VC: [13.25, -61.2], VE: [8.0, -66.0], VG: [18.5, -64.5],
  VI: [18.33, -64.83], VN: [16.0, 106.0], VU: [-16.0, 167.0], WS: [-13.58, -172.33], XK: [42.58, 21.0],
  YE: [15.0, 48.0], ZA: [-29.0, 24.0], ZM: [-15.0, 30.0], ZW: [-20.0, 30.0],
};

function stableHash(input) {
  let hash = 0;
  const s = String(input || '');
  for (let i = 0; i < s.length; i += 1) hash = (hash * 31 + s.charCodeAt(i)) >>> 0;
  return hash;
}

function jitterCoord(ip, amount = 1.2) {
  const h = stableHash(ip);
  return {
    lat: (((h & 0xff) / 255) - 0.5) * amount,
    lng: ((((h >>> 8) & 0xff) / 255) - 0.5) * amount,
  };
}

function estimatedLatLngForIp(ip, country) {
  const cc = String(country || '').slice(0, 2).toUpperCase();
  if (cc && COUNTRY_CENTROIDS[cc]) {
    const [lat, lng] = COUNTRY_CENTROIDS[cc];
    const jitter = jitterCoord(ip);
    return { lat: lat + jitter.lat, lng: lng + jitter.lng, status: 'estimated_country', source: 'country_centroid' };
  }

  const h = stableHash(ip);
  return {
    lat: -55 + ((h & 0xff) / 255) * 18,
    lng: -165 + (((h >>> 8) & 0xff) / 255) * 35,
    status: 'unknown',
    source: 'unknown_cluster',
  };
}

/**
 * Globe + spreadsheet: merged traffic with IP enrichment.
 * Exact dots use IPInfo lat/lng. Country-only enrichment is shown near the
 * country centroid, and IPs with no location data are clustered as unknown.
 */
router.get('/globe-view', (req, res) => {
  try {
    const srcList = String(req.query.sources || 'honeypot,maze')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const wantHp = srcList.includes('honeypot');
    const wantMaze = srcList.includes('maze');
    const wantAccess = srcList.includes('access') || srcList.includes('access_log');
    const wantFlags = srcList.includes('ai_flags') || srcList.includes('flags');

    const rowLimit = Math.min(500, Math.max(50, parseInt(req.query.limit, 10) || 300));
    const scanCap = Math.min(6000, Math.max(400, parseInt(req.query.scan_cap, 10) || 2800));
    const minHits = Math.max(1, parseInt(req.query.min_hits, 10) || 1);

    const buildHoneypotWhere = () => {
      const parts = [];
      const params = [];
      if (req.query.since || req.query.until) {
        if (req.query.since) {
          parts.push(`hit_at >= ?`);
          params.push(`${String(req.query.since).slice(0, 10)}T00:00:00.000Z`);
        }
        if (req.query.until) {
          parts.push(`hit_at <= ?`);
          params.push(`${String(req.query.until).slice(0, 10)}T23:59:59.999Z`);
        }
      } else {
        parts.push(`hit_at > ${rangeCutoff(req, 168)}`);
      }
      if (req.query.ip) {
        parts.push(`ip = ?`);
        params.push(String(req.query.ip));
      }
      if (req.query.source) {
        parts.push(`source = ?`);
        params.push(String(req.query.source));
      }
      if (req.query.path_contains) {
        parts.push(`LOWER(IFNULL(path,'')) LIKE ?`);
        params.push(`%${String(req.query.path_contains).slice(0, 200).toLowerCase()}%`);
      }
      if (req.query.country) {
        const cc = String(req.query.country).slice(0, 2).toUpperCase();
        parts.push(
          `(json_extract(enrichment, '$.summary.country') = ? OR json_extract(enrichment, '$.ipinfo.country') = ? OR json_extract(enrichment, '$.abuseipdb.country_code') = ?)`,
        );
        params.push(cc, cc, cc);
      }
      return { wc: parts.join(' AND '), params };
    };

    const buildMazeWhere = () => {
      const parts = [`1=1`];
      const params = [];
      if (req.query.since || req.query.until) {
        if (req.query.since) {
          parts.push(`last_seen >= ?`);
          params.push(`${String(req.query.since).slice(0, 10)}T00:00:00.000Z`);
        }
        if (req.query.until) {
          parts.push(`last_seen <= ?`);
          params.push(`${String(req.query.until).slice(0, 10)}T23:59:59.999Z`);
        }
      } else {
        parts.push(`last_seen > ${rangeCutoff(req, 168)}`);
      }
      if (req.query.ip) {
        parts.push(`ip = ?`);
        params.push(String(req.query.ip));
      }
      if (req.query.self_id_only === 'true') {
        parts.push(`self_id_token IS NOT NULL`);
      }
      if (req.query.path_contains) {
        parts.push(`LOWER(IFNULL(paths_visited,'')) LIKE ?`);
        params.push(`%${String(req.query.path_contains).slice(0, 400).toLowerCase()}%`);
      }
      if (req.query.country) {
        const cc = String(req.query.country).slice(0, 2).toUpperCase();
        parts.push(
          `(json_extract(enrichment, '$.summary.country') = ? OR json_extract(enrichment, '$.ipinfo.country') = ? OR json_extract(enrichment, '$.abuseipdb.country_code') = ?)`,
        );
        params.push(cc, cc, cc);
      }
      return { wc: parts.join(' AND '), params };
    };

    /** @type {any[]} */
    const tableRows = [];
    /** @type {Map<string, { ip: string, lat: number|null, lng: number|null, weight: number, kinds: Set<string>, country: string|null, city: string|null, last_seen: string, labels: Set<string>, geo_status: string, geo_source: string }>} */
    const ipAgg = new Map();

    const bumpIp = (ip, lat, lng, weight, kind, meta = {}) => {
      if (!ip) return;
      let a = ipAgg.get(ip);
      if (!a) {
        a = {
          ip,
          lat: null,
          lng: null,
          weight: 0,
          kinds: new Set(),
          country: null,
          city: null,
          last_seen: '',
          labels: new Set(),
          geo_status: 'unknown',
          geo_source: 'unknown_cluster',
        };
        ipAgg.set(ip, a);
      }
      a.weight += weight;
      a.kinds.add(kind);
      if (lat != null && lng != null && (a.lat == null || a.lng == null)) {
        a.lat = lat;
        a.lng = lng;
        a.geo_status = 'exact';
        a.geo_source = 'ipinfo';
      }
      if (meta.country) a.country = meta.country;
      if (meta.city) a.city = meta.city;
      if (meta.geo_status && a.geo_status !== 'exact') a.geo_status = meta.geo_status;
      if (meta.geo_source && a.geo_source !== 'ipinfo') a.geo_source = meta.geo_source;
      if (meta.last_seen && String(meta.last_seen) > String(a.last_seen)) a.last_seen = meta.last_seen;
      if (meta.label) a.labels.add(meta.label);
    };

    const applyStoredEnrichment = (agg) => {
      if (!agg?.ip || agg.lat != null || agg.lng != null) return;
      const row = getOne(
        `SELECT enrichment FROM (
           SELECT enrichment, hit_at AS seen_at FROM ai_honeypot_hits
             WHERE ip = ? AND enrichment IS NOT NULL
           UNION ALL
           SELECT enrichment, last_seen AS seen_at FROM maze_hits
             WHERE ip = ? AND enrichment IS NOT NULL
           UNION ALL
           SELECT enrichment, hit_at AS seen_at FROM network_sensor_events
             WHERE peer_ip = ? AND enrichment IS NOT NULL
         ) ORDER BY seen_at DESC LIMIT 1`,
        [agg.ip, agg.ip, agg.ip],
      );
      if (!row?.enrichment) return;
      const e = jsonParseSafe(row.enrichment, null);
      const ll = latLngFromEnrichment(e);
      const cty = countryFromEnrichment(e);
      const city = e?.ipinfo?.city || null;
      if (cty && !agg.country) agg.country = cty;
      if (city && !agg.city) agg.city = city;
      if (ll) {
        agg.lat = ll.lat;
        agg.lng = ll.lng;
        agg.geo_status = 'exact';
        agg.geo_source = 'stored_ipinfo';
      }
    };

    if (wantHp) {
      const { wc, params } = buildHoneypotWhere();
      const hpRows = getAll(
        `SELECT id, hit_at, ip, path, source, ua, enrichment
         FROM ai_honeypot_hits WHERE ${wc}
         ORDER BY hit_at DESC LIMIT ?`,
        [...params, scanCap],
      );
      for (const r of hpRows) {
        const e = jsonParseSafe(r.enrichment, null);
        const ll = latLngFromEnrichment(e);
        const cty = countryFromEnrichment(e);
        const city = e?.ipinfo?.city || null;
        bumpIp(r.ip, ll?.lat, ll?.lng, 1, 'honeypot', {
          country: cty,
          city,
          last_seen: r.hit_at,
          label: r.source,
        });
        tableRows.push({
          kind: 'honeypot',
          id: r.id,
          time: r.hit_at,
          ip: r.ip,
          path: r.path,
          endpoint: r.path,
          source: r.source,
          ua: r.ua,
          weight: 1,
          country: cty,
          city,
          lat: ll?.lat ?? null,
          lng: ll?.lng ?? null,
          geo_status: ll ? 'exact' : cty ? 'estimated_country' : 'unknown',
        });
      }
    }

    if (wantMaze) {
      const { wc, params } = buildMazeWhere();
      const mzRows = getAll(
        `SELECT id, ip, ua, date, last_seen, hit_count, max_depth, paths_visited, enrichment
         FROM maze_hits WHERE ${wc}
         ORDER BY last_seen DESC LIMIT ?`,
        [...params, scanCap],
      );
      for (const r of mzRows) {
        const e = jsonParseSafe(r.enrichment, null);
        const ll = latLngFromEnrichment(e);
        const cty = countryFromEnrichment(e);
        const city = e?.ipinfo?.city || null;
        const w = Math.max(1, Number(r.hit_count) || 1);
        bumpIp(r.ip, ll?.lat, ll?.lng, w, 'maze', {
          country: cty,
          city,
          last_seen: r.last_seen,
          label: `maze ${r.date}`,
        });
        tableRows.push({
          kind: 'maze',
          id: r.id,
          time: r.last_seen,
          ip: r.ip,
          path: null,
          endpoint: `data-room · depth ${r.max_depth}`,
          source: `maze · ${r.date}`,
          maze_date: r.date,
          hit_count: r.hit_count,
          max_depth: r.max_depth,
          ua: r.ua,
          weight: w,
          country: cty,
          city,
          lat: ll?.lat ?? null,
          lng: ll?.lng ?? null,
          geo_status: ll ? 'exact' : cty ? 'estimated_country' : 'unknown',
        });
      }
    }

    if (wantAccess) {
      const clauses = [];
      const params = [];
      if (req.query.since || req.query.until) {
        if (req.query.since) {
          clauses.push(`hit_at >= ?`);
          params.push(`${String(req.query.since).slice(0, 10)}T00:00:00.000Z`);
        }
        if (req.query.until) {
          clauses.push(`hit_at <= ?`);
          params.push(`${String(req.query.until).slice(0, 10)}T23:59:59.999Z`);
        }
      } else {
        clauses.push(`hit_at > ${rangeCutoff(req, 168)}`);
      }
      if (req.query.ip) {
        clauses.push(`ip = ?`);
        params.push(String(req.query.ip));
      }
      if (req.query.path_contains) {
        clauses.push(`LOWER(IFNULL(path,'')) LIKE ?`);
        params.push(`%${String(req.query.path_contains).slice(0, 200).toLowerCase()}%`);
      }
      const wc = clauses.join(' AND ');
      const alRows = getAll(
        `SELECT id, hit_at, ip, user_agent, path, referer, token
         FROM access_log WHERE ${wc}
         ORDER BY hit_at DESC LIMIT ?`,
        [...params, scanCap],
      );
      for (const r of alRows) {
        bumpIp(r.ip, null, null, 1, 'access', {
          last_seen: r.hit_at,
          label: 'mi_access',
        });
        tableRows.push({
          kind: 'access',
          id: r.id,
          time: r.hit_at,
          ip: r.ip,
          path: r.path,
          endpoint: r.path,
          source: 'mi_access',
          ua: r.user_agent,
          weight: 1,
          country: null,
          city: null,
          lat: null,
          lng: null,
          geo_status: 'unknown',
        });
      }
    }

    if (wantFlags) {
      const parts = [`1=1`];
      const params = [];
      if (req.query.since || req.query.until) {
        if (req.query.since) {
          parts.push(`date(created_at) >= date(?)`);
          params.push(String(req.query.since).slice(0, 10));
        }
        if (req.query.until) {
          parts.push(`date(created_at) <= date(?)`);
          params.push(String(req.query.until).slice(0, 10));
        }
      } else {
        parts.push(`created_at > ${rangeCutoff(req, 168)}`);
      }
      if (req.query.ip) {
        parts.push(`ip = ?`);
        params.push(String(req.query.ip));
      }
      if (req.query.route) {
        parts.push(`route = ?`);
        params.push(String(req.query.route));
      }
      if (req.query.path_contains) {
        parts.push(`LOWER(IFNULL(path,'')) LIKE ?`);
        params.push(`%${String(req.query.path_contains).slice(0, 200).toLowerCase()}%`);
      }
      const wc = parts.join(' AND ');
      const flRows = getAll(
        `SELECT id, created_at, ip, ua, route, path, severity, action_taken
         FROM ai_input_flags WHERE ${wc}
         ORDER BY created_at DESC LIMIT ?`,
        [...params, scanCap],
      );
      for (const r of flRows) {
        bumpIp(r.ip, null, null, 1, 'ai_flag', {
          last_seen: r.created_at,
          label: r.route,
        });
        tableRows.push({
          kind: 'ai_flag',
          id: r.id,
          time: r.created_at,
          ip: r.ip,
          path: r.path,
          endpoint: r.route,
          source: r.route,
          ua: r.ua,
          weight: 1,
          country: null,
          city: null,
          lat: null,
          lng: null,
          geo_status: 'unknown',
          severity: r.severity,
          action: r.action_taken,
        });
      }
    }

    tableRows.sort((a, b) => String(b.time || '').localeCompare(String(a.time || '')));
    const rows = tableRows.slice(0, rowLimit);

    for (const p of ipAgg.values()) {
      applyStoredEnrichment(p);
      if (p.lat != null && p.lng != null) continue;
      const estimated = estimatedLatLngForIp(p.ip, p.country);
      p.lat = estimated.lat;
      p.lng = estimated.lng;
      p.geo_status = estimated.status;
      p.geo_source = estimated.source;
    }

    let points = [...ipAgg.values()]
      .filter((p) => p.weight >= minHits)
      .map((p) => ({
        ip: p.ip,
        lat: p.lat,
        lng: p.lng,
        weight: p.weight,
        country: p.country,
        city: p.city,
        last_seen: p.last_seen || null,
        kinds: [...p.kinds],
        labels: [...p.labels].slice(0, 8),
        geo_status: p.geo_status,
        geo_source: p.geo_source,
      }));
    points.sort((a, b) => b.weight - a.weight);
    if (points.length > 500) points = points.slice(0, 500);

    res.json({
      points,
      rows,
      meta: {
        row_limit: rowLimit,
        scan_cap: scanCap,
        table_total_before_limit: tableRows.length,
        points_count: points.length,
        exact_points: points.filter((p) => p.geo_status === 'exact').length,
        estimated_points: points.filter((p) => p.geo_status === 'estimated_country').length,
        unknown_points: points.filter((p) => p.geo_status === 'unknown').length,
        note:
          'Exact markers use IPInfo coordinates. Country-only enrichment uses country centroids; IPs without location data are shown in a separate unknown cluster.',
      },
    });
  } catch (e) {
    res.status(500).json({ error: e?.message || 'globe_view_error' });
  }
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

// ─── Cowrie / network_sensor events ─────────────────────────────────────────
router.get('/network-sensor/stats', (_req, res) => {
  const since24 = sqlHoursAgo(24);
  const since168 = sqlHoursAgo(24 * 7);
  const totals = getOne(`
    SELECT
      (SELECT COUNT(*) FROM network_sensor_events) AS events_all,
      (SELECT COUNT(*) FROM network_sensor_events WHERE hit_at > ${since24}) AS events_24h,
      (SELECT COUNT(*) FROM network_sensor_events WHERE hit_at > ${since168}) AS events_7d,
      (SELECT COUNT(DISTINCT peer_ip) FROM network_sensor_events WHERE peer_ip IS NOT NULL AND hit_at > ${since24}) AS distinct_ips_24h,
      (SELECT COUNT(DISTINCT peer_ip) FROM network_sensor_events WHERE peer_ip IS NOT NULL) AS distinct_ips_all
  `);
  const by_protocol = getAll(`
    SELECT protocol, COUNT(*) AS hits FROM network_sensor_events
    WHERE hit_at > ${since168} AND protocol IS NOT NULL AND protocol <> ''
    GROUP BY protocol ORDER BY hits DESC LIMIT 20
  `).map((r) => ({ ...r, hits: Number(r.hits) }));
  const by_event = getAll(`
    SELECT event_type, COUNT(*) AS hits FROM network_sensor_events
    WHERE hit_at > ${since168}
    GROUP BY event_type ORDER BY hits DESC LIMIT 25
  `).map((r) => ({ ...r, hits: Number(r.hits) }));
  res.json({
    totals: {
      events_all: Number(totals?.events_all || 0),
      events_24h: Number(totals?.events_24h || 0),
      events_7d: Number(totals?.events_7d || 0),
      distinct_ips_24h: Number(totals?.distinct_ips_24h || 0),
      distinct_ips_all: Number(totals?.distinct_ips_all || 0),
    },
    by_protocol,
    by_event,
  });
});

router.get('/network-sensor', (req, res) => {
  const format = String(req.query.format || '');
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
    return finishNetworkSensor(req, res, clauses.join(' AND '), sp, format);
  }
  return finishNetworkSensor(req, res, `hit_at > ${rangeCutoff(req, 24)}`, [], format);
});

function finishNetworkSensor(req, res, hitClause, baseParams = [], format = '') {
  const { limit, offset } = parsePage(req);
  const where = [hitClause];
  const params = [...baseParams];
  if (req.query.protocol) {
    where.push(`protocol = ?`);
    params.push(String(req.query.protocol).slice(0, 32));
  }
  if (req.query.event_type) {
    where.push(`event_type LIKE ?`);
    params.push(`%${String(req.query.event_type).slice(0, 200)}%`);
  }
  if (req.query.ip) {
    where.push(`peer_ip = ?`);
    params.push(String(req.query.ip).slice(0, 128));
  }
  if (req.query.session_id) {
    where.push(`session_id = ?`);
    params.push(String(req.query.session_id).slice(0, 128));
  }
  const wc = where.join(' AND ');
  const rows = getAll(
    `SELECT id, hit_at, peer_ip, session_id, sensor_name, protocol, event_type,
            cowrie_eventid, payload_json, enrichment
     FROM network_sensor_events
     WHERE ${wc}
     ORDER BY hit_at DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset],
  ).map((r) => ({
    ...r,
    enrichment: jsonParseSafe(r.enrichment, null),
    payload_json: jsonParseSafe(r.payload_json, null),
  }));
  const total = Number(getOne(`SELECT COUNT(*) AS n FROM network_sensor_events WHERE ${wc}`, params)?.n || 0);
  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="network-sensor-events.csv"');
    return res.send(rowsToCsv(rows));
  }
  if (format === 'json') {
    res.setHeader('Content-Disposition', 'attachment; filename="network-sensor-events.json"');
    return res.json(rows);
  }
  res.json({ rows, total, totalCount: total, limit, offset });
}

router.get('/network-sensor/session/:sessionId', (req, res) => {
  const sid = String(req.params.sessionId || '').slice(0, 128);
  if (!sid) return res.status(400).json({ error: 'session_id required' });
  const rows = getAll(
    `SELECT id, hit_at, peer_ip, session_id, sensor_name, protocol, event_type,
            cowrie_eventid, payload_json, enrichment
     FROM network_sensor_events WHERE session_id = ?
     ORDER BY hit_at ASC LIMIT 500`,
    [sid],
  ).map((r) => ({
    ...r,
    enrichment: jsonParseSafe(r.enrichment, null),
    payload_json: jsonParseSafe(r.payload_json, null),
  }));
  res.json({ session_id: sid, rows, count: rows.length });
});

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

router.get('/fake-data/actions', (req, res) => {
  const { limit, offset } = parsePage(req);
  const { where, params } = decoyEventWhere(req);
  const clauses = [`source = 'fake_data'`, where];
  const rows = getAll(
    `SELECT * FROM decoy_access_events
     WHERE ${clauses.join(' AND ')}
     ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset],
  ).map(normalizeDecoyEventRow);
  const total = Number(
    getOne(`SELECT COUNT(*) AS n FROM decoy_access_events WHERE ${clauses.join(' AND ')}`, params)
      ?.n || 0,
  );
  res.json({ rows, total, totalCount: total, limit, offset });
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

// ─── Unified raw request/event stream ────────────────────────────────────────
router.get('/requests', (req, res) => {
  const { limit, offset } = parsePage(req);
  const { where, params } = decoyEventWhere(req);
  const order = decoyEventOrder(req);
  const rows = getAll(
    `SELECT * FROM decoy_access_events
     WHERE ${where}
     ORDER BY ${order}
     LIMIT ? OFFSET ?`,
    [...params, limit, offset],
  ).map(normalizeDecoyEventRow);
  const total = Number(getOne(`SELECT COUNT(*) AS n FROM decoy_access_events WHERE ${where}`, params)?.n || 0);
  res.json({ rows, total, totalCount: total, limit, offset });
});

router.get('/abuse-logs', (req, res) => {
  const { limit, offset } = parsePage(req);
  const { where, params } = decoyEventWhere(req, { suspiciousOnly: true });
  const order = decoyEventOrder(req);
  const rows = getAll(
    `SELECT * FROM decoy_access_events
     WHERE ${where}
     ORDER BY ${order}
     LIMIT ? OFFSET ?`,
    [...params, limit, offset],
  ).map(normalizeDecoyEventRow);
  const total = Number(getOne(`SELECT COUNT(*) AS n FROM decoy_access_events WHERE ${where}`, params)?.n || 0);
  res.json({ rows, total, totalCount: total, limit, offset });
});

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
         SELECT ip, date(hit_at) AS day, 1 AS hits, hit_at AS last_seen, enrichment FROM access_log WHERE ip IS NOT NULL AND hit_at > ${cutoff}
         UNION ALL
         SELECT ip, date(hit_at) AS day, 1 AS hits, hit_at AS last_seen, enrichment FROM ai_honeypot_hits WHERE ip IS NOT NULL AND hit_at > ${cutoff}
         UNION ALL
         SELECT peer_ip AS ip, date(hit_at) AS day, 1 AS hits, hit_at AS last_seen, enrichment FROM network_sensor_events WHERE peer_ip IS NOT NULL AND hit_at > ${cutoff}
       ) GROUP BY ip HAVING COUNT(DISTINCT day) >= 5
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
        SELECT ip, enrichment, hit_at AS last_seen, 'access_log' AS source FROM access_log
          WHERE ip IS NOT NULL AND enrichment IS NOT NULL AND hit_at > ${cutoff}
        UNION ALL
        SELECT ip, enrichment, hit_at AS last_seen, 'ai_honeypot' AS source FROM ai_honeypot_hits
          WHERE ip IS NOT NULL AND enrichment IS NOT NULL AND hit_at > ${cutoff}
        UNION ALL
        SELECT peer_ip AS ip, enrichment, hit_at AS last_seen, 'network_sensor' FROM network_sensor_events
          WHERE peer_ip IS NOT NULL AND enrichment IS NOT NULL AND hit_at > ${cutoff}
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
      UNION SELECT ip FROM access_log WHERE ip IS NOT NULL
      UNION SELECT peer_ip AS ip FROM network_sensor_events WHERE peer_ip IS NOT NULL`);
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
        ) ||
        getOne(
          `SELECT enrichment, hit_at AS last_seen FROM network_sensor_events WHERE peer_ip = ? ORDER BY hit_at DESC LIMIT 1`,
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
    { source: 'pharma_trials_export', path: 'GET /api/secrets/fake-data/pharma-trials.csv' },
    { source: 'password_dump', path: 'GET /api/secrets/fake-data/passwords.csv' },
    { source: 'database_backup', path: 'GET /api/secrets/fake-data/database-export.sql' },
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

  const netTotal = getOne(
    `SELECT COUNT(*) AS hits, MAX(hit_at) AS last_hit FROM network_sensor_events`,
  );
  rows.push({
    source: 'cowrie_network_sensor',
    path:
      'TCP Cowrie (SSH default :2222, Telnet :2223 — enabled by default via INFINI_NETWORK_HONEYPOT_ENABLED=1)',
    hits: Number(netTotal?.hits || 0),
    last_hit: netTotal?.last_hit || null,
  });

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

const VALID_SOURCES = new Set(['ai_flags', 'access_log', 'honeypot', 'maze', 'network_sensor']);
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
    } else if (source === 'network_sensor') {
      rows = getAll(
        `SELECT hit_at, peer_ip, protocol, event_type, session_id, cowrie_eventid
         FROM network_sensor_events
         WHERE hit_at > strftime('%Y-%m-%dT%H:%M:%fZ','now','-${hours} hours')
         ORDER BY hit_at DESC LIMIT 500`,
      );
    } else {
      return res.status(400).json({ error: 'invalid_source' });
    }

    await sendShare({
      channel,
      recipient,
      subject: subject || `Infini · ${source} (${hours}h)`,
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
