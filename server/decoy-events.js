import { createHash } from 'node:crypto';
import { run } from './db.js';
import { enrichIp } from './ip-enrichment.js';

const SAFE_HEADERS = [
  'accept',
  'accept-language',
  'accept-encoding',
  'content-type',
  'origin',
  'referer',
  'x-requested-with',
  'x-forwarded-for',
  'sec-ch-ua',
  'sec-ch-ua-platform',
  'sec-fetch-mode',
  'sec-fetch-dest',
];

const DEFAULT_SUSPICIOUS_REASONS = {
  honeypot: ['http_decoy_hit'],
  fake_data: ['fake_data_access'],
  protocol: ['protocol_decoy_event'],
};

function clientIp(req) {
  const fwd = req.headers?.['x-forwarded-for'];
  if (fwd) {
    const first = String(fwd).split(',')[0].trim();
    if (first) return first;
  }
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function safeJson(value, fallback = null) {
  try {
    return JSON.stringify(value ?? fallback);
  } catch {
    return JSON.stringify(fallback);
  }
}

function summarizeBody(req) {
  const rawBody = req.body;
  let bodyText = '';
  if (rawBody && typeof rawBody === 'object' && Object.keys(rawBody).length > 0) {
    bodyText = JSON.stringify(rawBody);
  } else if (typeof rawBody === 'string' && rawBody.length > 0) {
    bodyText = rawBody;
  }
  return {
    body_hash: bodyText ? createHash('sha256').update(bodyText).digest('hex').slice(0, 16) : null,
    body_excerpt: bodyText ? bodyText.slice(0, 1000) : null,
    payload_size: bodyText.length || 0,
  };
}

function headerExcerpt(req) {
  const headers = {};
  for (const h of SAFE_HEADERS) {
    if (req.headers?.[h]) headers[h] = String(req.headers[h]).slice(0, 256);
  }
  return headers;
}

function severityFor({ source, action, body_excerpt }) {
  if (action === 'download_attempt' || action === 'submit_token' || action === 'identify_self') return 'high';
  if (source === 'protocol') return 'medium';
  if (body_excerpt) return 'medium';
  return 'low';
}

export function recordDecoyRequest(req, opts = {}) {
  const source = opts.source || 'honeypot';
  const decoyType = opts.decoy_type || (source === 'fake_data' ? 'maze' : 'api');
  const action = opts.action || (String(req.method || 'GET').toUpperCase() === 'POST' ? 'submit' : 'view');
  const ip = opts.ip || clientIp(req);
  const ua = String(opts.user_agent || req.headers?.['user-agent'] || '').slice(0, 512) || null;
  const path = String(opts.path || req.originalUrl || req.url || '').slice(0, 512);
  const { body_hash, body_excerpt, payload_size } = summarizeBody(req);
  const severity = opts.severity || severityFor({ source, action, body_excerpt });
  const reasons = opts.reasons || DEFAULT_SUSPICIOUS_REASONS[source] || ['decoy_interaction'];

  let rowId = null;
  try {
    const result = run(
      `INSERT INTO decoy_access_events
         (source, decoy_id, decoy_type, action, severity, reasons, suspicious,
          ip, user_agent, referer, method, protocol, event_type, path, query,
          token, session_key, body_hash, body_excerpt, headers_excerpt, payload_json, payload_size)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        source,
        String(opts.decoy_id || 'unknown').slice(0, 128),
        String(decoyType).slice(0, 64),
        String(action).slice(0, 64),
        severity,
        safeJson(reasons, []),
        opts.suspicious === false ? 0 : 1,
        ip,
        ua,
        String(opts.referer || req.headers?.referer || req.headers?.referrer || '').slice(0, 512) || null,
        String(opts.method || req.method || 'GET').toUpperCase().slice(0, 16),
        opts.protocol ? String(opts.protocol).slice(0, 32) : null,
        opts.event_type ? String(opts.event_type).slice(0, 256) : null,
        path,
        safeJson(opts.query || req.query || {}, {}),
        String(opts.token || req.query?.token || '').slice(0, 128) || null,
        opts.session_key ? String(opts.session_key).slice(0, 128) : null,
        opts.body_hash || body_hash,
        opts.body_excerpt || body_excerpt,
        safeJson(opts.headers_excerpt || headerExcerpt(req), {}),
        opts.payload_json ? String(opts.payload_json).slice(0, 500_000) : null,
        Number(opts.payload_size ?? payload_size) || 0,
      ],
    );
    rowId = Number(result.lastInsertRowid);
  } catch (err) {
    console.warn('[decoy-events] insert failed:', err?.message || err);
  }

  if (opts.enrich !== false && rowId && ip && ip !== 'unknown') {
    enrichIp(ip)
      .then((info) => {
        if (!info) return;
        try {
          run(`UPDATE decoy_access_events SET enrichment = ? WHERE id = ?`, [
            JSON.stringify(info),
            rowId,
          ]);
        } catch {
          /* ignore */
        }
      })
      .catch(() => {});
  }

  return rowId;
}

export function recordProtocolDecoyEvent({
  hit_at,
  peer_ip,
  session_id,
  sensor_name,
  protocol,
  event_type,
  cowrie_eventid,
  payload_json,
}) {
  const lowerType = String(event_type || '').toLowerCase();
  const isHigh =
    lowerType.includes('login') ||
    lowerType.includes('command') ||
    lowerType.includes('input') ||
    lowerType.includes('download');
  let rowId = null;
  try {
    const result = run(
      `INSERT INTO decoy_access_events
         (created_at, source, decoy_id, decoy_type, action, severity, reasons, suspicious,
          ip, user_agent, method, protocol, event_type, path, session_key, payload_json, payload_size)
       VALUES (?, 'protocol', ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        hit_at,
        `${protocol || 'protocol'}_decoy`,
        protocol || 'protocol',
        isHigh ? 'submit' : 'protocol_event',
        isHigh ? 'medium' : 'low',
        safeJson(['protocol_decoy_event', event_type].filter(Boolean), []),
        peer_ip,
        sensor_name || null,
        null,
        protocol || null,
        event_type || null,
        cowrie_eventid || null,
        session_id || null,
        String(payload_json || '').slice(0, 500_000),
        String(payload_json || '').length,
      ],
    );
    rowId = Number(result.lastInsertRowid);
  } catch (err) {
    console.warn('[decoy-events] protocol insert failed:', err?.message || err);
  }
  return rowId;
}

export function recordSubmittedInputAbuse({ route, channel, path, ip, ua, severity, reasons, input, actionTaken }) {
  try {
    run(
      `INSERT INTO decoy_access_events
         (source, decoy_id, decoy_type, action, severity, reasons, suspicious,
          ip, user_agent, path, body_hash, body_excerpt, payload_size)
       VALUES ('submitted_input', ?, 'form', ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)`,
      [
        String(channel || route || 'submitted_input').slice(0, 128),
        actionTaken || 'logged',
        severity || 'low',
        safeJson(reasons || [], []),
        ip || null,
        ua ? String(ua).slice(0, 512) : null,
        path ? String(path).slice(0, 512) : null,
        input ? createHash('sha256').update(String(input)).digest('hex').slice(0, 16) : null,
        input ? String(input).slice(0, 1000) : null,
        input ? String(input).length : 0,
      ],
    );
  } catch (err) {
    console.warn('[decoy-events] submitted input insert failed:', err?.message || err);
  }
}
