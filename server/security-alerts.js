/**
 * server/security-alerts.js
 *
 * Security alert rules engine. Admins define rules in `security_alert_rules`
 * (predicate JSON + channel + recipient + cooldown). A 1-minute scheduler
 * tick calls `runAlerts()` which:
 *   1. Reads enabled rules.
 *   2. For each rule whose cooldown has elapsed, evaluates the predicate
 *      against sources: `ai_flags`, `access_log`, `honeypot`, `maze`, `network_sensor`.
 *   3. If the predicate fires, dispatches via the rule's channel (email,
 *      discord, telegram, webhook) and records the delivery + audit row.
 *
 * Sources updated for Infini: `access_log` replaces legacy `mi_access`
 * (renamed table), `maze` added so admins can alert on data-room surges. All
 * dispatched payloads truncate strings to 500 chars to avoid PII leakage.
 */

import { getAll, getOne, run } from './db.js';
import { getServiceCredentials } from './integrations.js';
import { audit } from './audit.js';

// ─── Predicate evaluation ───────────────────────────────────────────────────
function timeCutoffSql(windowMin) {
  const n = Math.max(1, Math.min(60 * 24 * 30, Number(windowMin) || 60));
  return `strftime('%Y-%m-%dT%H:%M:%fZ','now','-${n} minutes')`;
}

/** Alerts UI historically used `mi_access`; stored as `access_log`. */
function normalizeAlertSource(source) {
  return source === 'mi_access' ? 'access_log' : source;
}

function evaluatePredicate(source, predicate = {}) {
  source = normalizeAlertSource(source);
  const windowMin = Number(predicate.window_min || 60);
  const threshold = Number(predicate.count || 1);
  const cutoff = timeCutoffSql(windowMin);
  let sql = '';
  const params = [];

  if (source === 'ai_flags') {
    const clauses = [`created_at > ${cutoff}`];
    if (predicate.severity) {
      clauses.push(`severity = ?`);
      params.push(predicate.severity);
    }
    if (predicate.channel) {
      clauses.push(`channel = ?`);
      params.push(predicate.channel);
    }
    if (predicate.action_taken) {
      clauses.push(`action_taken = ?`);
      params.push(predicate.action_taken);
    }
    sql = `SELECT COUNT(*) AS n FROM ai_input_flags WHERE ${clauses.join(' AND ')}`;
  } else if (source === 'access_log') {
    const clauses = [`hit_at > ${cutoff}`];
    if (predicate.token_null === true) clauses.push(`token IS NULL`);
    if (predicate.ip) {
      clauses.push(`ip = ?`);
      params.push(predicate.ip);
    }
    sql = `SELECT COUNT(*) AS n FROM access_log WHERE ${clauses.join(' AND ')}`;
  } else if (source === 'honeypot') {
    const clauses = [`hit_at > ${cutoff}`];
    if (predicate.source_type) {
      clauses.push(`source = ?`);
      params.push(predicate.source_type);
    }
    if (predicate.ip) {
      clauses.push(`ip = ?`);
      params.push(predicate.ip);
    }
    sql = `SELECT COUNT(*) AS n FROM ai_honeypot_hits WHERE ${clauses.join(' AND ')}`;
  } else if (source === 'network_sensor') {
    const clauses = [`hit_at > ${cutoff}`];
    if (predicate.event_type) {
      clauses.push(`event_type LIKE ?`);
      params.push(`%${String(predicate.event_type).slice(0, 200)}%`);
    }
    if (predicate.protocol) {
      clauses.push(`protocol = ?`);
      params.push(String(predicate.protocol).slice(0, 32));
    }
    if (predicate.ip) {
      clauses.push(`peer_ip = ?`);
      params.push(String(predicate.ip).slice(0, 128));
    }
    sql = `SELECT COUNT(*) AS n FROM network_sensor_events WHERE ${clauses.join(' AND ')}`;
  } else if (source === 'maze') {
    const clauses = [`last_seen > ${cutoff}`];
    if (predicate.ip) {
      clauses.push(`ip = ?`);
      params.push(predicate.ip);
    }
    // maze rows are aggregated; we measure total hit_count, not row count
    sql = `SELECT COALESCE(SUM(hit_count),0) AS n FROM maze_hits WHERE ${clauses.join(' AND ')}`;
  } else {
    return false;
  }

  const row = getOne(sql, params);
  return Number(row?.n || 0) >= threshold;
}

function buildExcerpt(source, predicate = {}) {
  source = normalizeAlertSource(source);
  const windowMin = Number(predicate.window_min || 60);
  const cutoff = timeCutoffSql(windowMin);
  let sql = '';
  const params = [];

  if (source === 'ai_flags') {
    const clauses = [`created_at > ${cutoff}`];
    if (predicate.severity) {
      clauses.push(`severity = ?`);
      params.push(predicate.severity);
    }
    sql = `SELECT severity, action_taken, username, ip, input_excerpt, created_at
           FROM ai_input_flags WHERE ${clauses.join(' AND ')}
           ORDER BY created_at DESC LIMIT 5`;
  } else if (source === 'access_log') {
    const clauses = [`hit_at > ${cutoff}`];
    if (predicate.token_null === true) clauses.push(`token IS NULL`);
    sql = `SELECT ip, user_agent, referer, hit_at, path
           FROM access_log WHERE ${clauses.join(' AND ')}
           ORDER BY hit_at DESC LIMIT 5`;
  } else if (source === 'honeypot') {
    const clauses = [`hit_at > ${cutoff}`];
    if (predicate.source_type) {
      clauses.push(`source = ?`);
      params.push(predicate.source_type);
    }
    sql = `SELECT source, ip, ua, path, hit_at
           FROM ai_honeypot_hits WHERE ${clauses.join(' AND ')}
           ORDER BY hit_at DESC LIMIT 5`;
  } else if (source === 'network_sensor') {
    const clauses = [`hit_at > ${cutoff}`];
    if (predicate.event_type) {
      clauses.push(`event_type LIKE ?`);
      params.push(`%${String(predicate.event_type).slice(0, 200)}%`);
    }
    if (predicate.protocol) {
      clauses.push(`protocol = ?`);
      params.push(String(predicate.protocol).slice(0, 32));
    }
    if (predicate.ip) {
      clauses.push(`peer_ip = ?`);
      params.push(String(predicate.ip).slice(0, 128));
    }
    sql = `SELECT peer_ip, protocol, event_type, session_id, hit_at
           FROM network_sensor_events WHERE ${clauses.join(' AND ')}
           ORDER BY hit_at DESC LIMIT 5`;
  } else if (source === 'maze') {
    const clauses = [`last_seen > ${cutoff}`];
    sql = `SELECT ip, ua, hit_count, max_depth, last_seen
           FROM maze_hits WHERE ${clauses.join(' AND ')}
           ORDER BY last_seen DESC LIMIT 5`;
  } else {
    return [];
  }

  return getAll(sql, params).map((r) => {
    const safe = {};
    for (const [k, v] of Object.entries(r)) safe[k] = typeof v === 'string' ? v.slice(0, 500) : v;
    return safe;
  });
}

// ─── Outbound dispatch ──────────────────────────────────────────────────────
async function dispatch(channel, recipient, rule, excerpt) {
  const title = `[Security Alert] ${rule.name}`;
  const lines = [
    `Rule: ${rule.name}`,
    `Source: ${rule.source}`,
    `Fired at: ${new Date().toISOString()}`,
    '',
    'Recent rows (up to 5):',
    ...excerpt.map((r, i) => `  ${i + 1}. ${JSON.stringify(r).slice(0, 500)}`),
  ];
  const body = lines.join('\n');

  if (channel === 'email') {
    const creds = getServiceCredentials('smtp');
    if (!creds?.host) throw new Error('smtp_not_configured');
    const nodemailer = await import('nodemailer');
    const transport = nodemailer.default.createTransport({
      host: creds.host,
      port: Number(creds.port) || 587,
      secure: Boolean(creds.secure),
      auth: { user: creds.user, pass: creds.pass },
    });
    await transport.sendMail({
      from: `"${creds.from_name || 'Infini Security'}" <${creds.from_address || creds.user}>`,
      to: recipient,
      subject: title,
      text: body,
      html: `<pre style="font-family:monospace;font-size:13px">${body.replace(/</g, '&lt;')}</pre>`,
    });
    transport.close();
    return;
  }

  if (channel === 'discord') {
    const creds = getServiceCredentials('discord');
    if (!creds?.webhook_url) throw new Error('discord_not_configured');
    const r = await fetch(creds.webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: `**${title}**\n\`\`\`\n${body.slice(0, 1800)}\n\`\`\``,
      }),
    });
    if (!r.ok && r.status !== 204) throw new Error(`discord_${r.status}`);
    return;
  }

  if (channel === 'telegram') {
    const creds = getServiceCredentials('telegram');
    if (!creds?.bot_token || !creds?.channel_id) throw new Error('telegram_not_configured');
    const chatId = recipient || creds.channel_id;
    const r = await fetch(`https://api.telegram.org/bot${creds.bot_token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text: `${title}\n\n${body}`.slice(0, 4096),
      }),
    });
    if (!r.ok) throw new Error(`telegram_${r.status}`);
    return;
  }

  if (channel === 'webhook') {
    const creds = getServiceCredentials('webhook');
    const url = recipient.startsWith('http') ? recipient : creds?.url;
    if (!url) throw new Error('webhook_not_configured');
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        alert: rule.name,
        source: rule.source,
        fired_at: new Date().toISOString(),
        excerpt,
      }),
    });
    if (!r.ok) throw new Error(`webhook_${r.status}`);
    return;
  }

  throw new Error(`unknown_channel_${channel}`);
}

// ─── Scheduler entry point ──────────────────────────────────────────────────
let _running = false;

export async function runAlerts() {
  if (_running) return; // never overlap
  _running = true;
  try {
    const rules = getAll(`SELECT * FROM security_alert_rules WHERE enabled = 1 ORDER BY id`);
    for (const rule of rules) {
      try {
        if (rule.last_fired_at) {
          const elapsedMin = (Date.now() - new Date(rule.last_fired_at).getTime()) / 60_000;
          if (elapsedMin < (rule.cooldown_min ?? 5)) continue;
        }
        const predicate = JSON.parse(rule.predicate || '{}');
        const src = normalizeAlertSource(rule.source);
        const fired = evaluatePredicate(src, predicate);
        if (!fired) continue;

        const excerpt = buildExcerpt(src, predicate);
        let ok = false;
        let errMsg = null;
        try {
          await dispatch(rule.channel, rule.recipient, rule, excerpt);
          ok = true;
        } catch (err) {
          errMsg = String(err?.message || err).slice(0, 500);
           
          console.error(`[security-alerts] dispatch failed for "${rule.name}":`, errMsg);
        }

        run(
          `INSERT INTO security_alert_deliveries (rule_id, payload_excerpt, ok, error)
           VALUES (?, ?, ?, ?)`,
          [rule.id, JSON.stringify({ excerpt_count: excerpt.length }), ok ? 1 : 0, errMsg],
        );
        run(
          `UPDATE security_alert_rules SET last_fired_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`,
          [rule.id],
        );
        audit({
          actionType: 'security_alert_fired',
          actorUsername: 'security_alerts',
          targetType: 'security_alert_rule',
          targetId: String(rule.id),
          payload: {
            rule_name: rule.name,
            source: rule.source,
            channel: rule.channel,
            ok,
            error: errMsg,
          },
          ip: 'system',
        });
         
        console.log(
          `[security-alerts] rule "${rule.name}" fired → channel=${rule.channel}, ok=${ok}`,
        );
      } catch (err) {
         
        console.error(`[security-alerts] error evaluating rule ${rule.id}:`, err?.message);
      }
    }
  } finally {
    _running = false;
  }
}

/**
 * Start a 1-minute periodic scheduler. Idempotent — calling twice still runs once/min.
 * Returns a `stop()` fn.
 */
export function startAlertsScheduler({ intervalMs = 60_000 } = {}) {
  // run once shortly after boot, then on interval
  const initial = setTimeout(() => {
    runAlerts().catch(() => {});
  }, 5000);
  initial.unref();
  const handle = setInterval(() => {
    runAlerts().catch(() => {});
  }, intervalMs);
  handle.unref();
  return () => {
    clearTimeout(initial);
    clearInterval(handle);
  };
}

// ─── On-demand share helper used by /api/admin/security/share ───────────────
export async function sendShare({ channel, recipient, subject, rows, format }) {
  const title = subject || 'Security Report';

  const safeRows = (rows || []).map((r) => {
    const o = {};
    for (const [k, v] of Object.entries(r)) o[k] = typeof v === 'string' ? v.slice(0, 500) : v;
    return o;
  });

  if (channel === 'email') {
    const creds = getServiceCredentials('smtp');
    if (!creds?.host) throw new Error('smtp_not_configured');
    const nodemailer = await import('nodemailer');
    const transport = nodemailer.default.createTransport({
      host: creds.host,
      port: Number(creds.port) || 587,
      secure: Boolean(creds.secure),
      auth: { user: creds.user, pass: creds.pass },
    });
    const attachments = [];
    let textBody = '';
    if (format === 'csv') {
      const csv = buildCsv(safeRows);
      attachments.push({ filename: 'report.csv', content: csv, contentType: 'text/csv' });
      textBody = `See attached CSV (${safeRows.length} rows).`;
    } else if (format === 'json') {
      attachments.push({
        filename: 'report.json',
        content: JSON.stringify(safeRows, null, 2),
        contentType: 'application/json',
      });
      textBody = `See attached JSON (${safeRows.length} rows).`;
    } else {
      textBody = buildSummaryText(safeRows, title);
    }
    await transport.sendMail({
      from: `"${creds.from_name || 'Infini Security'}" <${creds.from_address || creds.user}>`,
      to: recipient,
      subject: title,
      text: textBody,
      attachments,
    });
    transport.close();
    return;
  }

  if (channel === 'discord') {
    const creds = getServiceCredentials('discord');
    if (!creds?.webhook_url) throw new Error('discord_not_configured');
    const snippet =
      format === 'summary' ? buildSummaryText(safeRows, title) : `${safeRows.length} rows exported.`;
    const r = await fetch(creds.webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: `**${title}**\n\`\`\`\n${snippet.slice(0, 1800)}\n\`\`\``,
      }),
    });
    if (!r.ok && r.status !== 204) throw new Error(`discord_${r.status}`);
    return;
  }

  if (channel === 'telegram') {
    const creds = getServiceCredentials('telegram');
    if (!creds?.bot_token || !creds?.channel_id) throw new Error('telegram_not_configured');
    const chatId = recipient || creds.channel_id;
    const snippet =
      format === 'summary' ? buildSummaryText(safeRows, title) : `${safeRows.length} rows exported.`;
    const r = await fetch(`https://api.telegram.org/bot${creds.bot_token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text: `${title}\n\n${snippet}`.slice(0, 4096),
      }),
    });
    if (!r.ok) throw new Error(`telegram_${r.status}`);
    return;
  }

  if (channel === 'webhook') {
    const creds = getServiceCredentials('webhook');
    const url = recipient?.startsWith('http') ? recipient : creds?.url;
    if (!url) throw new Error('webhook_not_configured');
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subject: title, rows: safeRows }),
    });
    if (!r.ok) throw new Error(`webhook_${r.status}`);
    return;
  }

  throw new Error(`unknown_channel_${channel}`);
}

// ─── CSV / summary helpers ──────────────────────────────────────────────────
function csvEscapeVal(val) {
  const s = String(val ?? '').replace(/"/g, '""');
  return /[",\n\r]/.test(s) ? `"${s}"` : s;
}
function buildCsv(rows) {
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
function buildSummaryText(rows, title) {
  return `${title}\n${new Date().toISOString()}\nTotal rows: ${rows.length}\n\nFirst 10:\n${rows
    .slice(0, 10)
    .map((r, i) => `${i + 1}. ${JSON.stringify(r).slice(0, 500)}`)
    .join('\n')}`;
}
