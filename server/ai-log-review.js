/**
 * AI Log Review — OpenAI-compat (xAI) with server-side injection guard + persistence.
 */

import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import OpenAI from 'openai';

import { getServiceCredentials } from './integrations.js';
import { evaluate, INJECTION_DEFENSE_MSG } from './ai-input-guard.js';
import { getRequestIp } from './audit.js';
import { auditReq } from './audit.js';
import { requireAdmin } from './auth.js';
import { getAll, run } from './db.js';

function inPlaceholders(vals) {
  return vals.map(() => '?').join(',');
}

function gatherContext(selection) {
  const lines = [];
  const summaryKeys = [];

  const hpIds = Array.isArray(selection?.honeypot_ids)
    ? selection.honeypot_ids.map(Number).filter(Number.isFinite)
    : [];
  if (hpIds.length) {
    summaryKeys.push(`monitored_endpoint_ids:${hpIds.length}`);
    const ph = inPlaceholders(hpIds);
    const rows = getAll(
      `SELECT id, hit_at, ip, ua, referer, path, method, source, body_excerpt, enrichment
         FROM ai_honeypot_hits WHERE id IN (${ph}) ORDER BY id DESC`,
      hpIds,
    );
    lines.push('# Monitored endpoint hits');
    for (const r of rows) lines.push(JSON.stringify({ table: 'ai_honeypot_hits', ...r }));
  }

  const mzPairs = [];
  if (selection?.maze_days && typeof selection.maze_days === 'object') {
    for (const ip of Object.keys(selection.maze_days)) {
      const day = selection.maze_days[ip];
      if (day != null && String(day))
        mzPairs.push({ ip: String(ip).slice(0, 128), date: String(day).slice(0, 32) });
    }
  }
  if (mzPairs.length) {
    summaryKeys.push(`maze_days:${mzPairs.length}`);
    lines.push('\n# Maze aggregates');
    for (const p of mzPairs.slice(0, 50)) {
      const row = getAll(
        `SELECT * FROM maze_hits WHERE ip = ? AND date = ?
          ORDER BY datetime(last_seen) DESC LIMIT 1`,
        [p.ip, p.date],
      );
      if (row[0]) lines.push(JSON.stringify({ table: 'maze_hits', ...row[0] }));
    }
  }

  const accIds = Array.isArray(selection?.access_ids)
    ? selection.access_ids.map(Number).filter(Number.isFinite)
    : [];
  if (accIds.length) {
    summaryKeys.push(`access_ids:${accIds.length}`);
    const ph = inPlaceholders(accIds);
    const rows = getAll(
      `SELECT id, hit_at, ip, user_agent, referer, token, path
         FROM access_log WHERE id IN (${ph}) ORDER BY id DESC`,
      accIds,
    );
    lines.push('\n# Access log');
    for (const r of rows) lines.push(JSON.stringify({ table: 'access_log', ...r }));
  }

  const flagIds = Array.isArray(selection?.ai_flag_ids)
    ? selection.ai_flag_ids.map(Number).filter(Number.isFinite)
    : [];
  if (flagIds.length) {
    summaryKeys.push(`ai_flag_ids:${flagIds.length}`);
    const ph = inPlaceholders(flagIds);
    const rows = getAll(
      `SELECT id, user_id, username, route, severity, reasons, input_excerpt, ip, ua, created_at
         FROM ai_input_flags WHERE id IN (${ph}) ORDER BY id DESC`,
      flagIds,
    );
    lines.push('\n# AI flags');
    for (const r of rows) lines.push(JSON.stringify({ table: 'ai_input_flags', ...r }));
  }

  const netIds = Array.isArray(selection?.network_ids)
    ? selection.network_ids.map(Number).filter(Number.isFinite)
    : [];
  if (netIds.length) {
    summaryKeys.push(`network_ids:${netIds.length}`);
    const ph = inPlaceholders(netIds);
    const rows = getAll(
      `SELECT id, hit_at, peer_ip, session_id, sensor_name, protocol, event_type, cowrie_eventid, payload_json, enrichment
         FROM network_sensor_events WHERE id IN (${ph}) ORDER BY id DESC`,
      netIds,
    );
    lines.push('\n# Network sensor (Cowrie)');
    for (const r of rows) lines.push(JSON.stringify({ table: 'network_sensor_events', ...r }));
  }

  const extraNotes = typeof selection?.notes === 'string' ? selection.notes : '';
  const blob =
    [...lines, extraNotes && `\n# Admin notes\n${extraNotes}`].filter(Boolean).join('\n') ||
    '';

  return { blob, summaryKeys };
}

const router = Router();
router.use(requireAdmin);

router.post('/log-review', async (req, res) => {
  const reviewTypeRaw = req.body?.review_type || 'mixed';
  const rt = ['honeypot', 'maze', 'access', 'ai_flag', 'alert', 'mixed', 'network'].includes(reviewTypeRaw)
    ? reviewTypeRaw
    : 'mixed';

  const selection =
    req.body?.selection && typeof req.body.selection === 'object' ? req.body.selection : {};
  const { blob, summaryKeys } = gatherContext(selection);
  const userContext =
    typeof req.body?.context === 'string' ? req.body.context.slice(0, 20000) : '';

  const combinedGuardInput = `${userContext}\n\n${blob || '(no structured rows)'}`;
  const guard = evaluate({
    user: req.user,
    route: 'log_review',
    input: combinedGuardInput.slice(0, 95_000),
    ip: getRequestIp(req),
    ua: req.headers['user-agent'] || '',
    channel: 'ai_log_review',
    path: '/api/admin/ai/log-review',
  });

  const requestId = randomUUID();

  run(
    `INSERT INTO ai_log_review_request_logs
     (request_id, route, status, user_id, username, role, review_type, selection_summary, request_payload)
     VALUES (?,?,?,?,?,?,?,?,?)`,
    [
      requestId,
      '/api/admin/ai/log-review',
      'running',
      req.user?.id ?? null,
      req.user?.username ?? null,
      req.user?.role ?? null,
      rt,
      JSON.stringify({ keys: summaryKeys }),
      JSON.stringify(selection),
    ],
  );

  if (guard.action === 'block') {
    run(
      `UPDATE ai_log_review_request_logs
          SET status = 'failed',
              finished_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
              error_message = ?,
              updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE request_id = ?`,
      [`input_guard_blocked: ${(guard.reasons || []).join(', ')}`, requestId],
    );
    auditReq(req, {
      actionType: 'ai.log_review_blocked',
      targetType: 'ai_log_review',
      targetId: requestId,
      payload: guard,
    });
    return res.status(403).json({ error: 'input_guard_blocked', reasons: guard.reasons });
  }

  const creds = getServiceCredentials('ai_llm');
  if (!creds?.api_key) {
    run(
      `UPDATE ai_log_review_request_logs
          SET status='failed',
              error_message=?,
              finished_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
              updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE request_id = ?`,
      ['ai_llm_not_configured', requestId],
    );
    return res.status(503).json({ error: 'ai_llm_not_configured' });
  }

  const baseURL = String(creds.api_url || process.env.OPENAI_COMPAT_URL || 'https://api.x.ai/v1').replace(
    /\/+$/,
    '',
  );
  const modelPrimary = creds.model || 'grok-4.3-latest';
  const modelFallback = creds.fallback_model || 'grok-latest';

  const client = new OpenAI({ apiKey: creds.api_key, baseURL });

  const systemInstructions = [
    'You are a security engineer reviewing structured security logs.',
    'Return a JSON object ONLY with keys: summary_md (markdown string)',
    'and suggested_actions (array of plain strings).',
    'Do not hallucinate IPs or events absent from payload.',
  ].join(' ');

  /** @type {import('openai/resources/chat/completions').ChatCompletionMessageParam[]} */
  const msgs = [{ role: 'system', content: systemInstructions }];
  if (guard.action === 'warn') msgs.push(INJECTION_DEFENSE_MSG);
  msgs.push({
    role: 'user',
    content: `# Review type\n${rt}\n\n# Log excerpts\n${blob || '(none)'}\n\n# Instructions from admin\n${userContext || '(none)'}`,
  });

  const fullPrompt = JSON.stringify(msgs);

  let summaryMd = '';
  let suggestedText = '';
  let modelUsed = modelPrimary;

  /** @type {Awaited<ReturnType<OpenAI['chat']['completions']['create']>> | null} */
  let completion = null;

  try {
    try {
      completion = await client.chat.completions.create({
        model: modelPrimary,
        temperature: 0.2,
        messages: msgs,
      });
      modelUsed = modelPrimary;
    } catch {
      completion = await client.chat.completions.create({
        model: modelFallback,
        temperature: 0.2,
        messages: msgs,
      });
      modelUsed = modelFallback;
    }

    const choice = completion?.choices?.[0]?.message?.content;
    const rawText = typeof choice === 'string' ? choice : '';
    /** @type {{ summary_md?: string; suggested_actions?: string[] }} */
    let parsed = {};
    try {
      parsed = JSON.parse(rawText);
    } catch {
      parsed = {};
    }

    summaryMd = parsed.summary_md || rawText;
    suggestedText = Array.isArray(parsed.suggested_actions)
      ? parsed.suggested_actions.join('\n')
      : '';

    const insertRev = run(
      `INSERT INTO ai_log_reviews
       (review_type, selection, summary_md, suggested_actions, model, raw_response, generated_by)
       VALUES (?,?,?,?,?,?,?)`,
      [
        rt,
        JSON.stringify(selection),
        summaryMd.slice(0, 50_000),
        suggestedText.slice(0, 20_000),
        modelUsed,
        rawText.slice(0, 120_000),
        req.user?.id ?? req.user?.username ?? 'unknown',
      ],
    );

    const reviewSqliteId =
      typeof insertRev.lastInsertRowid === 'bigint'
        ? Number(insertRev.lastInsertRowid)
        : insertRev.lastInsertRowid;

    run(
      `UPDATE ai_log_review_request_logs SET
           status='succeeded',
           model=?,
           request_payload=?,
           response_payload=?,
           prompt_tokens=?,
           completion_tokens=?,
           total_tokens=?,
           error_message=NULL,
           finished_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
           updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE request_id=?`,
      [
        modelUsed,
        fullPrompt,
        JSON.stringify(completion),
        completion.usage?.prompt_tokens ?? null,
        completion.usage?.completion_tokens ?? null,
        completion.usage?.total_tokens ?? null,
        requestId,
      ],
    );

    auditReq(req, {
      actionType: 'ai.log_review',
      targetType: 'ai_log_review',
      targetId: requestId,
      payload: {
        guard: guard.action,
        modelUsed,
        sqlite_review_rowid: reviewSqliteId,
      },
    });

    return res.status(200).json({
      request_id: requestId,
      guard: guard.action,
      summary_md: summaryMd,
      suggested_actions: suggestedText.split('\n').filter(Boolean),
      model: modelUsed,
      review_id: reviewSqliteId,
    });
  } catch (err) {
    run(
      `UPDATE ai_log_review_request_logs SET status='failed',
           error_message=?,
           finished_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
           updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
       WHERE request_id=?`,
      [String(err?.message || err).slice(0, 2048), requestId],
    );
    auditReq(req, {
      actionType: 'ai.log_review_failed',
      targetType: 'ai_log_review',
      targetId: requestId,
      payload: { error: String(err?.message || err) },
    });
    return res.status(502).json({ error: 'llm_failure', detail: String(err?.message || err) });
  }
});

router.get('/reviews', (_req, res) => {
  const rows = getAll(
    `SELECT id, review_type, summary_md, suggested_actions, model,
            generated_at, pinned
       FROM ai_log_reviews
       ORDER BY datetime(generated_at) DESC LIMIT 80`,
  );
  res.json({ reviews: rows });
});

router.get('/request-logs', (_req, res) => {
  const rows = getAll(
    `SELECT request_id, route, status, username, review_type, model,
            prompt_tokens, completion_tokens, total_tokens, error_message,
            created_at, finished_at, request_payload, response_payload
       FROM ai_log_review_request_logs
       ORDER BY datetime(created_at) DESC LIMIT 100`,
  );
  res.json({ logs: rows });
});

export default router;
