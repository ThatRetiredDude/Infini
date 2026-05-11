/**
 * server/integrations.js
 *
 * Slim integrations module for InfiniPot. Stores encrypted credentials for the
 * services the honeypot + AI Log Review + alerts engine need, and provides
 * `getServiceCredentials(service)` for other modules to read them.
 *
 * Schema lives in `server/schema.js` (table `integration_credentials`).
 * Encryption uses `server/crypto.js` with INTEGRATION_ENCRYPTION_KEY.
 */

import { Router } from 'express';
import { getOne, getAll, run } from './db.js';
import { encryptJson, decryptJson } from './crypto.js';
import { requireAdmin } from './auth.js';
import { auditReq } from './audit.js';

// ─── Service registry ───────────────────────────────────────────────────────
// Each entry describes the credential shape + what the test endpoint should do.
export const SERVICE_SCHEMAS = {
  // ── Threat intelligence / IP enrichment ─────────────────────────────────
  ipinfo: {
    label: 'IPInfo.io (IP geolocation)',
    category: 'security',
    fields: [
      {
        key: 'api_key',
        label: 'API Token',
        type: 'text',
        secret: true,
        required: false,
        placeholder: 'Optional — free tier works without a key (50k/mo)',
      },
    ],
  },
  abuseipdb: {
    label: 'AbuseIPDB (abuse confidence)',
    category: 'security',
    fields: [
      {
        key: 'api_key',
        label: 'API Key',
        type: 'text',
        secret: true,
        required: true,
        placeholder: 'Free tier: 1000 lookups/day',
      },
    ],
  },
  greynoise: {
    label: 'GreyNoise (scanner intelligence)',
    category: 'security',
    fields: [
      {
        key: 'api_key',
        label: 'API Key',
        type: 'text',
        secret: true,
        required: false,
        placeholder: 'Optional — Community API works without a key',
      },
    ],
  },
  turnstile: {
    label: 'Cloudflare Turnstile (challenge for repeat crawlers)',
    category: 'security',
    fields: [
      { key: 'site_key', label: 'Site Key', type: 'text', secret: false, required: false },
      { key: 'secret_key', label: 'Secret Key', type: 'text', secret: true, required: false },
    ],
    helpText:
      'When configured, IPs that have hit the Spider Trap 10+ times will be served a Turnstile challenge before getting more bait pages.',
  },

  // ── AI / LLM (used by AI Log Review) ─────────────────────────────────────
  ai_llm: {
    label: 'xAI Grok (AI Log Review)',
    category: 'infrastructure',
    fields: [
      {
        key: 'api_key',
        label: 'xAI API Key',
        type: 'text',
        secret: true,
        required: true,
        placeholder: 'xai-...',
      },
      {
        key: 'api_url',
        label: 'API Base URL',
        type: 'text',
        secret: false,
        required: false,
        placeholder: 'https://api.x.ai/v1',
      },
      {
        key: 'model',
        label: 'Default model',
        type: 'text',
        secret: false,
        required: false,
        placeholder: 'grok-4.3-latest',
      },
      {
        key: 'fallback_model',
        label: 'Fast fallback model',
        type: 'text',
        secret: false,
        required: false,
        placeholder: 'grok-latest',
      },
    ],
  },

  // ── Alert delivery channels ──────────────────────────────────────────────
  smtp: {
    label: 'Email (SMTP)',
    category: 'alerts',
    fields: [
      { key: 'host', label: 'SMTP Host', type: 'text', secret: false, required: true },
      { key: 'port', label: 'Port', type: 'number', secret: false, required: true },
      { key: 'secure', label: 'Use TLS', type: 'boolean', secret: false, required: false },
      { key: 'user', label: 'Username', type: 'text', secret: false, required: true },
      { key: 'pass', label: 'Password', type: 'text', secret: true, required: true },
      { key: 'from_address', label: 'From Address', type: 'text', secret: false, required: true },
      { key: 'from_name', label: 'From Name', type: 'text', secret: false, required: false },
    ],
  },
  discord: {
    label: 'Discord Webhook',
    category: 'alerts',
    fields: [
      { key: 'webhook_url', label: 'Webhook URL', type: 'text', secret: true, required: true },
    ],
  },
  telegram: {
    label: 'Telegram Bot',
    category: 'alerts',
    fields: [
      { key: 'bot_token', label: 'Bot Token', type: 'text', secret: true, required: true },
      { key: 'channel_id', label: 'Channel ID or @username', type: 'text', secret: false, required: true },
    ],
  },
  webhook: {
    label: 'Generic Webhook',
    category: 'alerts',
    fields: [
      { key: 'url', label: 'Webhook URL', type: 'text', secret: false, required: true },
      { key: 'secret', label: 'HMAC Secret (optional)', type: 'text', secret: true, required: false },
      { key: 'method', label: 'HTTP Method', type: 'text', secret: false, required: false, placeholder: 'POST' },
    ],
  },
};

function maskSecret(value) {
  if (!value || typeof value !== 'string') return '';
  if (value.length <= 8) return '****';
  return `${value.slice(0, 4)}${'*'.repeat(Math.min(value.length - 8, 12))}${value.slice(-4)}`;
}

// ─── Public helper used by ip-enrichment / honeypot / alerts ────────────────
/**
 * Returns the decrypted credentials object for a service, or null if the
 * service isn't configured or is disabled. Synchronous (SQLite is sync).
 */
export function getServiceCredentials(service) {
  const row = getOne(
    `SELECT payload_enc, iv, auth_tag, enabled FROM integration_credentials WHERE service = ?`,
    [service],
  );
  if (!row) return null;
  if (!row.enabled) return null;
  try {
    return decryptJson({
      payload_enc: row.payload_enc,
      iv: row.iv,
      auth_tag: row.auth_tag,
    });
  } catch {
    return null;
  }
}

// ─── Admin router ───────────────────────────────────────────────────────────
const router = Router();
router.use(requireAdmin);

router.get('/', (_req, res) => {
  const rows = getAll(
    `SELECT service, enabled, last_tested_at, last_test_ok, last_test_message, updated_at
     FROM integration_credentials ORDER BY service`,
  );
  const byService = Object.fromEntries(rows.map((r) => [r.service, r]));
  const services = Object.entries(SERVICE_SCHEMAS).map(([key, schema]) => {
    const row = byService[key];
    return {
      service: key,
      label: schema.label,
      category: schema.category,
      help_text: schema.helpText || null,
      configured: Boolean(row),
      enabled: row ? !!row.enabled : false,
      last_tested_at: row?.last_tested_at ?? null,
      last_test_ok: row ? !!row.last_test_ok : null,
      last_test_message: row?.last_test_message ?? null,
      updated_at: row?.updated_at ?? null,
    };
  });
  res.json({ services });
});

router.get('/schemas', (_req, res) => {
  res.json({ schemas: SERVICE_SCHEMAS });
});

router.get('/:service', (req, res) => {
  const { service } = req.params;
  const schema = SERVICE_SCHEMAS[service];
  if (!schema) return res.status(404).json({ error: 'unknown_service' });

  const row = getOne(
    `SELECT payload_enc, iv, auth_tag, enabled, last_tested_at, last_test_ok,
            last_test_message, updated_at
     FROM integration_credentials WHERE service = ?`,
    [service],
  );
  if (!row) {
    return res.json({ service, configured: false, enabled: false, fields: {}, schema });
  }

  let creds = {};
  try {
    creds = decryptJson({
      payload_enc: row.payload_enc,
      iv: row.iv,
      auth_tag: row.auth_tag,
    });
  } catch {
    return res.status(500).json({
      error: 'decrypt_failed',
      message: 'Could not decrypt stored credentials. INTEGRATION_ENCRYPTION_KEY may have changed.',
    });
  }

  const masked = {};
  for (const field of schema.fields) {
    const val = creds[field.key];
    if (val === undefined || val === null || val === '') masked[field.key] = '';
    else if (field.secret) masked[field.key] = maskSecret(String(val));
    else masked[field.key] = val;
  }

  res.json({
    service,
    configured: true,
    enabled: !!row.enabled,
    last_tested_at: row.last_tested_at,
    last_test_ok: row.last_test_ok == null ? null : !!row.last_test_ok,
    last_test_message: row.last_test_message,
    updated_at: row.updated_at,
    fields: masked,
    schema,
  });
});

router.put('/:service', (req, res) => {
  const { service } = req.params;
  const schema = SERVICE_SCHEMAS[service];
  if (!schema) return res.status(404).json({ error: 'unknown_service' });

  const incoming = req.body?.credentials;
  if (!incoming || typeof incoming !== 'object') {
    return res.status(400).json({ error: 'missing_credentials_object' });
  }

  // Preserve existing values when the client sends back masked placeholders
  let existing = {};
  const existingRow = getOne(
    `SELECT payload_enc, iv, auth_tag FROM integration_credentials WHERE service = ?`,
    [service],
  );
  if (existingRow) {
    try {
      existing = decryptJson(existingRow);
    } catch {
      existing = {};
    }
  }

  const merged = {};
  for (const field of schema.fields) {
    const val = incoming[field.key];
    const looksMasked = field.secret && typeof val === 'string' && /^[*\w]{4}\*+[*\w]{4}$|^\*+$/.test(val);
    if (looksMasked) {
      merged[field.key] = existing[field.key] ?? '';
    } else if (val !== undefined) {
      if (field.type === 'number') merged[field.key] = Number(val);
      else if (field.type === 'boolean') merged[field.key] = Boolean(val);
      else merged[field.key] = String(val);
    } else {
      merged[field.key] = existing[field.key] ?? '';
    }
  }

  const missing = schema.fields.filter((f) => f.required && !merged[f.key]);
  if (missing.length) {
    return res.status(400).json({
      error: 'missing_required_fields',
      missing: missing.map((f) => f.label),
    });
  }

  const enc = encryptJson(merged);
  run(
    `INSERT INTO integration_credentials
       (service, payload_enc, iv, auth_tag, enabled, updated_at, updated_by)
     VALUES (?, ?, ?, ?, 1, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?)
     ON CONFLICT(service) DO UPDATE SET
       payload_enc = excluded.payload_enc,
       iv = excluded.iv,
       auth_tag = excluded.auth_tag,
       updated_at = excluded.updated_at,
       updated_by = excluded.updated_by`,
    [service, enc.payload_enc, enc.iv, enc.auth_tag, req.user?.id || null],
  );

  auditReq(req, {
    actionType: 'integration.update',
    targetType: 'integration',
    targetId: service,
    payload: { fields_set: Object.keys(merged) },
  });

  res.json({ ok: true });
});

router.put('/:service/toggle', (req, res) => {
  const { service } = req.params;
  if (!SERVICE_SCHEMAS[service]) return res.status(404).json({ error: 'unknown_service' });
  const enabled = req.body?.enabled ? 1 : 0;
  const result = run(
    `UPDATE integration_credentials SET enabled = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
       updated_by = ? WHERE service = ?`,
    [enabled, req.user?.id || null, service],
  );
  if (result.changes === 0) return res.status(404).json({ error: 'service_not_configured' });
  auditReq(req, {
    actionType: 'integration.toggle',
    targetType: 'integration',
    targetId: service,
    payload: { enabled: !!enabled },
  });
  res.json({ ok: true, enabled: !!enabled });
});

router.delete('/:service', (req, res) => {
  const { service } = req.params;
  if (!SERVICE_SCHEMAS[service]) return res.status(404).json({ error: 'unknown_service' });
  const result = run(`DELETE FROM integration_credentials WHERE service = ?`, [service]);
  if (result.changes === 0) return res.status(404).json({ error: 'service_not_configured' });
  auditReq(req, {
    actionType: 'integration.delete',
    targetType: 'integration',
    targetId: service,
  });
  res.json({ ok: true });
});

router.post('/:service/test', async (req, res) => {
  const { service } = req.params;
  if (!SERVICE_SCHEMAS[service]) return res.status(404).json({ error: 'unknown_service' });
  const creds = getServiceCredentials(service);
  if (!creds) return res.status(404).json({ error: 'service_not_configured_or_disabled' });

  let ok = false;
  let message = '';
  try {
    if (service === 'smtp') {
      const nodemailer = await import('nodemailer');
      const transport = nodemailer.default.createTransport({
        host: creds.host,
        port: Number(creds.port) || 587,
        secure: Boolean(creds.secure),
        auth: { user: creds.user, pass: creds.pass },
        connectionTimeout: 10_000,
        greetingTimeout: 10_000,
      });
      await transport.verify();
      transport.close();
      ok = true;
      message = 'SMTP connection verified.';
    } else if (service === 'discord') {
      const resp = await fetch(creds.webhook_url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: 'InfiniPot integration test. You can delete this message.' }),
      });
      ok = resp.ok || resp.status === 204;
      message = ok ? 'Discord webhook test message sent.' : `Discord returned ${resp.status}`;
    } else if (service === 'telegram') {
      const resp = await fetch(`https://api.telegram.org/bot${creds.bot_token}/getMe`);
      const data = await resp.json();
      ok = !!data.ok;
      message = ok ? `Bot: @${data.result.username}` : data.description || 'invalid_bot_token';
    } else if (service === 'webhook') {
      const method = (creds.method || 'POST').toUpperCase();
      const resp = await fetch(creds.url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: method !== 'GET' ? JSON.stringify({ test: true, source: 'infinipot' }) : undefined,
      });
      ok = resp.ok;
      message = ok ? `Webhook responded ${resp.status}.` : `Webhook returned ${resp.status}`;
    } else if (service === 'ai_llm') {
      const baseUrl = (creds.api_url || 'https://api.x.ai/v1').replace(/\/+$/, '');
      const resp = await fetch(`${baseUrl}/models`, {
        headers: { Authorization: `Bearer ${creds.api_key}` },
      });
      ok = resp.ok;
      message = ok ? 'xAI API key is valid.' : `xAI returned ${resp.status}`;
    } else if (service === 'turnstile') {
      const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ secret: creds.secret_key, response: 'test-token-invalid' }),
      });
      const data = await resp.json();
      if (data['error-codes']?.includes('invalid-input-secret')) {
        message = 'Turnstile secret key is invalid.';
      } else {
        ok = true;
        message = 'Turnstile secret key is valid (test token correctly rejected).';
      }
    } else if (service === 'ipinfo' || service === 'abuseipdb' || service === 'greynoise') {
      // Light-touch validation against 8.8.8.8 — wide free tiers won't get burned.
      const probeIp = '8.8.8.8';
      const { enrichIp } = await import('./ip-enrichment.js');
      const result = await enrichIp(probeIp, { only: service });
      ok = !!result && !!result[service];
      message = ok ? `${service} returned data for ${probeIp}.` : `${service} lookup failed`;
    } else {
      message = 'no_test_available';
    }
  } catch (err) {
    message = err?.message || 'connection_test_failed';
  }

  run(
    `UPDATE integration_credentials SET last_tested_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
       last_test_ok = ?, last_test_message = ? WHERE service = ?`,
    [ok ? 1 : 0, message, service],
  );
  auditReq(req, {
    actionType: 'integration.test',
    targetType: 'integration',
    targetId: service,
    payload: { ok, message },
  });
  res.json({ ok, message });
});

export default router;
