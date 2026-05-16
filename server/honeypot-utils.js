import { createHash, randomBytes } from 'node:crypto';

const SESSION_TTL_MS = 30 * 60 * 1000;
const MAX_SESSIONS = 5000;
const sessions = new Map();

function nowIso() {
  return new Date().toISOString();
}

function hashShort(value, length = 10) {
  return createHash('sha256').update(String(value)).digest('hex').slice(0, length);
}

function clientIp(req) {
  const fwd = req.headers?.['x-forwarded-for'];
  if (fwd) {
    const first = String(fwd).split(',')[0].trim();
    if (first) return first;
  }
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function sessionKey(req) {
  const ua = String(req.headers?.['user-agent'] || '').slice(0, 256);
  return hashShort(`${clientIp(req)}|${ua}`, 16);
}

function pruneSessions() {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const [key, session] of sessions) {
    if (session.last_seen_ms < cutoff) sessions.delete(key);
  }
  if (sessions.size <= MAX_SESSIONS) return;
  const oldest = [...sessions.entries()]
    .sort((a, b) => a[1].last_seen_ms - b[1].last_seen_ms)
    .slice(0, sessions.size - MAX_SESSIONS);
  for (const [key] of oldest) sessions.delete(key);
}

export function getLureContext(req, source = 'unknown') {
  pruneSessions();
  const key = sessionKey(req);
  const now = Date.now();
  const path = String(req.originalUrl || req.url || '').slice(0, 512);
  let session = sessions.get(key);
  if (!session) {
    const seed = `${key}:${now}:${randomBytes(4).toString('hex')}`;
    session = {
      key,
      first_seen: nowIso(),
      first_seen_ms: now,
      last_seen: nowIso(),
      last_seen_ms: now,
      request_count: 0,
      sources: [],
      paths: [],
      request_prefix: `req_${hashShort(seed, 8)}`,
      canary_id: `APC-CAN-${hashShort(seed, 12).toUpperCase()}`,
    };
    sessions.set(key, session);
  }

  session.last_seen = nowIso();
  session.last_seen_ms = now;
  session.request_count += 1;
  if (!session.sources.includes(source)) {
    session.sources.push(source);
    if (session.sources.length > 20) session.sources = session.sources.slice(-20);
  }
  if (!session.paths.includes(path)) {
    session.paths.push(path);
    if (session.paths.length > 30) session.paths = session.paths.slice(-30);
  }

  const requestId = `${session.request_prefix}-${String(session.request_count).padStart(4, '0')}`;
  const ctx = {
    session_key: session.key,
    request_id: requestId,
    trace_id: hashShort(`${session.key}:${requestId}`, 24),
    canary_id: session.canary_id,
    request_count: session.request_count,
    first_seen: session.first_seen,
    sequence: [...session.sources],
    recent_paths: [...session.paths],
  };
  req.decoyContext = ctx;
  return ctx;
}

export function decorateDecoyResponse(req, res, source) {
  const ctx = req.decoyContext || getLureContext(req, source);
  res.setHeader('X-Request-Id', ctx.request_id);
  res.setHeader('X-Trace-Id', ctx.trace_id);
  res.cookie?.('apc_sso_state', ctx.session_key, {
    httpOnly: true,
    sameSite: 'Lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: SESSION_TTL_MS,
  });
  return ctx;
}

function firstBodyValue(body, keys) {
  if (!body || typeof body !== 'object') return '';
  for (const key of keys) {
    if (body[key] != null) return String(body[key]);
  }
  for (const key of Object.keys(body)) {
    const lower = key.toLowerCase();
    if (keys.some((candidate) => lower.includes(candidate.toLowerCase()))) {
      return String(body[key]);
    }
  }
  return '';
}

export function classifyCredentialAttempt(body = {}) {
  const username = firstBodyValue(body, [
    'username',
    'user',
    'email',
    'login',
    'j_username',
    'log',
    'user[login]',
  ]).trim();
  const password = firstBodyValue(body, [
    'password',
    'pass',
    'pwd',
    'j_password',
    'user[password]',
  ]);
  const u = username.toLowerCase();
  const p = password.toLowerCase();
  const reasons = [];
  let category = 'unknown';
  let severity = 'medium';

  if (!username && !password) {
    category = 'empty_or_scripted_submit';
    severity = 'low';
    reasons.push('empty_form_submit');
  } else if (
    ['admin', 'root', 'administrator', 'test', 'guest', 'grafana', 'jenkins'].includes(u) &&
    ['admin', 'root', 'password', 'password1', '123456', '12345678', 'changeme', 'test'].includes(p)
  ) {
    category = 'default_credentials';
    severity = 'high';
    reasons.push('default_credential_pair');
  } else if (/@ardenpointcapital\.example$|@infini\.win$|apc|arden|maxwell/.test(u + ' ' + p)) {
    category = 'company_themed_guess';
    severity = 'high';
    reasons.push('company_theme_in_guess');
  } else if (/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(u)) {
    category = 'real_user_looking_email';
    reasons.push('email_identifier');
  } else if (/(summer|winter|spring|fall|q[1-4]|202[0-9]|!|@|#|\$)/.test(p) && password.length >= 8) {
    category = 'leaked_style_password';
    severity = 'high';
    reasons.push('season_year_or_policy_style_password');
  } else if (/^(admin|root|user|test|demo|operator|svc|service)[0-9._-]*$/.test(u)) {
    category = 'tool_generated_bruteforce';
    reasons.push('common_bruteforce_username');
  } else {
    category = 'manual_or_low_volume_guess';
    reasons.push('credential_submit');
  }

  return {
    category,
    severity,
    reasons,
    username_excerpt: username.slice(0, 96) || null,
    password_length: password.length || 0,
    password_hash: password ? hashShort(password, 16) : null,
  };
}

export function buildCanaryPayload(ctx, extra = {}) {
  return {
    request_id: ctx.request_id,
    trace_id: ctx.trace_id,
    canary_id: ctx.canary_id,
    session_key: ctx.session_key,
    sequence: ctx.sequence,
    ...extra,
  };
}
