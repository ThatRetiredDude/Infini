import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import multer from 'multer';

import { ensureSchema } from './schema.js';
import { closeDb } from './db.js';
import {
  attachUser,
  requireAdmin,
  requireAuth,
  findUserByUsername,
  findUserById,
  verifyPassword,
  changeOwnPassword,
  MIN_NEW_PASSWORD_LENGTH,
  issueSession,
  revokeSession,
  setAuthCookies,
  clearAuthCookies,
  generateRecoveryPassword,
  createUser,
} from './auth.js';
import { audit, auditReq, getRequestIp } from './audit.js';
import { buildAccessToken } from './crypto.js';
import { run, getOne } from './db.js';
import { csrfProtection } from './csrf.js';
import adminMfaRouter from './admin-mfa.js';
import { issueMfaTicket, verifyMfaTicket, unsealTotpSecret, verifyTotpCode } from './mfa-totp.js';
import integrationsRouter from './integrations.js';
import monitoredEndpointRouter, {
  envFileHandler,
  gitConfigHandler,
  gitHeadHandler,
  wpAdminHandler,
  openApiHandler,
  apiKeysHandler,
  internalDebugHandler,
  backupIndexHandler,
  awsCredsHandler,
  dockerConfigHandler,
  phpmyadminHandler,
  adminerHandler,
  securityTxtHandler,
  accessPolicyRobotsHandler,
  jenkinsLoginHandler,
  gitlabSignInHandler,
  grafanaLoginHandler,
  actuatorEnvHandler,
  owaHandler,
  solrHandler,
  awsConsoleHandler,
  exchangeEcpHandler,
} from './monitored-endpoints.js';
import dataRoomRouter from './data-room.js';
import intranetRouter from './intranet.js';
import securityHubRouter from './security-hub.js';
import aiFlagsAdminRouter from './ai-flags-admin.js';
import { startAlertsScheduler } from './security-alerts.js';
import { sitePublicRouter, siteAdminRouter } from './page-visibility.js';
import { createBlogPublicRouter, createBlogAdminRouter } from './blog.js';
import { createCarouselPublicRouter, createCarouselAdminRouter } from './carousel.js';
import adminAuditRouter from './admin-audit.js';
import aiLogReviewRouter from './ai-log-review.js';
import { startCowrieIngestLoop, getCowrieIngestHealth } from './cowrie-ingest.js';
import { recordDecoyRequest } from './decoy-events.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';
const ACCESS_LOG_CSV_DIR = process.env.ACCESS_LOG_CSV_DIR
  ? path.resolve(ROOT, process.env.ACCESS_LOG_CSV_DIR)
  : null;

// Uploads directory (shared with static /uploads and blog images)
const uploadsDir = process.env.UPLOADS_DIR
  ? path.resolve(process.env.UPLOADS_DIR)
  : path.join(ROOT, 'data', 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

function resolveCorsOrigins() {
  const fromEnv = (process.env.CORS_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (fromEnv.length) return fromEnv;
  if (!IS_PROD) {
    return [
      'http://localhost:5173',
      'http://127.0.0.1:5173',
      'http://localhost:3000',
      'http://127.0.0.1:3000',
    ];
  }
  const site = (process.env.PUBLIC_SITE_ORIGIN || process.env.PUBLIC_BASE_URL || '')
    .trim()
    .replace(/\/+$/, '');
  return site ? [site] : [];
}

const CORS_ALLOWED = resolveCorsOrigins();

function enforceHttps(req, res, next) {
  if (process.env.ENFORCE_HTTPS !== 'true') return next();
  const secure = req.secure || req.get('x-forwarded-proto') === 'https';
  if (secure) return next();
  const host = req.get('host') || '';
  return res.redirect(301, `https://${host}${req.originalUrl}`);
}

const ADMIN_HTML_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https:",
  "font-src 'self' data:",
  "connect-src 'self' https:",
  "worker-src 'self' blob:",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ');

// ─── Boot: schema ────────────────────────────────────────────────────────────
ensureSchema();

// ─── Middleware ──────────────────────────────────────────────────────────────
app.set('trust proxy', 1);
app.use(enforceHttps);
app.use(
  helmet({
    contentSecurityPolicy: false, // configured per-route in production builds
    crossOriginEmbedderPolicy: false,
  }),
);
if (IS_PROD && CORS_ALLOWED.length === 0) {
  console.warn(
    '[cors] PUBLIC_SITE_ORIGIN / CORS_ORIGINS unset in production — browser API calls with Origin may fail.',
  );
}
app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true);
      if (CORS_ALLOWED.length === 0) return cb(null, false);
      return cb(null, CORS_ALLOWED.includes(origin));
    },
    credentials: true,
  }),
);
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(cookieParser());
app.use(attachUser);
app.use(csrfProtection);

// Public access policy headers. Keep these neutral so public responses read
// like ordinary compliance controls rather than instrumentation.
app.use((_req, res, next) => {
  res.setHeader('X-Robots-Tag', 'noai, noimageai');
  res.setHeader('AI-Content-Policy', 'disallow-training');
  res.setHeader('X-Access-Policy', 'access may be logged for compliance and security review');
  next();
});

// ─── Health ──────────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'infini',
    env: NODE_ENV,
    cowrie: getCowrieIngestHealth(),
  });
});

// ─── Public / site ─────────────────────────────────────────────────────────────
app.use('/api/site', sitePublicRouter);
app.use('/api/blog', createBlogPublicRouter());
app.use('/api/carousel', createCarouselPublicRouter());

// ─── Admin: integrations CRUD ────────────────────────────────────────────────
app.use('/api/admin/integrations', integrationsRouter);
app.use('/api/admin/site', siteAdminRouter);
app.use('/api/admin/security', securityHubRouter);
app.use('/api/admin/ai-flags', aiFlagsAdminRouter);
app.use('/api/admin/blog', createBlogAdminRouter());
app.use('/api/admin/carousel', createCarouselAdminRouter());
app.use('/api/admin/audit', adminAuditRouter);
app.use('/api/admin/ai', aiLogReviewRouter);
app.use('/api/admin/auth/mfa', adminMfaRouter);

// ─── Admin uploads for blog images (cover + inline) ───────────────────────────
const upload = multer({
  storage: multer.diskStorage({
    destination: uploadsDir,
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname) || '.bin';
      cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
    },
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('only_images_allowed'));
    cb(null, true);
  },
});
app.post('/api/admin/uploads', requireAdmin, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'no_file' });
  res.json({ url: `/uploads/${req.file.filename}` });
});

// ─── Monitored internal-looking routes (mounted under /api/secrets) ───────────
// IMPORTANT: data-room router must mount BEFORE monitoredEndpointRouter, because the
// monitoredEndpointRouter is also mounted under /api/secrets and Express resolves the
// most-specific path first only when both routers are at the same prefix and
// the longer one is registered first. Both routers' routes are disjoint.
app.use('/api/secrets/explore', dataRoomRouter);
app.use('/api/secrets', monitoredEndpointRouter);

// Finite corporate intranet (disjoint from maze and secrets)
app.use('/intranet', intranetRouter);

// ─── Scanner-friendly internal-looking URLs ──────────────────────────────────
// These are the URLs that classic credential / secret / admin scanners look
// for. Each one returns plausible-looking-but-empty content and logs the hit
// with a distinct `source` discriminator.
app.get(['/.env', '/.env.local', '/.env.production', '/api/.env'], envFileHandler);
app.get('/.git/config', gitConfigHandler);
app.get('/.git/HEAD', gitHeadHandler);
app.get(['/.aws/credentials', '/.aws/config'], awsCredsHandler);
app.get('/.docker/config.json', dockerConfigHandler);
app.get(['/wp-admin', '/wp-admin/', '/wp-login.php', '/xmlrpc.php'], wpAdminHandler);
app.get(['/phpmyadmin', '/phpmyadmin/', '/phpMyAdmin', '/phpMyAdmin/'], phpmyadminHandler);
app.get(['/adminer.php', '/adminer'], adminerHandler);
app.get(['/openapi.json', '/swagger.json', '/api/docs.json'], openApiHandler);
app.get(['/api/keys', '/api/admin/api-keys', '/api/admin/keys'], apiKeysHandler);
app.get(['/api/internal/debug', '/api/admin/debug', '/api/debug/env'], internalDebugHandler);
app.get(['/backup.sql', '/dump.sql', '/db_backup.zip', '/backups/', '/backups/index.json'], backupIndexHandler);
app.get('/.well-known/security.txt', securityTxtHandler);
app.get('/robots.txt', accessPolicyRobotsHandler);

// Easy high-coverage HTTP lures (interactive feedback on login attempts etc.)
app.get(['/jenkins', '/jenkins/', '/jenkins/login'], jenkinsLoginHandler);
app.post('/jenkins/j_acegi_security_check', jenkinsLoginHandler);
app.get(['/users/sign_in', '/gitlab/'], gitlabSignInHandler);
app.post('/users/sign_in', gitlabSignInHandler);
app.get(['/login', '/grafana/'], grafanaLoginHandler);
app.post('/login', grafanaLoginHandler);
app.get(['/actuator', '/actuator/env', '/actuator/health', '/actuator/beans'], actuatorEnvHandler);
app.get(['/owa', '/owa/', '/owa/auth.owa'], owaHandler);
app.post('/owa/auth.owa', owaHandler);
app.get(['/solr', '/solr/', '/solr/admin'], solrHandler);
app.get(['/console', '/console/home', '/signin'], awsConsoleHandler);
app.post('/signin', awsConsoleHandler);
app.get(['/ecp', '/ecp/', '/ecp/default.aspx'], exchangeEcpHandler);
app.post('/ecp/default.aspx', exchangeEcpHandler);

// Any other /api/admin route is a real admin surface: it must never fall
// through as public. The intentionally exposed decoy admin-looking URLs above
// are the only exception.
app.use('/api/admin', requireAdmin, (_req, res) => {
  res.status(404).json({ error: 'admin_route_not_found' });
});

// ─── Auth routes ─────────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const MAX_LOGIN_FAILURES = Number(process.env.MAX_LOGIN_FAILURES || 5);
const LOGIN_BLOCK_DURATION_MS = 5 * 60 * 1000;
const loginFailureMap = new Map(); // lowercased username -> { count: number, blockedUntil: number | null }

function getLoginFailureKey(username) {
  return String(username || '').toLowerCase();
}

function isLoginBlocked(username) {
  const key = getLoginFailureKey(username);
  const entry = loginFailureMap.get(key);
  if (!entry || !entry.blockedUntil) return false;
  if (Date.now() > entry.blockedUntil) {
    loginFailureMap.delete(key);
    return false;
  }
  return true;
}

function recordLoginFailure(username) {
  const key = getLoginFailureKey(username);
  const now = Date.now();
  let entry = loginFailureMap.get(key);
  if (!entry) {
    entry = { count: 0, blockedUntil: null };
    loginFailureMap.set(key, entry);
  }
  entry.count += 1;
  if (entry.count >= MAX_LOGIN_FAILURES && !entry.blockedUntil) {
    entry.blockedUntil = now + LOGIN_BLOCK_DURATION_MS;
  }
}

function clearLoginFailures(username) {
  loginFailureMap.delete(getLoginFailureKey(username));
}

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'username_and_password_required' });
  }
  const attemptedUsername = String(username);
  if (isLoginBlocked(attemptedUsername)) {
    audit({
      actionType: 'auth.login_failed',
      actorUsername: attemptedUsername,
      ip: getRequestIp(req),
      userAgent: req.headers['user-agent'],
      payload: { reason: 'rate_limited' },
    });
    return res.status(429).json({ error: 'too_many_attempts' });
  }
  const user = findUserByUsername(attemptedUsername);
  if (!user) {
    audit({
      actionType: 'auth.login_failed',
      actorUsername: attemptedUsername,
      ip: getRequestIp(req),
      userAgent: req.headers['user-agent'],
      payload: { reason: 'user_not_found' },
    });
    recordLoginFailure(attemptedUsername);
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  const ok = await verifyPassword(String(password), user.password_hash);
  if (!ok) {
    audit({
      actionType: 'auth.login_failed',
      actorUsername: attemptedUsername,
      ip: getRequestIp(req),
      userAgent: req.headers['user-agent'],
      payload: { reason: 'invalid_password' },
    });
    recordLoginFailure(attemptedUsername);
    return res.status(401).json({ error: 'invalid_credentials' });
  }

  if (user.totp_enabled && user.totp_secret_sealed) {
    const ticket = issueMfaTicket(user.id);
    return res.json({
      mfa_required: true,
      ticket,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        is_admin: !!user.is_admin,
        email: user.email,
        password_change_required: !!user.password_change_required,
        totp_enabled: true,
      },
    });
  }

  clearLoginFailures(attemptedUsername);

  const { token, csrfToken } = issueSession(user, {
    ip: getRequestIp(req),
    userAgent: req.headers['user-agent'],
  });
  setAuthCookies(res, req, { token, csrfToken });

  audit({
    actionType: 'auth.login',
    actorId: user.id,
    actorUsername: user.username,
    ip: getRequestIp(req),
    userAgent: req.headers['user-agent'],
  });

  res.json({
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      is_admin: !!user.is_admin,
      email: user.email,
      password_change_required: !!user.password_change_required,
      totp_enabled: false,
    },
  });
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/api/auth/register', registerLimiter, async (req, res) => {
  const { username, password, email } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'username_and_password_required' });
  }
  const uname = String(username).trim();
  if (uname.length < 3 || uname.length > 32) {
    return res.status(400).json({ error: 'username_invalid' });
  }
  if (String(password).length < MIN_NEW_PASSWORD_LENGTH) {
    return res.status(400).json({ error: 'password_too_weak' });
  }
  if (findUserByUsername(uname)) {
    return res.status(409).json({ error: 'username_taken' });
  }
  try {
    const user = await createUser({
      username: uname,
      email: email ? String(email).trim() : null,
      password,
      role: 'guest',
      passwordChangeRequired: false,
    });
    const { token, csrfToken } = issueSession(user, {
      ip: getRequestIp(req),
      userAgent: req.headers['user-agent'],
    });
    setAuthCookies(res, req, { token, csrfToken });
    audit({
      actionType: 'auth.register',
      actorId: user.id,
      actorUsername: user.username,
      ip: getRequestIp(req),
      userAgent: req.headers['user-agent'],
    });
    res.status(201).json({
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        is_admin: !!user.is_admin,
        email: user.email,
        password_change_required: !!user.password_change_required,
        totp_enabled: false,
      },
    });
  } catch (e) {
    if (e.message && e.message.includes('invalid role')) {
      return res.status(400).json({ error: 'invalid_role' });
    }
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'username_or_email_taken' });
    }
    if (e.code === 'SQLITE_CONSTRAINT_CHECK') {
      return res.status(500).json({ error: 'schema_constraint_failed', detail: e.message });
    }
    if (e.code === 'SQLITE_CONSTRAINT_NOTNULL') {
      return res.status(400).json({ error: 'missing_required_field' });
    }
    console.error('[register] error', e);
    return res.status(500).json({ error: 'registration_failed' });
  }
});

const mfaVerifyLimiter = rateLimit({
  windowMs: 60_000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/api/auth/mfa/totp-verify', mfaVerifyLimiter, async (req, res) => {
  const { ticket, code } = req.body || {};
  if (!ticket || !code) {
    return res.status(400).json({ error: 'ticket_and_code_required' });
  }
  let userId;
  try {
    ({ userId } = verifyMfaTicket(ticket));
  } catch {
    audit({
      actionType: 'auth.mfa_failed',
      ip: getRequestIp(req),
      userAgent: req.headers['user-agent'],
      payload: { reason: 'invalid_mfa_ticket', ticket: String(ticket || '').slice(0, 8) + '...' },
    });
    return res.status(401).json({ error: 'invalid_mfa_ticket' });
  }

  const user = findUserById(userId);
  if (!user?.totp_enabled || !user.totp_secret_sealed) {
    return res.status(400).json({ error: 'totp_not_enabled' });
  }

  let secretPlain;
  try {
    secretPlain = unsealTotpSecret(user.totp_secret_sealed);
  } catch {
    return res.status(500).json({ error: 'totp_unseal_failed' });
  }

  if (!verifyTotpCode(secretPlain, code)) {
    audit({
      actionType: 'auth.mfa_failed',
      actorId: userId,
      ip: getRequestIp(req),
      userAgent: req.headers['user-agent'],
      payload: { reason: 'invalid_totp_code' },
    });
    return res.status(401).json({ error: 'invalid_totp_code' });
  }

  clearLoginFailures(user.username); // clear any prior password failures on full MFA success

  const { token, csrfToken } = issueSession(user, {
    ip: getRequestIp(req),
    userAgent: req.headers['user-agent'],
  });
  setAuthCookies(res, req, { token, csrfToken });

  audit({
    actionType: 'auth.login_mfa',
    actorId: user.id,
    actorUsername: user.username,
    ip: getRequestIp(req),
    userAgent: req.headers['user-agent'],
  });

  res.json({
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      is_admin: !!user.is_admin,
      email: user.email,
      password_change_required: !!user.password_change_required,
      totp_enabled: true,
    },
  });
});

const changePasswordLimiter = rateLimit({
  windowMs: 60_000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
});

const forgotPasswordLimiter = rateLimit({
  windowMs: 60_000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/api/auth/change-password', changePasswordLimiter, requireAuth, async (req, res) => {
  const { current_password, new_password } = req.body || {};
  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'password_fields_required' });
  }
  const outcome = await changeOwnPassword(req.user.id, req.user.sessionId, current_password, new_password);

  if (outcome.error === 'password_too_weak') {
    return res.status(400).json({
      error: outcome.error,
      min_length: MIN_NEW_PASSWORD_LENGTH,
    });
  }
  if (outcome.error === 'invalid_current_password') {
    return res.status(401).json({ error: outcome.error });
  }
  if (outcome.error === 'same_password') {
    return res.status(400).json({ error: outcome.error });
  }
  if (outcome.error) {
    return res.status(500).json({ error: 'password_change_failed' });
  }

  const u = findUserById(req.user.id);
  auditReq(req, { actionType: 'auth.password_change' });

  res.json({
    ok: true,
    user: {
      id: u.id,
      username: u.username,
      role: u.role,
      is_admin: !!u.is_admin,
      email: u.email,
      password_change_required: !!u.password_change_required,
    },
  });
});

app.post('/api/auth/forgot-password', forgotPasswordLimiter, async (req, res) => {
  const { username } = req.body || {};
  if (!username) {
    return res.status(400).json({ error: 'username_required' });
  }
  const user = findUserByUsername(String(username).trim());
  if (!user) {
    return res.status(404).json({ error: 'user_not_found' });
  }
  let recoveryFile;
  try {
    ({ recoveryFile } = await generateRecoveryPassword(user.username));
  } catch (e) {
    return res.status(500).json({ error: 'recovery_failed' });
  }

  // Phase 2: optional supplementary email when SMTP_HOST is set (and user has email on file)
  if (process.env.SMTP_HOST && user.email) {
    try {
      const nodemailer = await import('nodemailer');
      const transport = nodemailer.default.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT) || 587,
        secure: process.env.SMTP_SECURE === 'true',
        auth: process.env.SMTP_USER
          ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS || '' }
          : undefined,
      });
      await transport.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER || 'no-reply@localhost',
        to: user.email,
        subject: 'Infini Password Recovery File Created',
        text: [
          'A password recovery file was created for your account.',
          '',
          `Recovery file location: ${recoveryFile}`,
          '',
          'Please check the server volume (only the operator can access it).',
          'Your previous password remains valid. Delete the file after use.',
        ].join('\n'),
      });
      transport.close();
    } catch (mailErr) {
      console.warn('[forgot-password] SMTP send failed (non-fatal):', mailErr?.message || mailErr);
    }
  }

  auditReq(req, { actionType: 'auth.forgot_password', actorUsername: user.username });
  res.json({ ok: true, recoveryFile });
});

app.post('/api/auth/logout', (req, res) => {
  if (req.user?.sessionId) {
    revokeSession(req.user.sessionId);
    auditReq(req, { actionType: 'auth.logout' });
  }
  clearAuthCookies(res, req);
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.user) return res.json({ user: null });
  const full = findUserById(req.user.id);
  res.json({
    user: {
      id: req.user.id,
      username: req.user.username,
      role: req.user.role,
      is_admin: req.user.is_admin,
      password_change_required: !!req.user.password_change_required,
      totp_enabled: !!(full?.totp_enabled && full?.totp_secret_sealed),
      totp_enroll_pending: !!(full?.totp_pending_sealed && !full?.totp_enabled),
    },
  });
});

// ─── SPA fallback + access logging ───────────────────────────────────────────
// Every request that isn't an /api or /uploads route gets the SPA shell.
// We inject a per-request access token into a meta tag and record the hit.
function csvEscapeVal(val) {
  const s = String(val ?? '').replace(/"/g, '""');
  return /[",\n\r]/.test(s) ? `"${s}"` : s;
}

function appendAccessCsv(row) {
  if (!ACCESS_LOG_CSV_DIR) return;
  try {
    fs.mkdirSync(ACCESS_LOG_CSV_DIR, { recursive: true });
    const date = row.hit_at.slice(0, 10);
    const file = path.join(ACCESS_LOG_CSV_DIR, `access-log-${date}.csv`);
    const header = ['hit_at', 'ip', 'user_agent', 'referer', 'token', 'path'];
    const line = header.map((key) => csvEscapeVal(row[key])).join(',');
    const needsHeader = !fs.existsSync(file);
    fs.appendFile(file, `${needsHeader ? `${header.join(',')}\n` : ''}${line}\n`, (err) => {
      if (err) console.warn('[access_log] csv append failed:', err?.message || err);
    });
  } catch (err) {
    console.warn('[access_log] csv setup failed:', err?.message || err);
  }
}

function logAccess(req, token) {
  const row = {
    hit_at: new Date().toISOString(),
    ip: getRequestIp(req),
    user_agent: req.headers['user-agent'] || null,
    referer: req.headers['referer'] || null,
    token,
    path: req.originalUrl,
  };
  try {
    run(
      `INSERT INTO access_log (ip, user_agent, referer, token, path) VALUES (?, ?, ?, ?, ?)`,
      [row.ip, row.user_agent, row.referer, row.token, row.path],
    );
    recordDecoyRequest(req, {
      source: 'access_trail',
      decoy_id: token ? 'spa_page_load' : 'hidden_beacon',
      decoy_type: 'beacon',
      action: token ? 'view' : 'hidden_link_follow',
      severity: token ? 'low' : 'medium',
      suspicious: !token,
      reasons: token ? ['access_trail'] : ['hidden_link_follow'],
      token,
      enrich: false,
    });
    appendAccessCsv(row);
  } catch (err) {
    console.warn('[access_log] insert failed:', err?.message || err);
  }
}

// Hidden 1×1 beacon — the SPA links to this from a `display:none` <a>.
app.get('/api/mi-verify', (req, res) => {
  logAccess(req, null); // token=NULL signals a beacon hit (the bait was followed)
  res
    .status(200)
    .set('Cache-Control', 'no-store')
    .type('text/plain')
    .send('ok');
});

// Serve build output in production, plus uploaded files.
const distDir = path.join(ROOT, 'dist');
app.use('/uploads', express.static(uploadsDir));

if (IS_PROD && fs.existsSync(distDir)) {
  app.use(
    express.static(distDir, {
      index: false, // we serve index.html ourselves so we can inject tokens
      maxAge: '1h',
    }),
  );
}

app.get('*', (req, res, next) => {
  // Don't catch API routes
  if (req.path.startsWith('/api/') || req.path.startsWith('/uploads/')) return next();

  const token = buildAccessToken();
  logAccess(req, token);

  // In dev, Vite serves index.html; we only render it ourselves in prod.
  if (!IS_PROD) return next();

  const indexPath = path.join(distDir, 'index.html');
  if (!fs.existsSync(indexPath)) {
    return res.status(503).type('text/plain').send('Build artifacts missing. Run `npm run build`.');
  }
  fs.readFile(indexPath, 'utf8', (err, html) => {
    if (err) return next(err);
    let headExtra = `<meta name="mi-session-ref" content="${token}" />`;
    // Blog social preview meta (og + twitter cards) for x.com etc.
    if (req.path.startsWith('/blog/')) {
      const slug = req.path.slice(6).split(/[?#]/)[0].replace(/\/$/, '');
      if (slug) {
        const post = getOne(
          `SELECT title, excerpt, cover_image_url FROM blog_posts WHERE slug = ? AND status = 'published' LIMIT 1`,
          [slug]
        );
        if (post) {
          const site = (process.env.PUBLIC_SITE_ORIGIN || process.env.PUBLIC_BASE_URL || '').replace(/\/$/, '');
          const img = post.cover_image_url ? (post.cover_image_url.startsWith('http') ? post.cover_image_url : (site + post.cover_image_url)) : '';
          const desc = (post.excerpt || '').slice(0, 200).replace(/"/g, '');
          const title = (post.title || 'Blog').replace(/"/g, '');
          headExtra += `
    <meta property="og:title" content="${title}" />
    <meta property="og:description" content="${desc}" />
    <meta property="og:image" content="${img}" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${title}" />
    <meta name="twitter:description" content="${desc}" />
    <meta name="twitter:image" content="${img}" />`;
        }
      }
    }
    const injected = html.replace(/<head>/i, `<head>\n    ${headExtra}`);
    const isAdminShell = req.path === '/admin' || req.path.startsWith('/admin/');
    const headers = { 'Cache-Control': 'no-store' };
    if (isAdminShell) {
      headers['Content-Security-Policy'] = ADMIN_HTML_CSP;
    }
    res.status(200).set(headers).type('text/html').send(injected);
  });
});

// ─── Boot ────────────────────────────────────────────────────────────────────
let stopAlertsScheduler = null;
let stopCowrieIngest = null;
const server = app.listen(PORT, () => {
   
  console.log(`[infini] listening on http://localhost:${PORT}  (${NODE_ENV})`);
  if (process.env.DISABLE_SECURITY_ALERT_SCHEDULER !== '1') {
    stopAlertsScheduler = startAlertsScheduler();
  }
  stopCowrieIngest = startCowrieIngestLoop();
});

function shutdown(signal) {
   
  console.log(`[infini] received ${signal}, shutting down…`);
  if (typeof stopAlertsScheduler === 'function') {
    stopAlertsScheduler();
    stopAlertsScheduler = null;
  }
  if (typeof stopCowrieIngest === 'function') {
    stopCowrieIngest();
    stopCowrieIngest = null;
  }
  server.close(() => {
    closeDb();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
