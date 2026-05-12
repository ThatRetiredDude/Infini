import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

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
  getCookieOptions,
  AUTH_COOKIE_NAME,
} from './auth.js';
import { audit, auditReq, getRequestIp } from './audit.js';
import { buildAccessToken } from './crypto.js';
import { run } from './db.js';
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
} from './monitored-endpoints.js';
import dataRoomRouter from './data-room.js';
import securityHubRouter from './security-hub.js';
import aiFlagsAdminRouter from './ai-flags-admin.js';
import { startAlertsScheduler } from './security-alerts.js';
import { sitePublicRouter, siteAdminRouter } from './page-visibility.js';
import { createBlogPublicRouter, createBlogAdminRouter } from './blog.js';
import { createCarouselPublicRouter, createCarouselAdminRouter } from './carousel.js';
import adminAuditRouter from './admin-audit.js';
import aiLogReviewRouter from './ai-log-review.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';
const ACCESS_LOG_CSV_DIR = process.env.ACCESS_LOG_CSV_DIR
  ? path.resolve(ROOT, process.env.ACCESS_LOG_CSV_DIR)
  : null;

// ─── Boot: schema ────────────────────────────────────────────────────────────
ensureSchema();

// ─── Middleware ──────────────────────────────────────────────────────────────
app.set('trust proxy', 1);
app.use(
  helmet({
    contentSecurityPolicy: false, // configured per-route in production builds
    crossOriginEmbedderPolicy: false,
  }),
);
app.use(
  cors({
    origin: (origin, cb) => cb(null, true),
    credentials: true,
  }),
);
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(cookieParser());
app.use(attachUser);

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
  res.json({ ok: true, service: 'infini', env: NODE_ENV });
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

// ─── Monitored internal-looking routes (mounted under /api/secrets) ───────────
// IMPORTANT: data-room router must mount BEFORE monitoredEndpointRouter, because the
// monitoredEndpointRouter is also mounted under /api/secrets and Express resolves the
// most-specific path first only when both routers are at the same prefix and
// the longer one is registered first. Both routers' routes are disjoint.
app.use('/api/secrets/explore', dataRoomRouter);
app.use('/api/secrets', monitoredEndpointRouter);

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

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'username_and_password_required' });
  }
  const user = findUserByUsername(String(username));
  if (!user) return res.status(401).json({ error: 'invalid_credentials' });
  const ok = await verifyPassword(String(password), user.password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });

  const { token } = issueSession(user, {
    ip: getRequestIp(req),
    userAgent: req.headers['user-agent'],
  });
  res.cookie(AUTH_COOKIE_NAME, token, getCookieOptions());

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
    },
  });
});

const changePasswordLimiter = rateLimit({
  windowMs: 60_000,
  max: 8,
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

app.post('/api/auth/logout', (req, res) => {
  if (req.user?.sessionId) {
    revokeSession(req.user.sessionId);
    auditReq(req, { actionType: 'auth.logout' });
  }
  const co = getCookieOptions();
  res.clearCookie(AUTH_COOKIE_NAME, {
    path: '/',
    secure: co.secure,
    sameSite: co.sameSite,
    domain: co.domain,
  });
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.user) return res.json({ user: null });
  res.json({
    user: {
      id: req.user.id,
      username: req.user.username,
      role: req.user.role,
      is_admin: req.user.is_admin,
      password_change_required: !!req.user.password_change_required,
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
const uploadsDir = process.env.UPLOADS_DIR
  ? path.resolve(process.env.UPLOADS_DIR)
  : path.join(ROOT, 'data', 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
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
    const injected = html.replace(
      /<head>/i,
      `<head>\n    <meta name="mi-session-ref" content="${token}" />`,
    );
    res
      .status(200)
      .set('Cache-Control', 'no-store')
      .type('text/html')
      .send(injected);
  });
});

// ─── Boot ────────────────────────────────────────────────────────────────────
let stopAlertsScheduler = null;
const server = app.listen(PORT, () => {
   
  console.log(`[infini] listening on http://localhost:${PORT}  (${NODE_ENV})`);
  if (process.env.DISABLE_SECURITY_ALERT_SCHEDULER !== '1') {
    stopAlertsScheduler = startAlertsScheduler();
  }
});

function shutdown(signal) {
   
  console.log(`[infini] received ${signal}, shutting down…`);
  if (typeof stopAlertsScheduler === 'function') {
    stopAlertsScheduler();
    stopAlertsScheduler = null;
  }
  server.close(() => {
    closeDb();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
