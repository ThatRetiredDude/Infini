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
  findUserByUsername,
  verifyPassword,
  issueSession,
  revokeSession,
  getCookieOptions,
  AUTH_COOKIE_NAME,
} from './auth.js';
import { audit, auditReq, getRequestIp } from './audit.js';
import { buildAccessToken } from './crypto.js';
import { run } from './db.js';
import integrationsRouter from './integrations.js';
import aiHoneypotRouter, {
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
  honeypotRobotsHandler,
} from './ai-honeypot.js';
import aiTarpitRouter from './ai-tarpit.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';

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

// Public-facing anti-AI / honeypot signal headers. These are intentionally
// served on every response so crawlers can't claim plausible deniability.
app.use((_req, res, next) => {
  res.setHeader('X-Robots-Tag', 'noai, noimageai');
  res.setHeader('AI-Content-Policy', 'disallow-training');
  res.setHeader('X-Honeypot-Warning', 'this site contains honeypot traps; automated access is logged');
  next();
});

// ─── Health ──────────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'infinipot', env: NODE_ENV });
});

// ─── Admin: integrations CRUD ────────────────────────────────────────────────
app.use('/api/admin/integrations', integrationsRouter);

// ─── Honeypot: AI-flavored decoys (mounted under /api/ai) ────────────────────
// IMPORTANT: tarpit (router) must mount BEFORE aiHoneypotRouter, because the
// aiHoneypotRouter is also mounted under /api/ai and Express resolves the
// most-specific path first only when both routers are at the same prefix and
// the longer one is registered first. Both routers' routes are disjoint.
app.use('/api/ai/explore', aiTarpitRouter);
app.use('/api/ai', aiHoneypotRouter);

// ─── Honeypot: standalone decoys at scanner-friendly URLs ────────────────────
// These are the URLs that classic credential / secret / admin scanners look
// for. Each one returns plausible-looking-but-empty bait and logs the hit
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
app.get('/robots.txt', honeypotRobotsHandler);

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
    },
  });
});

app.post('/api/auth/logout', (req, res) => {
  if (req.user?.sessionId) {
    revokeSession(req.user.sessionId);
    auditReq(req, { actionType: 'auth.logout' });
  }
  res.clearCookie(AUTH_COOKIE_NAME, { path: '/' });
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
    },
  });
});

// ─── SPA fallback + access logging ───────────────────────────────────────────
// Every request that isn't an /api or /uploads route gets the SPA shell.
// We inject a per-request access token into a meta tag and record the hit.
function logAccess(req, token) {
  try {
    run(
      `INSERT INTO access_log (ip, user_agent, referer, token, path) VALUES (?, ?, ?, ?, ?)`,
      [
        getRequestIp(req),
        req.headers['user-agent'] || null,
        req.headers['referer'] || null,
        token,
        req.originalUrl,
      ],
    );
  } catch (err) {
    // eslint-disable-next-line no-console
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
const uploadsDir = path.join(ROOT, 'data', 'uploads');
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
const server = app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[infinipot] listening on http://localhost:${PORT}  (${NODE_ENV})`);
});

function shutdown(signal) {
  // eslint-disable-next-line no-console
  console.log(`[infinipot] received ${signal}, shutting down…`);
  server.close(() => {
    closeDb();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
