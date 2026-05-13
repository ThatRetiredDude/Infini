import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getOne, run } from './db.js';
import { sha256Hex } from './crypto.js';

const COOKIE_NAME = process.env.COOKIE_NAME || 'mi_session';
export const CSRF_COOKIE_NAME = process.env.CSRF_COOKIE_NAME || 'mi_csrf';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

const MIN_PASSWORD_LENGTH = 12;
const ENFORCE_SESSION_IP_BINDING = process.env.ENFORCE_SESSION_IP_BINDING === '1' || process.env.ENFORCE_SESSION_IP_BINDING === 'true';

export function getJwtSecret() {
  const s = process.env.JWT_SECRET;
  if (!s || s.length < 32) {
    throw new Error('JWT_SECRET must be set and at least 32 characters.');
  }
  return s;
}

function cookieMaxAgeMs() {
  const m = String(JWT_EXPIRES_IN).match(/^(\d+)([smhd])$/);
  if (!m) return 7 * 24 * 60 * 60 * 1000;
  const n = Number(m[1]);
  const unit = m[2];
  const mult = unit === 's' ? 1000 : unit === 'm' ? 60_000 : unit === 'h' ? 3_600_000 : 86_400_000;
  return n * mult;
}

/** @param {import('express').Request | undefined} req */
export function cookieSecureForRequest(req) {
  if (process.env.COOKIE_SECURE === 'true') return true;
  if (process.env.COOKIE_SECURE === 'auto' && req) {
    return !!(req.secure || req.get('x-forwarded-proto') === 'https');
  }
  return false;
}

/** @param {import('express').Request | undefined} req */
export function cookieSameSiteForRequest(req) {
  const raw = (process.env.COOKIE_SAMESITE || 'lax').toLowerCase();
  let s = raw === 'strict' ? 'strict' : raw === 'none' ? 'none' : 'lax';
  if (s === 'none' && !cookieSecureForRequest(req)) {
    s = 'lax';
  }
  return s;
}

/** @param {import('express').Request | undefined} req */
export function getCookieOptions(req) {
  return {
    httpOnly: true,
    secure: cookieSecureForRequest(req),
    sameSite: cookieSameSiteForRequest(req),
    maxAge: cookieMaxAgeMs(),
    domain: process.env.COOKIE_DOMAIN || undefined,
    path: '/',
  };
}

/** @param {import('express').Request | undefined} req */
export function getCsrfCookieOptions(req) {
  return {
    httpOnly: false,
    secure: cookieSecureForRequest(req),
    sameSite: cookieSameSiteForRequest(req),
    maxAge: cookieMaxAgeMs(),
    domain: process.env.COOKIE_DOMAIN || undefined,
    path: '/',
  };
}

/** @param {import('express').Response} res @param {import('express').Request} req */
export function setAuthCookies(res, req, { token, csrfToken }) {
  res.cookie(COOKIE_NAME, token, getCookieOptions(req));
  res.cookie(CSRF_COOKIE_NAME, csrfToken, getCsrfCookieOptions(req));
}

/** @param {import('express').Response} res @param {import('express').Request} req */
export function clearAuthCookies(res, req) {
  const co = getCookieOptions(req);
  const cco = getCsrfCookieOptions(req);
  res.clearCookie(COOKIE_NAME, {
    path: '/',
    secure: co.secure,
    sameSite: co.sameSite,
    domain: co.domain,
  });
  res.clearCookie(CSRF_COOKIE_NAME, {
    path: '/',
    secure: cco.secure,
    sameSite: cco.sameSite,
    domain: cco.domain,
  });
}

export async function hashPassword(plain) {
  return bcrypt.hash(plain, 12);
}

export async function verifyPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

/**
 * Create a user row.
 */
export async function createUser({
  username,
  email = null,
  password,
  role = 'user',
  passwordChangeRequired = false,
}) {
  if (!username || !password) throw new Error('username and password are required');
  if (!['user', 'journalist', 'admin', 'guest'].includes(role)) {
    throw new Error(`invalid role: ${role}`);
  }
  const id = uuidv4();
  const password_hash = await hashPassword(password);
  const is_admin = role === 'admin' ? 1 : 0;
  const pwdChg = passwordChangeRequired ? 1 : 0;
  run(
    `INSERT INTO users (id, username, email, password_hash, role, is_admin, password_change_required)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [id, username, email, password_hash, role, is_admin, pwdChg],
  );
  return getOne(`SELECT * FROM users WHERE id = ?`, [id]);
}

export function findUserByUsername(username) {
  return getOne(`SELECT * FROM users WHERE username = ? COLLATE NOCASE`, [username]);
}

export function findUserById(id) {
  return getOne(`SELECT * FROM users WHERE id = ?`, [id]);
}

/**
 * Issue a JWT and persist a session row (so we can invalidate on logout).
 */
export function issueSession(user, { ip, userAgent } = {}) {
  const sessionId = uuidv4();
  const csrfToken = crypto.randomBytes(32).toString('hex');
  const token = jwt.sign(
    {
      sub: user.id,
      username: user.username,
      role: user.role,
      sid: sessionId,
    },
    getJwtSecret(),
    { expiresIn: JWT_EXPIRES_IN },
  );
  const expiresAt = new Date(Date.now() + cookieMaxAgeMs()).toISOString();
  run(
    `INSERT INTO user_sessions (id, user_id, token_hash, user_agent, ip, expires_at, csrf_token)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [sessionId, user.id, sha256Hex(token), userAgent || null, ip || null, expiresAt, csrfToken],
  );
  run(`UPDATE users SET last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`, [user.id]);
  return { token, sessionId, expiresAt, csrfToken };
}

export function revokeSession(sessionId) {
  run(
    `UPDATE user_sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`,
    [sessionId],
  );
}

/** Revoke all other sessions for this user (e.g. after password change). Pass null/undefined for exceptSessionId to revoke ALL sessions. */
export function revokeOtherSessions(userId, exceptSessionId) {
  if (exceptSessionId) {
    run(
      `UPDATE user_sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
       WHERE user_id = ? AND id != ? AND revoked_at IS NULL`,
      [userId, exceptSessionId],
    );
  } else {
    run(
      `UPDATE user_sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
       WHERE user_id = ? AND revoked_at IS NULL`,
      [userId],
    );
  }
}

/**
 * @returns {Promise<{ ok: true } | { error: string }>}
 */
export async function changeOwnPassword(userId, sessionId, currentPassword, newPassword) {
  const plainNew = String(newPassword ?? '');
  if (plainNew.length < MIN_PASSWORD_LENGTH) {
    return { error: 'password_too_weak' };
  }
  const user = findUserById(userId);
  if (!user) return { error: 'user_not_found' };

  const currentOk = await verifyPassword(String(currentPassword ?? ''), user.password_hash);
  if (!currentOk) return { error: 'invalid_current_password' };

  const sameAsOld = await verifyPassword(plainNew, user.password_hash);
  if (sameAsOld) return { error: 'same_password' };

  const password_hash = await hashPassword(plainNew);
  run(
    `UPDATE users SET password_hash = ?, password_change_required = 0,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE id = ?`,
    [password_hash, userId],
  );
  if (sessionId) revokeOtherSessions(userId, sessionId);
  return { ok: true };
}

/**
 * Express middleware: parse cookie/bearer JWT and attach req.user.
 * Does NOT block unauthenticated requests by itself.
 */
export function attachUser(req, _res, next) {
  let token = null;
  let authViaCookie = false;
  if (req.cookies && req.cookies[COOKIE_NAME]) {
    token = req.cookies[COOKIE_NAME];
    authViaCookie = true;
  } else {
    const h = req.headers.authorization || '';
    if (h.startsWith('Bearer ')) token = h.slice(7);
  }
  if (!token) return next();

  try {
    const decoded = jwt.verify(token, getJwtSecret());
    const session = getOne(
      `SELECT * FROM user_sessions WHERE id = ? AND revoked_at IS NULL AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')`,
      [decoded.sid],
    );
    if (!session) return next();
    if (ENFORCE_SESSION_IP_BINDING) {
      const currentIp = (req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : null) || req.ip || req.socket?.remoteAddress || null;
      if (session.ip && currentIp && session.ip !== currentIp) {
        return next(); // IP mismatch: treat session as invalid
      }
    }
    const user = findUserById(decoded.sub);
    if (!user) return next();
    req.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      is_admin: !!user.is_admin,
      sessionId: decoded.sid,
      password_change_required: !!user.password_change_required,
    };
    req.authViaCookie = authViaCookie;
    req.sessionCsrf = session.csrf_token || '';
  } catch {
    // bad/expired token — just don't attach
  }
  next();
}

export function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'authentication_required' });
  next();
}

export function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'authentication_required' });
  if (req.user.role !== 'admin' && !req.user.is_admin) {
    return res.status(403).json({ error: 'admin_required' });
  }
  if (req.user.password_change_required) {
    return res.status(403).json({ error: 'password_change_required' });
  }
  next();
}

export const MIN_NEW_PASSWORD_LENGTH = MIN_PASSWORD_LENGTH;

/** Generate a recovery password file (Jellyfin-style) and set it as the user's current password.
 * Revokes ALL existing sessions (forces re-login with the recovery password).
 * Does NOT set password_change_required.
 * Only the server operator can read the file. The password in the file is now active.
 */
export async function generateRecoveryPassword(username) {
  if (!username) throw new Error('username is required');
  const user = findUserByUsername(username);
  if (!user) throw new Error('user_not_found');

  // Strong temp password (~22 chars)
  const tempPassword = `${crypto.randomBytes(12).toString('base64url')}${crypto.randomBytes(4).toString('base64url')}`;

  // Actually activate the password so it can be used to sign in (the file is only for the operator).
  const password_hash = await hashPassword(tempPassword);
  run(
    `UPDATE users SET password_hash = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`,
    [password_hash, user.id],
  );

  // Revoke all sessions so the recovery password requires fresh login everywhere.
  revokeOtherSessions(user.id, null);

  // Resolve secrets dir consistently with DATABASE_FILE convention (Docker: /data, local: ./data)
  // This ensures writes stay inside the persistent volume and avoids permission errors or
  // accidental writes outside the intended data directory (security hardening).
  const dbFile = process.env.DATABASE_FILE;
  const dataDir = dbFile
    ? path.dirname(dbFile)
    : path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'data');
  const SECRETS_DIR = path.join(dataDir, '.secrets');

  fs.mkdirSync(SECRETS_DIR, { recursive: true, mode: 0o700 });

  const safeUsername = String(username).replace(/[^a-zA-Z0-9_-]/g, '');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const fileName = `recovery-${safeUsername}-${timestamp}.txt`;
  const filePath = path.join(SECRETS_DIR, fileName);

  const content = [
    'Infini Password Recovery',
    '',
    `Username: ${user.username}`,
    `New password: ${tempPassword}`,
    `Generated at: ${new Date().toISOString()}`,
    '',
    'Instructions: Use the password above to sign in at the login screen.',
    'Existing sessions (if any) were not revoked and will remain active until they expire or the user logs out.',
    'Delete this file after use for security.',
    '',
    'This file is only accessible to the server operator (0600 permissions).',
    'It is written under the data volume and persists across restarts.',
  ].join('\n');

  fs.writeFileSync(filePath, content, { mode: 0o600 });
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {
    // Best effort only; fs.writeFileSync already used restrictive mode above.
  }

  return { recoveryFile: filePath };
}
