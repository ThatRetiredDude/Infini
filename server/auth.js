import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { getOne, run } from './db.js';
import { sha256Hex } from './crypto.js';

const COOKIE_NAME = process.env.COOKIE_NAME || 'mi_session';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

const MIN_PASSWORD_LENGTH = 12;

function getJwtSecret() {
  const s = process.env.JWT_SECRET;
  if (!s || s.length < 32) {
    throw new Error('JWT_SECRET must be set and at least 32 characters.');
  }
  return s;
}

function cookieMaxAgeMs() {
  // Parse the same shape jsonwebtoken accepts ('7d', '30m', etc.) into ms.
  const m = String(JWT_EXPIRES_IN).match(/^(\d+)([smhd])$/);
  if (!m) return 7 * 24 * 60 * 60 * 1000;
  const n = Number(m[1]);
  const unit = m[2];
  const mult = unit === 's' ? 1000 : unit === 'm' ? 60_000 : unit === 'h' ? 3_600_000 : 86_400_000;
  return n * mult;
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
  if (!['user', 'journalist', 'admin'].includes(role)) {
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
    `INSERT INTO user_sessions (id, user_id, token_hash, user_agent, ip, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [sessionId, user.id, sha256Hex(token), userAgent || null, ip || null, expiresAt],
  );
  run(`UPDATE users SET last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`, [user.id]);
  return { token, sessionId, expiresAt };
}

export function revokeSession(sessionId) {
  run(
    `UPDATE user_sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`,
    [sessionId],
  );
}

/** Revoke all other sessions for this user (e.g. after password change). */
export function revokeOtherSessions(userId, exceptSessionId) {
  run(
    `UPDATE user_sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE user_id = ? AND id != ? AND revoked_at IS NULL`,
    [userId, exceptSessionId],
  );
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

export function getCookieOptions() {
  // Secure cookies only when COOKIE_SECURE=true. Default false so plain HTTP (e.g.
  // localhost Docker with NODE_ENV=production) still stores the session cookie.
  // Behind HTTPS terminating TLS, set COOKIE_SECURE=true in .env.
  const secure = process.env.COOKIE_SECURE === 'true';
  return {
    httpOnly: true,
    secure,
    sameSite: 'lax',
    maxAge: cookieMaxAgeMs(),
    domain: process.env.COOKIE_DOMAIN || undefined,
    path: '/',
  };
}

/**
 * Express middleware: parse cookie/bearer JWT and attach req.user.
 * Does NOT block unauthenticated requests by itself.
 */
export function attachUser(req, _res, next) {
  let token = null;
  if (req.cookies && req.cookies[COOKIE_NAME]) {
    token = req.cookies[COOKIE_NAME];
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

export const AUTH_COOKIE_NAME = COOKIE_NAME;
