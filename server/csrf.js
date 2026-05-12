import crypto from 'node:crypto';
import { CSRF_COOKIE_NAME } from './auth.js';

const EXEMPT = new Set(['/api/auth/login', '/api/auth/mfa/totp-verify']);

function timingEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

/**
 * Double-submit CSRF for cookie-based sessions. Bearer-only clients skip (no CSRF cookie).
 */
export function csrfProtection(req, res, next) {
  const m = req.method.toUpperCase();
  if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return next();
  if (!req.path.startsWith('/api/')) return next();
  if (EXEMPT.has(req.path)) return next();
  if (!req.user) return next();
  if (!req.authViaCookie) return next();

  const cookieTok = req.cookies?.[CSRF_COOKIE_NAME] || '';
  const headerTok = req.get('x-csrf-token') || '';
  const sessionTok = req.sessionCsrf || '';
  if (!timingEqual(cookieTok, headerTok) || !timingEqual(headerTok, sessionTok)) {
    return res.status(403).json({ error: 'csrf_invalid' });
  }
  next();
}
