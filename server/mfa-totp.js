import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { generateSecret, generateURI, verifySync } from 'otplib';
import { getJwtSecret } from './auth.js';

/** ±1 TOTP step at default 30s period (otplib v11 authenticator.options.window = 1). */
const TOTP_EPOCH_TOLERANCE_SEC = 30;

function deriveTotpAesKey() {
  return crypto.createHash('sha256').update(`infini:totp:v1:${getJwtSecret()}`, 'utf8').digest();
}

export function sealTotpSecret(plainBase32) {
  const key = deriveTotpAesKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(String(plainBase32), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64')}:${tag.toString('base64')}:${enc.toString('base64')}`;
}

export function unsealTotpSecret(sealed) {
  const parts = String(sealed).split(':');
  if (parts.length !== 3) throw new Error('invalid_sealed_secret');
  const [ivB, tagB, encB] = parts;
  const key = deriveTotpAesKey();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB, 'base64'));
  const dec = Buffer.concat([decipher.update(Buffer.from(encB, 'base64')), decipher.final()]);
  return dec.toString('utf8');
}

export function generateTotpSecret() {
  return generateSecret();
}

export function verifyTotpCode(secretPlain, code) {
  const { valid } = verifySync({
    secret: secretPlain,
    token: String(code || '').replace(/\s/g, ''),
    epochTolerance: TOTP_EPOCH_TOLERANCE_SEC,
  });
  return valid;
}

export function buildOtpauthUrl({ secret, label, issuer = 'Infini' }) {
  return generateURI({ issuer, label, secret });
}

export function issueMfaTicket(userId) {
  return jwt.sign({ sub: userId, typ: 'mfa_pending' }, getJwtSecret(), { expiresIn: '5m' });
}

export function verifyMfaTicket(token) {
  const d = jwt.verify(String(token || ''), getJwtSecret());
  if (d.typ !== 'mfa_pending' || !d.sub) {
    throw new Error('invalid_mfa_ticket');
  }
  return { userId: d.sub };
}
