import crypto from 'node:crypto';

const ALGO = 'aes-256-gcm';

function getKey() {
  const hex = process.env.INTEGRATION_ENCRYPTION_KEY;
  if (!hex) {
    throw new Error(
      'INTEGRATION_ENCRYPTION_KEY is not set. Generate one with `openssl rand -hex 32` and add it to .env.',
    );
  }
  const key = Buffer.from(hex, 'hex');
  if (key.length !== 32) {
    throw new Error('INTEGRATION_ENCRYPTION_KEY must be 32 bytes (64 hex chars).');
  }
  return key;
}

export function encryptJson(value) {
  const key = getKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const plaintext = Buffer.from(JSON.stringify(value), 'utf8');
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    payload_enc: enc.toString('base64'),
    iv: iv.toString('base64'),
    auth_tag: authTag.toString('base64'),
  };
}

export function decryptJson({ payload_enc, iv, auth_tag }) {
  const key = getKey();
  const decipher = crypto.createDecipheriv(ALGO, key, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(auth_tag, 'base64'));
  const enc = Buffer.from(payload_enc, 'base64');
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return JSON.parse(dec.toString('utf8'));
}

export function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

/**
 * Build a session-reference token shaped like MI2026-XXXX-XXXX-XXXX.
 * Used in access_log and injected into the SPA on each fallback request.
 */
export function buildAccessToken() {
  const year = new Date().getFullYear();
  const chunk = () =>
    crypto.randomBytes(2).toString('hex').toUpperCase();
  return `MI${year}-${chunk()}-${chunk()}-${chunk()}`;
}
