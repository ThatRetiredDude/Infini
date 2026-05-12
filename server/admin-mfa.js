/**
 * TOTP MFA enrollment + status for administrators (Security hub).
 */

import { Router } from 'express';
import { run } from './db.js';
import { requireAdmin, findUserById, verifyPassword } from './auth.js';
import {
  sealTotpSecret,
  unsealTotpSecret,
  generateTotpSecret,
  verifyTotpCode,
  buildOtpauthUrl,
} from './mfa-totp.js';
import { auditReq } from './audit.js';

const router = Router();
router.use(requireAdmin);

router.get('/status', (req, res) => {
  const user = findUserById(req.user.id);
  if (!user) return res.status(404).json({ error: 'user_not_found' });
  res.json({
    totp_enabled: !!user.totp_enabled,
    enroll_pending: !!(user.totp_pending_sealed && !user.totp_enabled),
  });
});

router.post('/enroll-start', (req, res) => {
  const user = findUserById(req.user.id);
  if (!user) return res.status(404).json({ error: 'user_not_found' });
  if (user.totp_enabled) return res.status(400).json({ error: 'totp_already_enabled' });

  const secret = generateTotpSecret();
  const sealed = sealTotpSecret(secret);
  run(`UPDATE users SET totp_pending_sealed = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`, [
    sealed,
    user.id,
  ]);

  const issuer =
    (process.env.MFA_ISSUER || process.env.PUBLIC_SITE_ORIGIN || 'Infini')
      .replace(/^https?:\/\//, '')
      .replace(/\/$/, '') || 'Infini';
  const otpauth_url = buildOtpauthUrl({ secret, label: user.username, issuer });

  auditReq(req, { actionType: 'auth.mfa_enroll_start' });
  res.json({ otpauth_url, manual_entry_key: secret });
});

router.post('/enroll-verify', (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ error: 'code_required' });

  const user = findUserById(req.user.id);
  if (!user?.totp_pending_sealed) {
    return res.status(400).json({ error: 'no_pending_enrollment' });
  }

  let secretPlain;
  try {
    secretPlain = unsealTotpSecret(user.totp_pending_sealed);
  } catch {
    return res.status(500).json({ error: 'totp_unseal_failed' });
  }

  if (!verifyTotpCode(secretPlain, code)) {
    return res.status(401).json({ error: 'invalid_totp_code' });
  }

  const pending = user.totp_pending_sealed;
  run(
    `UPDATE users SET totp_enabled = 1, totp_secret_sealed = ?, totp_pending_sealed = NULL,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE id = ?`,
    [pending, user.id],
  );

  auditReq(req, { actionType: 'auth.mfa_enroll_complete' });
  res.json({ ok: true });
});

router.post('/enroll-cancel', (req, res) => {
  run(`UPDATE users SET totp_pending_sealed = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`, [
    req.user.id,
  ]);
  auditReq(req, { actionType: 'auth.mfa_enroll_cancel' });
  res.json({ ok: true });
});

router.post('/disable', async (req, res) => {
  const { password, code } = req.body || {};
  if (!password || !code) return res.status(400).json({ error: 'password_and_code_required' });

  const user = findUserById(req.user.id);
  if (!user?.totp_enabled || !user.totp_secret_sealed) {
    return res.status(400).json({ error: 'totp_not_enabled' });
  }

  const pwdOk = await verifyPassword(String(password), user.password_hash);
  if (!pwdOk) return res.status(401).json({ error: 'invalid_password' });

  let secretPlain;
  try {
    secretPlain = unsealTotpSecret(user.totp_secret_sealed);
  } catch {
    return res.status(500).json({ error: 'totp_unseal_failed' });
  }

  if (!verifyTotpCode(secretPlain, code)) {
    return res.status(401).json({ error: 'invalid_totp_code' });
  }

  run(
    `UPDATE users SET totp_enabled = 0, totp_secret_sealed = NULL, totp_pending_sealed = NULL,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE id = ?`,
    [user.id],
  );

  auditReq(req, { actionType: 'auth.mfa_disabled' });
  res.json({ ok: true });
});

export default router;
