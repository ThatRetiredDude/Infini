/**
 * AI input guard related admin routes (manual disable / restore).
 * Mounted at /api/admin/ai-flags (not overlapping /api/admin/security/ai-flags).
 */

import { Router } from 'express';
import { getAll, run } from './db.js';
import { requireAdmin } from './auth.js';
import { auditReq } from './audit.js';

const router = Router();
router.use(requireAdmin);

router.get('/disabled-users', (_req, res) => {
  const users = getAll(
    `SELECT id, username, email, role, ai_disabled, ai_disabled_at, ai_disabled_reason
     FROM users WHERE ai_disabled = 1 ORDER BY ai_disabled_at DESC`,
  ).map((u) => ({ ...u, ai_disabled: !!u.ai_disabled }));
  res.json({ users });
});

router.post('/users/:id/restore', (req, res) => {
  const targetId = String(req.params.id || '').trim();
  if (!targetId) return res.status(400).json({ error: 'user id required' });
  const result = run(
    `UPDATE users SET ai_disabled = 0, ai_disabled_at = NULL, ai_disabled_reason = NULL WHERE id = ?`,
    [targetId],
  );
  if (result.changes === 0) return res.status(404).json({ error: 'user_not_found' });
  auditReq(req, {
    actionType: 'ai_access_restored',
    targetType: 'user',
    targetId,
    payload: { reason: req.body?.reason || null },
  });
  res.json({ ok: true });
});

router.post('/users/:id/disable', (req, res) => {
  const targetId = String(req.params.id || '').trim();
  if (!targetId) return res.status(400).json({ error: 'user id required' });
  const reason = String(
    req.body?.reason || `Manually disabled by ${req.user?.username || 'admin'}`,
  ).slice(0, 500);
  const result = run(
    `UPDATE users SET ai_disabled = 1,
        ai_disabled_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
        ai_disabled_reason = ?
      WHERE id = ?`,
    [reason, targetId],
  );
  if (result.changes === 0) return res.status(404).json({ error: 'user_not_found' });
  auditReq(req, {
    actionType: 'ai_access_disabled',
    targetType: 'user',
    targetId,
    payload: { reason },
  });
  res.json({ ok: true });
});

export default router;
