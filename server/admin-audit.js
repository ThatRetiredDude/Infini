/**
 * Paginated audit log listing for admins.
 */

import { Router } from 'express';
import { requireAdmin } from './auth.js';
import { getAll, getOne } from './db.js';

const router = Router();
router.use(requireAdmin);

router.get('/', (req, res) => {
  const limitRaw = Number(req.query.limit);
  const limit = Math.min(100, Math.max(5, Number.isFinite(limitRaw) ? limitRaw : 50));
  let afterId = req.query.after;
  /** @type {unknown[]} */
  const params = [limit];

  let whereClause = '';
  if (afterId !== undefined && afterId !== '') {
    const ai = Number(afterId);
    if (!Number.isFinite(ai)) return res.status(400).json({ error: 'invalid_after' });
    whereClause = 'WHERE id < ?';
    params.unshift(ai);
  }

  /** @format string */
  const sql = `
    SELECT id, action_type AS actionType, actor_id AS actorId, actor_username AS actorUsername,
           target_type AS targetType, target_id AS targetId, payload,
           ip, user_agent AS userAgent, created_at AS createdAt
      FROM audit_log
      ${whereClause}
      ORDER BY id DESC
      LIMIT ?
  `.trim();

  const rows = getAll(sql, params);
  /** @format string */
  const nextCursor =
    rows.length >= limit ? String(rows[rows.length - 1].id ?? '') : null;

  let totalApprox = Number(getOne(`SELECT COUNT(*) AS c FROM audit_log`)?.c ?? 0);

  res.json({ entries: rows, next_cursor: nextCursor, total_approx: totalApprox });
});

export default router;
