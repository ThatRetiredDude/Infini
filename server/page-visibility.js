/**
 * Minimal page visibility: home, blog, donations.
 */

import { Router } from 'express';
import { getAll, run } from './db.js';
import { requireAdmin } from './auth.js';
import { auditReq } from './audit.js';

export const PAGE_KEYS = /** @type {const} */ (['home', 'blog', 'donations']);

/**
 * @returns {Record<string, string>}
 */
export function loadVisibilityMap() {
  const rows = getAll(`SELECT page_key, visibility FROM page_visibility`);
  const map = /** @type {Record<string, string>} */ ({
    home: 'public',
    blog: 'public',
    donations: 'public',
  });
  for (const r of rows) {
    map[r.page_key] = r.visibility;
  }
  return map;
}

/** @param {Express.Request['user']} user */
export function pageVisibleToUser(pageKey, user) {
  const v = loadVisibilityMap()[pageKey] || 'public';
  const admin = Boolean(user && (user.role === 'admin' || user.is_admin));
  if (v === 'public') return true;
  if (v === 'hidden') return admin;
  if (v === 'admin_only') return admin;
  return true;
}

export function requirePageVisible(pageKey) {
  return (req, res, next) => {
    if (!pageVisibleToUser(pageKey, req.user))
      return res.status(404).json({ error: 'not_found' });
    next();
  };
}

const publicRouter = Router();
publicRouter.get('/visibility', (_req, res) => {
  res.json({ pages: loadVisibilityMap() });
});

const adminRouter = Router();
adminRouter.use(requireAdmin);

adminRouter.patch('/visibility', (req, res) => {
  const body = req.body?.pages ?? req.body?.visibility ?? req.body ?? {};
  if (!body || typeof body !== 'object')
    return res.status(400).json({ error: 'invalid_payload' });

  /** @type {string[]} */
  const updatedKeys = [];

  for (const key of PAGE_KEYS) {
    if (!(key in body)) continue;
    const v = String(body[key]);
    if (!['public', 'hidden', 'admin_only'].includes(v)) {
      return res.status(400).json({ error: 'invalid_visibility', key });
    }
    run(
      `UPDATE page_visibility SET visibility = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), updated_by = ?
       WHERE page_key = ?`,
      [v, req.user?.id ?? null, key],
    );
    updatedKeys.push(key);
  }

  auditReq(req, {
    actionType: 'visibility.update',
    targetType: 'page_visibility',
    payload: updatedKeys.reduce((acc, k) => ({ ...acc, [k]: body[k] }), {}),
  });

  res.json({ pages: loadVisibilityMap(), updated: updatedKeys });
});

export { publicRouter as sitePublicRouter };
export { adminRouter as siteAdminRouter };
