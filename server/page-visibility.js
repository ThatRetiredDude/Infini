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

/**
 * Load current site branding (single row).
 * @returns {{brand_name: string, footer_text: string, accent_color: string}}
 */
export function loadBranding() {
  const rows = getAll(`SELECT brand_name, footer_text, accent_color FROM site_branding WHERE id=1 LIMIT 1`);
  return rows[0] || { brand_name: 'Infini', footer_text: 'Infini · MI', accent_color: '#34d399' };
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
publicRouter.get('/branding', (_req, res) => {
  res.json(loadBranding());
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

adminRouter.patch('/branding', (req, res) => {
  const body = req.body || {};
  const updates = [];
  const params = [];
  if (body.brand_name !== undefined) {
    const v = String(body.brand_name).trim();
    if (!v) return res.status(400).json({ error: 'invalid_brand_name' });
    updates.push('brand_name = ?');
    params.push(v);
  }
  if (body.footer_text !== undefined) {
    updates.push('footer_text = ?');
    params.push(String(body.footer_text));
  }
  if (body.accent_color !== undefined) {
    let v = String(body.accent_color);
    if (!/^#?[0-9a-fA-F]{6}$/.test(v)) return res.status(400).json({ error: 'invalid_accent_color' });
    if (!v.startsWith('#')) v = '#' + v;
    updates.push('accent_color = ?');
    params.push(v);
  }
  if (!updates.length) return res.status(400).json({ error: 'no_fields_to_update' });
  params.push(req.user?.id ?? null);
  run(
    `UPDATE site_branding SET ${updates.join(', ')}, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), updated_by = ? WHERE id=1`,
    params,
  );
  auditReq(req, {
    actionType: 'branding.update',
    targetType: 'site_branding',
    payload: { brand_name: body.brand_name, footer_text: body.footer_text, accent_color: body.accent_color },
  });
  res.json(loadBranding());
});

export { publicRouter as sitePublicRouter };
export { adminRouter as siteAdminRouter };
