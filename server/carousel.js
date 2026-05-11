/**
 * Homepage carousel tiles — public list + admin CRUD.
 */

import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { getAll, getOne, run } from './db.js';
import { requireAdmin } from './auth.js';
import { auditReq } from './audit.js';
import { requirePageVisible } from './page-visibility.js';

/** @returns {express.Router} */
export function createCarouselPublicRouter() {
  const r = Router();
  r.use(requirePageVisible('home'));

  r.get('/', (_req, res) => {
    const items = getAll(
      `SELECT id, item_type AS type, title, body, url, thumbnail_url,
              display_at, pinned, sort_order, created_at, updated_at
         FROM carousel_items
         ORDER BY pinned DESC,
                  sort_order ASC,
                  CASE WHEN display_at IS NULL THEN 1 ELSE 0 END,
                  datetime(display_at) DESC,
                  datetime(updated_at) DESC`,
    );
    res.json({ items });
  });

  return r;
}

/** @returns {express.Router} */
export function createCarouselAdminRouter() {
  const r = Router();
  r.use(requireAdmin);

  r.get('/items', (_req, res) => {
    const items = getAll(
      `SELECT * FROM carousel_items
        ORDER BY pinned DESC,
                 sort_order ASC,
                 CASE WHEN display_at IS NULL THEN 1 ELSE 0 END,
                 datetime(display_at) DESC`,
    );
    res.json({ items });
  });

  r.post('/items', (req, res) => {
    const body = req.body || {};
    const type = ['video', 'social', 'link'].includes(body.type || body.item_type)
      ? body.type || body.item_type
      : null;
    if (!type || !body.title || !body.url)
      return res.status(400).json({ error: 'type_title_url_required' });

    const id = uuidv4();
    run(
      `INSERT INTO carousel_items (
        id, item_type, title, body, url, thumbnail_url, display_at, pinned, sort_order,
        created_by, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
      [
        id,
        type,
        String(body.title).slice(0, 512),
        body.body ? String(body.body).slice(0, 8192) : null,
        String(body.url).slice(0, 2048),
        body.thumbnail_url ? String(body.thumbnail_url).slice(0, 2048) : null,
        body.display_at ? String(body.display_at) : null,
        body.pinned ? 1 : 0,
        Number(body.sort_order) || 0,
        req.user?.id ?? null,
      ],
    );
    auditReq(req, {
      actionType: 'carousel.create',
      targetType: 'carousel_item',
      targetId: id,
    });

    const row = getOne(`SELECT * FROM carousel_items WHERE id = ?`, [id]);
    res.status(201).json({ item: row });
  });

  r.put('/items/:id', (req, res) => {
    const existing = getOne(`SELECT * FROM carousel_items WHERE id = ?`, [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'not_found' });

    const b = req.body || {};
    const type = ['video', 'social', 'link'].includes(b.type || b.item_type)
      ? b.type || b.item_type
      : existing.item_type;
    run(
      `UPDATE carousel_items SET
        item_type = ?, title = ?, body = ?, url = ?, thumbnail_url = ?,
        display_at = ?, pinned = ?, sort_order = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
       WHERE id = ?`,
      [
        type,
        typeof b.title === 'string' ? b.title.slice(0, 512) : existing.title,
        typeof b.body === 'string' ? b.body.slice(0, 8192) : existing.body,
        typeof b.url === 'string' ? b.url.slice(0, 2048) : existing.url,
        typeof b.thumbnail_url === 'undefined' ? existing.thumbnail_url : b.thumbnail_url || null,
        typeof b.display_at === 'undefined' ? existing.display_at : b.display_at || null,
        typeof b.pinned === 'undefined' ? existing.pinned : b.pinned ? 1 : 0,
        typeof b.sort_order === 'number' ? b.sort_order : existing.sort_order,
        existing.id,
      ],
    );
    auditReq(req, {
      actionType: 'carousel.update',
      targetType: 'carousel_item',
      targetId: existing.id,
    });
    res.json({ item: getOne(`SELECT * FROM carousel_items WHERE id = ?`, [existing.id]) });
  });

  r.delete('/items/:id', (req, res) => {
    const existing = getOne(`SELECT id FROM carousel_items WHERE id = ?`, [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'not_found' });
    run(`DELETE FROM carousel_items WHERE id = ?`, [existing.id]);
    auditReq(req, {
      actionType: 'carousel.delete',
      targetType: 'carousel_item',
      targetId: existing.id,
    });
    res.json({ ok: true });
  });

  return r;
}
