/**
 * Blog: public reads + admin CRUD. View counts via item_views.
 */

import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { getAll, getOne, run } from './db.js';
import { requireAdmin } from './auth.js';
import { auditReq } from './audit.js';
import { requirePageVisible } from './page-visibility.js';

const ITEM_TYPE_BLOG = 'blog_post';

function sanitizeSlug(slug) {
  return String(slug || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 160);
}

function incrementBlogViews(postId) {
  const now = new Date().toISOString();
  run(
    `INSERT INTO item_views (item_type, item_id, views, last_viewed_at)
     VALUES (?, ?, 1, ?)
     ON CONFLICT(item_type, item_id)
     DO UPDATE SET views = views + 1, last_viewed_at = excluded.last_viewed_at`,
    [ITEM_TYPE_BLOG, postId, now],
  );
}

async function webhookOnPublish(post) {
  const url =
    process.env.BLOG_PUBLISH_WEBHOOK_URL ||
    process.env.BLOG_DEPLOY_WEBHOOK_URL ||
    process.env.BLOG_CROSSPOST_WEBHOOK_URL;
  if (!url) return;

  let siteBase =
    process.env.PUBLIC_SITE_ORIGIN || process.env.PUBLIC_BASE_URL || process.env.PUBLIC_SITE_URL || '';
  if (siteBase) siteBase = String(siteBase).replace(/\/+$/, '');
  const link = siteBase ? `${siteBase}/blog/${post.slug}` : `/blog/${post.slug}`;

  const secret =
    process.env.BLOG_PUBLISH_WEBHOOK_SECRET ||
    process.env.BLOG_DEPLOY_WEBHOOK_TOKEN ||
    process.env.BLOG_CROSSPOST_WEBHOOK_TOKEN ||
    '';
  const headers = {
    'Content-Type': 'application/json',
    ...(secret ? { Authorization: `Bearer ${secret}` } : {}),
  };
  await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      slug: post.slug,
      title: post.title,
      excerpt: post.excerpt,
      url: link,
      published_at: post.published_at,
    }),
  }).catch(() => {});
}

/** @typedef {{ id: string, title: string, slug: string, excerpt?: string|null, cover_image_url?: string|null, published_at?: string|null }} PostRowLite */

/** @returns {express.Router} */
export function createBlogPublicRouter() {
  const r = Router();
  r.use(requirePageVisible('blog'));

  r.get('/posts', (req, res) => {
    const limit = Math.min(80, Math.max(1, Number(req.query.limit) || 40));
    const rows = getAll(
      `SELECT p.id, p.title, p.slug, p.excerpt, p.cover_image_url, p.published_at, p.updated_at,
              COALESCE(v.views, 0) AS views
         FROM blog_posts p
         LEFT JOIN item_views v ON v.item_type = ? AND v.item_id = p.id
        WHERE p.status = 'published'
        ORDER BY coalesce(datetime(p.published_at), datetime(p.updated_at)) DESC
        LIMIT ?`,
      [ITEM_TYPE_BLOG, limit],
    );
    res.json({
      posts: rows.map((p) => ({
        id: p.id,
        title: p.title,
        slug: p.slug,
        excerpt: p.excerpt,
        cover_image_url: p.cover_image_url,
        published_at: p.published_at,
        updated_at: p.updated_at,
        views: Number(p.views || 0),
      })),
    });
  });

  r.get('/posts/:slug', (req, res) => {
    const slug = String(req.params.slug || '').slice(0, 200);
    const post = getOne(
      `SELECT id, title, slug, excerpt, body, cover_image_url,
              published_at, updated_at, author_id,
              COALESCE(v.views, 0) AS views
         FROM blog_posts p
         LEFT JOIN item_views v ON v.item_type = ? AND v.item_id = p.id
        WHERE p.slug = ? AND p.status = 'published'
        LIMIT 1`,
      [ITEM_TYPE_BLOG, slug],
    );
    if (!post) return res.status(404).json({ error: 'not_found' });
    incrementBlogViews(post.id);
    res.json({
      post: {
        id: post.id,
        title: post.title,
        slug: post.slug,
        excerpt: post.excerpt,
        body: post.body,
        cover_image_url: post.cover_image_url,
        published_at: post.published_at,
        updated_at: post.updated_at,
        author_id: post.author_id,
        views: Number(post.views || 0) + 1,
      },
    });
  });

  return r;
}

/** @returns {express.Router} */
export function createBlogAdminRouter() {
  const r = Router();
  r.use(requireAdmin);

  r.get('/posts', (req, res) => {
    const status =
      typeof req.query.status === 'string' && ['draft', 'published', 'all'].includes(req.query.status)
        ? req.query.status
        : 'all';

    /** @type {string} */
    let where = '';
    const params = /** @type {unknown[]} */ ([]);
    if (status === 'draft') {
      where = `WHERE p.status = 'draft'`;
    } else if (status === 'published') {
      where = `WHERE p.status = 'published'`;
    }

    const rows = getAll(
      `SELECT p.*, COALESCE(v.views, 0) AS views
         FROM blog_posts p
         LEFT JOIN item_views v ON v.item_type = ? AND v.item_id = p.id
         ${where}
         ORDER BY datetime(p.updated_at) DESC`,
      [ITEM_TYPE_BLOG, ...params],
    );
    res.json({ posts: rows });
  });

  r.get('/posts/:id', (req, res) => {
    const post = getOne(`SELECT * FROM blog_posts WHERE id = ?`, [req.params.id]);
    if (!post) return res.status(404).json({ error: 'not_found' });
    const vw = getOne(
      `SELECT views FROM item_views WHERE item_type = ? AND item_id = ?`,
      [ITEM_TYPE_BLOG, post.id],
    );
    res.json({ post: { ...post, views: Number(vw?.views || 0) } });
  });

  r.post('/posts', (req, res) => {
    const {
      title,
      slug,
      excerpt = '',
      body = '',
      cover_image_url = null,
      status = 'draft',
      cross_post_to_blog = 0,
    } = req.body || {};
    if (!title || typeof title !== 'string') return res.status(400).json({ error: 'title_required' });
    const slugFinal = sanitizeSlug(slug || title);
    if (!slugFinal) return res.status(400).json({ error: 'invalid_slug' });

    const dupe = getOne(`SELECT id FROM blog_posts WHERE slug = ? COLLATE NOCASE LIMIT 1`, [slugFinal]);
    if (dupe) return res.status(409).json({ error: 'slug_conflict' });

    const id = uuidv4();
    const pub = status === 'published' ? new Date().toISOString() : null;
    run(
      `INSERT INTO blog_posts
       (id, title, slug, excerpt, body, cover_image_url, author_id,
        status, published_at, cross_post_to_blog, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
      [
        id,
        title,
        slugFinal,
        excerpt ?? '',
        typeof body === 'string' ? body : '',
        cover_image_url || null,
        req.user?.id ?? null,
        status === 'published' ? 'published' : 'draft',
        pub,
        cross_post_to_blog ? 1 : 0,
      ],
    );
    auditReq(req, {
      actionType: 'blog.create',
      targetType: 'blog_post',
      targetId: id,
      payload: { slug: slugFinal, status },
    });
    if (status === 'published' && pub) {
      webhookOnPublish({
        title,
        slug: slugFinal,
        excerpt,
        published_at: pub,
      }).catch(() => {});
    }

    const post = getOne(`SELECT * FROM blog_posts WHERE id = ?`, [id]);
    res.status(201).json({ post });
  });

  r.put('/posts/:id', (req, res) => {
    const existing = getOne(`SELECT * FROM blog_posts WHERE id = ?`, [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'not_found' });

    const {
      title,
      slug,
      excerpt,
      body,
      cover_image_url,
      status,
      cross_post_to_blog,
    } = req.body || {};

    let slugFinal = existing.slug;
    if (slug != null && slug !== '') {
      slugFinal = sanitizeSlug(slug);
      if (!slugFinal) return res.status(400).json({ error: 'invalid_slug' });
      const dupe = getOne(
        `SELECT id FROM blog_posts WHERE slug = ? COLLATE NOCASE AND id != ? LIMIT 1`,
        [slugFinal, existing.id],
      );
      if (dupe) return res.status(409).json({ error: 'slug_conflict' });
    }

    const titleFinal = typeof title === 'string' ? title : existing.title;
    const excerptFinal = typeof excerpt === 'string' ? excerpt : existing.excerpt;
    const bodyFinal = typeof body === 'string' ? body : existing.body;
    const cov =
      typeof cover_image_url !== 'undefined' ? cover_image_url || null : existing.cover_image_url;

    /** @type {string} */
    let statusFinal = existing.status;
    if (typeof status === 'string' && ['draft', 'published'].includes(status)) statusFinal = status;

    const crossFinal =
      typeof cross_post_to_blog === 'number' ? (cross_post_to_blog ? 1 : 0) : existing.cross_post_to_blog;

    let publishedFinal = existing.published_at;
    if (statusFinal === 'published' && !publishedFinal)
      publishedFinal = new Date().toISOString();
    if (statusFinal === 'draft') publishedFinal = null;

    run(
      `UPDATE blog_posts SET
       title = ?, slug = ?, excerpt = ?, body = ?, cover_image_url = ?,
       status = ?, published_at = ?, cross_post_to_blog = ?,
       updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
       WHERE id = ?`,
      [
        titleFinal,
        slugFinal,
        excerptFinal,
        bodyFinal,
        cov,
        statusFinal,
        publishedFinal,
        crossFinal,
        existing.id,
      ],
    );
    auditReq(req, {
      actionType: 'blog.update',
      targetType: 'blog_post',
      targetId: existing.id,
      payload: { status: statusFinal, slug: slugFinal },
    });

    const refreshed = getOne(`SELECT * FROM blog_posts WHERE id = ?`, [existing.id]);

    const wasPublished = existing.status === 'published';
    if (statusFinal === 'published' && !wasPublished && publishedFinal && refreshed)
      webhookOnPublish({
        title: refreshed.title,
        slug: refreshed.slug,
        excerpt: refreshed.excerpt,
        published_at: publishedFinal,
      }).catch(() => {});

    res.json({ post: refreshed });
  });

  r.delete('/posts/:id', (req, res) => {
    const existing = getOne(`SELECT id, slug FROM blog_posts WHERE id = ?`, [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'not_found' });

    run(`DELETE FROM blog_posts WHERE id = ?`, [existing.id]);
    run(`DELETE FROM item_views WHERE item_type = ? AND item_id = ?`, [ITEM_TYPE_BLOG, existing.id]);
    auditReq(req, {
      actionType: 'blog.delete',
      targetType: 'blog_post',
      targetId: existing.id,
      payload: { slug: existing.slug },
    });
    res.json({ ok: true });
  });

  return r;
}
