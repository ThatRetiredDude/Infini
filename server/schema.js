// All SQLite schema lives here. Tables are created idempotently at boot via
// `ensureSchema(db)`. SQLite uses INTEGER PRIMARY KEY for autoincrementing IDs,
// TEXT for UUIDs (we generate them in JS), and JSON columns are stored as TEXT
// (we json_decode in code). Booleans are stored as 0/1 integers.

import { getDb } from './db.js';

const STATEMENTS = [
  // ─── users + sessions ──────────────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','journalist','admin')),
    is_admin INTEGER NOT NULL DEFAULT 0,
    ai_disabled INTEGER NOT NULL DEFAULT 0,
    ai_disabled_at TEXT,
    ai_disabled_reason TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_login_at TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)`,

  `CREATE TABLE IF NOT EXISTS user_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    user_agent TEXT,
    ip TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at TEXT NOT NULL,
    revoked_at TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at)`,

  // ─── audit log ─────────────────────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_type TEXT NOT NULL,
    actor_id TEXT,
    actor_username TEXT,
    target_type TEXT,
    target_id TEXT,
    payload TEXT,
    ip TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  )`,
  `CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action_type, created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_id, created_at DESC)`,

  // ─── app-wide settings (key/value, JSON values) ────────────────────────────
  `CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_by TEXT
  )`,

  // ─── encrypted integration credentials ─────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS integration_credentials (
    service TEXT PRIMARY KEY,
    payload_enc TEXT NOT NULL,
    iv TEXT NOT NULL,
    auth_tag TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_tested_at TEXT,
    last_test_ok INTEGER,
    last_test_message TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_by TEXT
  )`,

  // ─── access_log (replaces mi_access_log) ───────────────────────────────────
  // Every public page load and beacon hit. token = MI<year>-XXXX-XXXX-XXXX or NULL.
  `CREATE TABLE IF NOT EXISTS access_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    user_agent TEXT,
    referer TEXT,
    token TEXT,
    path TEXT,
    hit_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  )`,
  `CREATE INDEX IF NOT EXISTS idx_access_log_ip ON access_log(ip, hit_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_access_log_token ON access_log(token)`,
  `CREATE INDEX IF NOT EXISTS idx_access_log_hit_at ON access_log(hit_at DESC)`,

  // ─── ai_honeypot_hits ─────────────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS ai_honeypot_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hit_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    ip TEXT,
    ua TEXT,
    referer TEXT,
    path TEXT,
    method TEXT,
    body_hash TEXT,
    body_excerpt TEXT,
    headers_excerpt TEXT,
    token TEXT,
    source TEXT NOT NULL,
    enrichment TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS idx_honeypot_hit_at ON ai_honeypot_hits(hit_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_honeypot_ip ON ai_honeypot_hits(ip, hit_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_honeypot_source ON ai_honeypot_hits(source, hit_at DESC)`,

  // ─── maze_hits (tarpit aggregation, per IP per day) ────────────────────────
  `CREATE TABLE IF NOT EXISTS maze_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    ua TEXT,
    date TEXT NOT NULL,
    first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    hit_count INTEGER NOT NULL DEFAULT 1,
    max_depth INTEGER NOT NULL DEFAULT 0,
    paths_visited TEXT,
    self_id_token TEXT,
    self_id_raw TEXT,
    enrichment TEXT,
    UNIQUE(ip, date)
  )`,
  `CREATE INDEX IF NOT EXISTS idx_maze_ip ON maze_hits(ip)`,
  `CREATE INDEX IF NOT EXISTS idx_maze_date ON maze_hits(date)`,
  `CREATE INDEX IF NOT EXISTS idx_maze_self_id ON maze_hits(self_id_token) WHERE self_id_token IS NOT NULL`,

  // ─── ai_input_flags ───────────────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS ai_input_flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    username TEXT,
    route TEXT NOT NULL,
    channel TEXT,
    path TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('low','medium','high')),
    reasons TEXT NOT NULL,
    input_excerpt TEXT,
    ip TEXT,
    ua TEXT,
    action_taken TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  )`,
  `CREATE INDEX IF NOT EXISTS idx_ai_flags_user ON ai_input_flags(user_id, created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_ai_flags_severity ON ai_input_flags(severity, created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_ai_flags_ip ON ai_input_flags(ip)`,

  // ─── ai_quota_log ─────────────────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS ai_quota_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    feature TEXT NOT NULL,
    tokens_in INTEGER,
    tokens_out INTEGER,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  )`,
  `CREATE INDEX IF NOT EXISTS idx_ai_quota ON ai_quota_log(user_id, feature, created_at DESC)`,

  // ─── ai_log_reviews (repurposed entity_briefs) ────────────────────────────
  // Stores AI-generated reviews of log events / honeypot hits / alerts. The
  // user picks a set of log rows in the admin UI and the AI returns a
  // structured analysis + suggested actions.
  `CREATE TABLE IF NOT EXISTS ai_log_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    review_type TEXT NOT NULL CHECK (review_type IN ('honeypot','maze','access','ai_flag','alert','mixed')),
    selection TEXT NOT NULL,
    summary_md TEXT,
    suggested_actions TEXT,
    model TEXT,
    raw_response TEXT,
    generated_by TEXT,
    generated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at TEXT,
    pinned INTEGER NOT NULL DEFAULT 0
  )`,
  `CREATE INDEX IF NOT EXISTS idx_log_reviews_generated_at ON ai_log_reviews(generated_at DESC)`,

  // ─── ai_log_review_request_logs ───────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS ai_log_review_request_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL,
    route TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running','succeeded','failed')),
    user_id TEXT,
    username TEXT,
    role TEXT,
    review_type TEXT,
    selection_summary TEXT,
    request_payload TEXT,
    response_payload TEXT,
    model TEXT,
    cached INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    total_tokens INTEGER,
    cost_usd_ticks INTEGER,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    finished_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  )`,
  `CREATE INDEX IF NOT EXISTS idx_log_review_requests ON ai_log_review_request_logs(created_at DESC)`,

  // ─── security_alert_rules + deliveries ────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS security_alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('ai_flags','access_log','honeypot','maze')),
    predicate TEXT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('email','discord','telegram','webhook')),
    recipient TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    cooldown_min INTEGER NOT NULL DEFAULT 5,
    last_fired_at TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  )`,
  `CREATE TABLE IF NOT EXISTS security_alert_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL REFERENCES security_alert_rules(id) ON DELETE CASCADE,
    fired_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    payload_excerpt TEXT,
    ok INTEGER NOT NULL DEFAULT 0,
    error TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS idx_alert_deliveries_rule ON security_alert_deliveries(rule_id, fired_at DESC)`,

  // ─── blog_posts (renamed from news_posts) ─────────────────────────────────
  `CREATE TABLE IF NOT EXISTS blog_posts (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    excerpt TEXT,
    body TEXT NOT NULL DEFAULT '',
    cover_image_url TEXT,
    author_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published')),
    published_at TEXT,
    cross_post_to_blog INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  )`,
  `CREATE INDEX IF NOT EXISTS idx_blog_posts_slug ON blog_posts(slug)`,
  `CREATE INDEX IF NOT EXISTS idx_blog_posts_published ON blog_posts(published_at DESC) WHERE status='published'`,

  // ─── carousel_items ───────────────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS carousel_items (
    id TEXT PRIMARY KEY,
    item_type TEXT NOT NULL CHECK (item_type IN ('video','social','link')),
    title TEXT NOT NULL,
    body TEXT,
    url TEXT NOT NULL,
    thumbnail_url TEXT,
    display_at TEXT,
    pinned INTEGER NOT NULL DEFAULT 0,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  )`,
  `CREATE INDEX IF NOT EXISTS idx_carousel_pinned ON carousel_items(pinned DESC, sort_order ASC, display_at DESC)`,

  // ─── item_views (per-post view counts) ────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS item_views (
    item_type TEXT NOT NULL,
    item_id TEXT NOT NULL,
    views INTEGER NOT NULL DEFAULT 0,
    last_viewed_at TEXT,
    PRIMARY KEY (item_type, item_id)
  )`,
];

export function ensureSchema() {
  const db = getDb();
  const tx = db.transaction(() => {
    for (const stmt of STATEMENTS) {
      db.exec(stmt);
    }
  });
  tx();
}
