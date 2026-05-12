import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DEFAULT_DB_FILE = process.env.DATABASE_FILE
  || path.resolve(__dirname, '..', 'data', 'infinipot.sqlite');

let _db = null;

export function getDb() {
  if (_db) return _db;

  const dbPath = path.resolve(DEFAULT_DB_FILE);
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  _db = new Database(dbPath);
  _db.pragma('journal_mode = WAL');
  _db.pragma('foreign_keys = ON');
  _db.pragma('synchronous = NORMAL');
  _db.pragma('busy_timeout = 5000');

  return _db;
}

export function closeDb() {
  if (_db) {
    _db.close();
    _db = null;
  }
}

/**
 * Run a SQL statement and return the result.
 * For SELECT, returns rows; for INSERT/UPDATE/DELETE, returns `{ changes, lastInsertRowid }`.
 */
export function exec(sql) {
  return getDb().exec(sql);
}

export function prepare(sql) {
  return getDb().prepare(sql);
}

export function transaction(fn) {
  return getDb().transaction(fn);
}

/**
 * Convenience: returns the row that matches, or undefined.
 */
export function getOne(sql, params = []) {
  return prepare(sql).get(...(Array.isArray(params) ? params : [params]));
}

/**
 * Convenience: returns an array of rows.
 */
export function getAll(sql, params = []) {
  return prepare(sql).all(...(Array.isArray(params) ? params : [params]));
}

/**
 * Convenience: run an INSERT/UPDATE/DELETE and return { changes, lastInsertRowid }.
 */
export function run(sql, params = []) {
  return prepare(sql).run(...(Array.isArray(params) ? params : [params]));
}
