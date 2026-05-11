#!/usr/bin/env node
// Creates the SQLite database file and applies the full schema. Safe to run
// repeatedly — every CREATE uses IF NOT EXISTS.

import 'dotenv/config';
import { ensureSchema } from '../schema.js';
import { closeDb } from '../db.js';

try {
  ensureSchema();
  // eslint-disable-next-line no-console
  console.log('[db-init] schema applied.');
  closeDb();
  process.exit(0);
} catch (err) {
  // eslint-disable-next-line no-console
  console.error('[db-init] failed:', err);
  process.exit(1);
}
