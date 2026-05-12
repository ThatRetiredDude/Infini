#!/usr/bin/env node
// Idempotently creates the seed admin from env vars if no admin exists.

import 'dotenv/config';
import { ensureSchema } from '../schema.js';
import { getOne, closeDb } from '../db.js';
import { createUser } from '../auth.js';

/** Public, documented bootstrap only when SEED_ADMIN_PASSWORD is unset — user must rotate on first sign-in. */
const DOCUMENTED_BOOTSTRAP_PASSWORD = 'ChangeMeImmediately!';

const USERNAME = process.env.SEED_ADMIN_USERNAME || 'admin';
const EMAIL = process.env.SEED_ADMIN_EMAIL || null;

async function main() {
  ensureSchema();

  const existingAdmin = getOne(
    `SELECT id, username FROM users WHERE role = 'admin' OR is_admin = 1 LIMIT 1`,
  );
  if (existingAdmin) {
    console.log(`[seed-admin] admin already exists: ${existingAdmin.username}. Nothing to do.`);
    return;
  }

  const trimmed = typeof process.env.SEED_ADMIN_PASSWORD === 'string'
    ? process.env.SEED_ADMIN_PASSWORD.trim()
    : '';
  let password = trimmed;
  if (!password) {
    password = DOCUMENTED_BOOTSTRAP_PASSWORD;
    console.warn(
      '[seed-admin] SEED_ADMIN_PASSWORD not set — using documented bootstrap password (see README). Set SEED_ADMIN_PASSWORD to choose a different initial secret.',
    );
  }

  const user = await createUser({
    username: USERNAME,
    email: EMAIL,
    password,
    role: 'admin',
    passwordChangeRequired: true,
  });

  console.log(`[seed-admin] created admin '${user.username}' (${user.id}). Password change required on first sign-in.`);
}

main()
  .catch((err) => {
    console.error('[seed-admin] failed:', err);
    process.exitCode = 1;
  })
  .finally(() => {
    closeDb();
  });
