#!/usr/bin/env node
// Idempotently creates the seed admin from env vars if no admin exists.

import 'dotenv/config';
import { ensureSchema } from '../schema.js';
import { getOne, closeDb, run } from '../db.js';
import { createUser, hashPassword } from '../auth.js';

/** Public, documented bootstrap only when SEED_ADMIN_PASSWORD is unset — user must rotate on first sign-in. */
const DOCUMENTED_BOOTSTRAP_PASSWORD = 'ChangeMeImmediately!';

const USERNAME = process.env.SEED_ADMIN_USERNAME || 'admin';
const EMAIL = process.env.SEED_ADMIN_EMAIL || null;

const OVERWRITE_EXISTING_PASSWORD =
  process.env.SEED_ADMIN_OVERWRITE_PASSWORD === '1' ||
  process.env.SEED_ADMIN_OVERWRITE_PASSWORD === 'true';

async function main() {
  ensureSchema();

  const existingAdmin = getOne(
    `SELECT id, username FROM users WHERE role = 'admin' OR is_admin = 1 LIMIT 1`,
  );

  const trimmed = typeof process.env.SEED_ADMIN_PASSWORD === 'string'
    ? process.env.SEED_ADMIN_PASSWORD.trim()
    : '';
  let password = trimmed || DOCUMENTED_BOOTSTRAP_PASSWORD;
  if (!trimmed) {
    console.warn(
      '[seed-admin] SEED_ADMIN_PASSWORD not set — using documented bootstrap password (see README). Set SEED_ADMIN_PASSWORD to choose a different initial secret.',
    );
  }

  if (existingAdmin) {
    if (OVERWRITE_EXISTING_PASSWORD) {
      const hash = await hashPassword(password);
      run(
        `UPDATE users SET password_hash = ?, password_change_required = 1,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ?`,
        [hash, existingAdmin.id],
      );
      console.warn(
        `[seed-admin] reset password for admin '${existingAdmin.username}' (${existingAdmin.id}) — SEED_ADMIN_OVERWRITE_PASSWORD was set.`,
      );
      return;
    }

    console.log(`[seed-admin] admin already exists: ${existingAdmin.username}. Nothing to do.`);
    return;
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
