#!/usr/bin/env node
// Idempotently creates the seed admin from env vars if no admin exists.

import 'dotenv/config';
import { ensureSchema } from '../schema.js';
import { getOne, closeDb } from '../db.js';
import { createUser } from '../auth.js';

const USERNAME = process.env.SEED_ADMIN_USERNAME || 'admin';
const PASSWORD = process.env.SEED_ADMIN_PASSWORD;
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

  if (!PASSWORD) {
     
    console.error(
      '[seed-admin] no SEED_ADMIN_PASSWORD set and no admin exists in DB. Set the env var or create an admin manually.',
    );
    process.exitCode = 1;
    return;
  }

  const user = await createUser({
    username: USERNAME,
    email: EMAIL,
    password: PASSWORD,
    role: 'admin',
  });
   
  console.log(`[seed-admin] created admin '${user.username}' (${user.id}).`);
}

main()
  .catch((err) => {
     
    console.error('[seed-admin] failed:', err);
    process.exitCode = 1;
  })
  .finally(() => {
    closeDb();
  });
