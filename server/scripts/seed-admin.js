#!/usr/bin/env node
// Idempotently creates the seed admin from env vars if no admin exists.

import crypto from 'node:crypto';
import 'dotenv/config';
import { ensureSchema } from '../schema.js';
import { getOne, closeDb } from '../db.js';
import { createUser } from '../auth.js';

const USERNAME = process.env.SEED_ADMIN_USERNAME || 'admin';
const EMAIL = process.env.SEED_ADMIN_EMAIL || null;

function randomBootstrapPassword() {
  return crypto.randomBytes(18).toString('base64url');
}

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
    password = randomBootstrapPassword();
    console.warn(
      '[seed-admin] SEED_ADMIN_PASSWORD not set — generated one-time bootstrap password. Copy it now; logs may be visible to host operators.',
    );
    console.warn(`[seed-admin] BOOTSTRAP_PASSWORD=${password}`);
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
