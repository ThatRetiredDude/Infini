#!/usr/bin/env node
/**
 * InfiniPot smoke checks (no auth). Run with the API listening on SMOKE_BASE.
 * Example: SMOKE_BASE=http://127.0.0.1:3000 node server/scripts/smoke-check.mjs
 */

const base = process.env.SMOKE_BASE || `http://127.0.0.1:${process.env.PORT || 3000}`;

const paths = [
  ['/api/health', (j) => j?.ok === true && j?.service === 'infinipot'],
  ['/api/site/visibility', (j) => j?.pages?.home && j?.pages?.blog],
  ['/api/blog/posts', (j) => Array.isArray(j?.posts)],
  ['/api/carousel', (j) => Array.isArray(j?.items)],
];

async function hit(path) {
  const res = await fetch(`${base.replace(/\/+$/, '')}${path}`);
  let body = null;
  const text = await res.text();
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = { raw: text };
  }
  return { res, body };
}

async function main() {
  let failed = 0;
  for (const [path, pred] of paths) {
    try {
      const { res, body } = await hit(path);
      if (!res.ok) {
        console.error(`FAIL ${path}: HTTP ${res.status}`);
        failed += 1;
        continue;
      }
      if (!pred(body)) {
        console.error(`FAIL ${path}: unexpected JSON`, body);
        failed += 1;
        continue;
      }
      console.log(`ok  ${path}`);
    } catch (e) {
      console.error(`FAIL ${path}: ${e?.message || e}`);
      failed += 1;
    }
  }
  if (failed) {
    console.error(`\nSmoke: ${failed} check(s) failed (is the server running?).`);
    process.exit(1);
  }
  console.log('\nSmoke: all checks passed.');
}

main();
