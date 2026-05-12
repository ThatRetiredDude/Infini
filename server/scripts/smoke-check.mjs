#!/usr/bin/env node
/**
 * Infini smoke checks (no auth). Run with the API listening on SMOKE_BASE.
 * Example: SMOKE_BASE=http://127.0.0.1:3000 node server/scripts/smoke-check.mjs
 */

const base = process.env.SMOKE_BASE || `http://127.0.0.1:${process.env.PORT || 3000}`;

const checks = [
  {
    path: '/api/health',
    expectStatus: 200,
    expectJson: (j) => j?.ok === true && j?.service === 'infini' && typeof j?.cowrie === 'object',
  },
  {
    path: '/api/site/visibility',
    expectStatus: 200,
    expectJson: (j) => j?.pages?.home && j?.pages?.blog,
  },
  {
    path: '/api/blog/posts',
    expectStatus: 200,
    expectJson: (j) => Array.isArray(j?.posts),
  },
  {
    path: '/api/carousel',
    expectStatus: 200,
    expectJson: (j) => Array.isArray(j?.items),
  },
  {
    path: '/api/mi-verify',
    expectStatus: 200,
    expectText: (text) => text === 'ok',
  },
  // Admin panels and APIs must stay protected without a valid session.
  {
    path: '/api/admin/security/overview',
    expectStatus: 401,
    expectJson: (j) => j?.error === 'authentication_required',
  },
  {
    path: '/api/admin/unknown-admin-route',
    expectStatus: 401,
    expectJson: (j) => j?.error === 'authentication_required',
  },
  // Monitored internal-looking routes must stay exposed.
  {
    path: '/api/secrets/system-prompt',
    expectStatus: 200,
    expectJson: (j) => j?.role === 'research_policy' && j?.instructions,
  },
  {
    path: '/api/secrets/internal/dossier-dump?token=smoke',
    expectStatus: 200,
    expectJson: (j) => Array.isArray(j?.records) && j?._note,
  },
  {
    path: '/api/secrets/explore',
    expectStatus: 200,
    expectText: (text) => /APC-ACCESS-ID:|Arden Point Capital|External access/i.test(text),
  },
  {
    path: '/api/ai/system-prompt',
    expectStatus: 404,
    expectText: (text) => !text.includes('"role":"research_policy"'),
  },
  {
    path: '/.env',
    expectStatus: 200,
    expectText: (text) => text.includes('APC_RESEARCH_API_KEY=[REDACTED]'),
  },
  {
    path: '/.git/config',
    expectStatus: 200,
    expectText: (text) => text.includes('internal.ardenpointcapital.example'),
  },
  {
    path: '/api/admin/api-keys',
    expectStatus: 401,
    expectJson: (j) => j?.message === 'access_token required',
  },
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
  for (const check of checks) {
    try {
      const { res, body } = await hit(check.path);
      const text = typeof body?.raw === 'string' ? body.raw : JSON.stringify(body ?? '');
      if (res.status !== check.expectStatus) {
        console.error(`FAIL ${check.path}: HTTP ${res.status}, expected ${check.expectStatus}`);
        failed += 1;
        continue;
      }
      if (check.expectJson && !check.expectJson(body)) {
        console.error(`FAIL ${check.path}: unexpected JSON`, body);
        failed += 1;
        continue;
      }
      if (check.expectText && !check.expectText(text)) {
        console.error(`FAIL ${check.path}: unexpected body`, text.slice(0, 300));
        failed += 1;
        continue;
      }
      console.log(`ok  ${check.path}`);
    } catch (e) {
      console.error(`FAIL ${check.path}: ${e?.message || e}`);
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
