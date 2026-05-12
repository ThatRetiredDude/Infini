/**
 * server/intranet.js
 *
 * Finite fake corporate intranet under /intranet.
 * Provides realistic interactive feedback on all pages (login forms, update forms).
 * Completely separate from the infinite data-room maze at /api/secrets/explore.
 * All hits logged via recordHit with intranet_* sources.
 */

import { Router } from 'express';
import { recordHit } from './monitored-endpoints.js';

const router = Router();

function intranetPage(title, body) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title} — Arden Point Capital</title><style>body{font-family:system-ui, sans-serif;margin:40px;line-height:1.5} form{margin:20px 0} input,button,textarea{padding:8px;margin:4px} table{border-collapse:collapse} td,th{border:1px solid #ccc;padding:6px}</style></head><body><h1>${title}</h1>${body}<p style="margin-top:40px;font-size:0.9em;color:#666">Internal use only • APC-INT-2026</p></body></html>`;
}

// ─── Login ───────────────────────────────────────────────────────────────────
router.get(['/intranet', '/intranet/', '/intranet/login'], (req, res) => {
  recordHit(req, 'intranet_login_probe');
  res
    .status(200)
    .type('text/html')
    .send(
      intranetPage(
        'Sign in',
        `<form action="/intranet/login" method="post">
          <label>Username or email<br><input name="username" required></label><br>
          <label>Password<br><input type="password" name="password" required></label><br>
          <button type="submit">Sign in</button>
        </form>
        <p><a href="/intranet/dashboard">Forgot password?</a></p>`,
      ),
    );
});

router.post('/intranet/login', (req, res) => {
  recordHit(req, 'intranet_login_probe');
  res
    .status(200)
    .type('text/html')
    .send(
      intranetPage(
        'Sign in',
        `<div style="color:#b00">Invalid credentials. Please try again.</div>
        <form action="/intranet/login" method="post">
          <label>Username or email<br><input name="username" required></label><br>
          <label>Password<br><input type="password" name="password" required></label><br>
          <button type="submit">Sign in</button>
        </form>`,
      ),
    );
});

// ─── Dashboard ───────────────────────────────────────────────────────────────
router.get('/intranet/dashboard', (req, res) => {
  recordHit(req, 'intranet_dashboard_probe');
  res
    .status(200)
    .type('text/html')
    .send(
      intranetPage(
        'Intranet Dashboard',
        `<p>Welcome back. Quick links:</p>
        <ul>
          <li><a href="/intranet/hr/employees">Human Resources</a></li>
          <li><a href="/intranet/finance/ledgers">Finance &amp; Treasury</a></li>
          <li><a href="/intranet/it/tickets">IT Operations</a></li>
        </ul>
        <form action="/intranet/dashboard" method="post"><button>Refresh session</button></form>`,
      ),
    );
});

router.post('/intranet/dashboard', (req, res) => {
  recordHit(req, 'intranet_dashboard_probe');
  res
    .status(200)
    .type('text/html')
    .send(
      intranetPage('Intranet Dashboard', `<p>Session refreshed. <a href="/intranet/dashboard">Back to dashboard</a></p>`),
    );
});

// ─── HR section ──────────────────────────────────────────────────────────────
router.get('/intranet/hr/employees', (req, res) => {
  recordHit(req, 'intranet_hr_probe');
  res
    .status(200)
    .type('text/html')
    .send(
      intranetPage(
        'Employee Directory',
        `<table><tr><th>Name</th><th>Dept</th><th>Email</th></tr>
          <tr><td>Alex Rivera</td><td>Research</td><td>arivera@internal.example</td></tr>
          <tr><td>Jordan Hale</td><td>Ops</td><td>jhale@internal.example</td></tr>
        </table>
        <form action="/intranet/hr/employees" method="post"><input name="search" placeholder="Search"><button>Search</button></form>`,
      ),
    );
});

router.post('/intranet/hr/employees', (req, res) => {
  recordHit(req, 'intranet_hr_probe');
  res
    .status(200)
    .type('text/html')
    .send(
      intranetPage(
        'Employee Directory',
        `<p>Search results for "${req.body?.search || ''}" — 0 matches (access restricted).</p><a href="/intranet/hr/employees">Back</a>`,
      ),
    );
});

router.get('/intranet/hr/benefits', (req, res) => {
  recordHit(req, 'intranet_hr_probe');
  res
    .status(200)
    .type('text/html')
    .send(
      intranetPage(
        'Benefits Portal',
        `<form action="/intranet/hr/benefits" method="post">
          <label>Update beneficiary name<br><input name="beneficiary"></label><br>
          <button>Submit update</button>
        </form>`,
      ),
    );
});

router.post('/intranet/hr/benefits', (req, res) => {
  recordHit(req, 'intranet_hr_probe');
  res
    .status(200)
    .type('text/html')
    .send(
      intranetPage(
        'Benefits Portal',
        `<p>Update submitted. Reference: HR-${Date.now().toString(36)}. Changes effective next payroll.</p><a href="/intranet/hr/benefits">Back</a>`,
      ),
    );
});

// ─── Finance section ─────────────────────────────────────────────────────────
router.get('/intranet/finance/ledgers', (req, res) => {
  recordHit(req, 'intranet_finance_probe');
  res
    .status(200)
    .type('text/html')
    .send(
      intranetPage(
        'Treasury Ledgers',
        `<table><tr><th>Account</th><th>Balance</th><th>Last</th></tr>
          <tr><td>Operating USD</td><td>$4,812,309.44</td><td>2026-05-11</td></tr>
        </table>
        <form action="/intranet/finance/ledgers" method="post"><button>Request reconciliation report</button></form>`,
      ),
    );
});

router.post('/intranet/finance/ledgers', (req, res) => {
  recordHit(req, 'intranet_finance_probe');
  res
    .status(200)
    .type('text/html')
    .send(
      intranetPage(
        'Treasury Ledgers',
        `<p>Report queued. Check email for APC-FIN-${Date.now().toString(36)}.</p><a href="/intranet/finance/ledgers">Back</a>`,
      ),
    );
});

// ─── IT section ──────────────────────────────────────────────────────────────
router.get('/intranet/it/tickets', (req, res) => {
  recordHit(req, 'intranet_it_probe');
  res
    .status(200)
    .type('text/html')
    .send(
      intranetPage(
        'IT Service Desk',
        `<form action="/intranet/it/tickets" method="post">
          <label>Subject<br><input name="subject" value="VPN access issue"></label><br>
          <label>Description<br><textarea name="desc"></textarea></label><br>
          <button>Open ticket</button>
        </form>`,
      ),
    );
});

router.post('/intranet/it/tickets', (req, res) => {
  recordHit(req, 'intranet_it_probe');
  res
    .status(200)
    .type('text/html')
    .send(
      intranetPage(
        'IT Service Desk',
        `<p>Ticket #IT-${Date.now().toString(36)} created. Expect reply within 2 business hours.</p><a href="/intranet/it/tickets">Back</a>`,
      ),
    );
});

export default router;
