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

function intranetPage(title, body, extraHead = '') {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title} — Arden Point Capital Intranet</title>
  <link rel="stylesheet" href="https://cdn.tailwindcss.com">
  <style>
    .apc-header { background: linear-gradient(90deg, #0f172a 0%, #1e3a5f 100%); }
    .nav-active { border-bottom: 3px solid #3b82f6; }
    .modern-card { transition: transform .2s ease, box-shadow .2s ease; }
    .modern-card:hover { transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1); }
    .hero-bg { background-image: linear-gradient(rgba(15,23,42,0.65), rgba(15,23,42,0.75)), url('data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 1200 630%22%3E%3Cdefs%3E%3ClinearGradient id=%22g%22 x1=%220%25%22 y1=%220%25%22 x2=%22100%25%22 y2=%22100%25%22%3E%3Cstop offset=%220%25%22 stop-color=%22%231e3a5f%22/%3E%3Cstop offset=%22100%25%22 stop-color=%22%230f172a%22/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect fill=%22url(%23g)%22 width=%221200%22 height=%22630%22/%3E%3C/svg%3E'); background-size: cover; }
    .carousel { position: relative; overflow: hidden; }
    .slide { transition: opacity 0.6s ease; }
  </style>
  ${extraHead}
</head>
<body class="bg-slate-50 text-slate-900 font-sans">
  <header class="apc-header text-white">
    <div class="max-w-screen-xl mx-auto px-6 py-4 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-9 h-9 bg-blue-600 rounded flex items-center justify-center"><span class="font-bold text-xl">A</span></div>
        <div>
          <div class="font-semibold tracking-tight text-xl">Arden Point Capital</div>
          <div class="text-[10px] text-blue-400 -mt-1">INTERNAL INTRANET</div>
        </div>
      </div>
      <nav class="flex items-center gap-8 text-sm">
        <a href="/intranet/dashboard" class="hover:text-blue-400 transition">Dashboard</a>
        <a href="/intranet/hr/employees" class="hover:text-blue-400 transition">Human Resources</a>
        <a href="/intranet/finance/ledgers" class="hover:text-blue-400 transition">Finance</a>
        <a href="/intranet/it/tickets" class="hover:text-blue-400 transition">IT Services</a>
        <div class="flex items-center gap-2 pl-6 border-l border-white/20">
          <div class="text-right"><div class="text-xs">Alex Rivera</div><div class="text-[10px] text-blue-400">Research • VP</div></div>
          <div class="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-xs font-medium">AR</div>
        </div>
      </nav>
    </div>
  </header>
  <main class="max-w-screen-xl mx-auto px-6 py-8">
    <div class="mb-6">
      <h1 class="text-3xl font-semibold tracking-tight">${title}</h1>
    </div>
    ${body}
  </main>
  <footer class="max-w-screen-xl mx-auto px-6 py-8 text-xs text-slate-500 border-t">© 2026 Arden Point Capital • Confidential • APC-INT-2026</footer>
</body>
</html>`;
}

// ─── Login ───────────────────────────────────────────────────────────────────
router.get(['/intranet', '/intranet/', '/intranet/login'], (req, res) => {
  recordHit(req, 'intranet_login_probe');
  const loginBody = `
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
    <div>
      <div class="max-w-md">
        <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-100 text-blue-700 text-xs font-medium mb-4">SECURE ACCESS</div>
        <h2 class="text-4xl font-semibold tracking-tight mb-3">Welcome back to the team.</h2>
        <p class="text-slate-600 mb-8">Sign in with your Arden Point Capital credentials to access internal resources, research tools, and company systems.</p>
        
        <div class="bg-white border border-slate-200 rounded-2xl p-8 shadow-sm modern-card">
          <form action="/intranet/login" method="post" class="space-y-5">
            <div>
              <label class="block text-sm font-medium text-slate-700 mb-1.5">Email address</label>
              <input type="email" name="username" required class="w-full px-4 py-3 border border-slate-300 rounded-xl focus:outline-none focus:border-blue-500" placeholder="you@ardenpointcapital.example">
            </div>
            <div>
              <label class="block text-sm font-medium text-slate-700 mb-1.5">Password</label>
              <input type="password" name="password" required class="w-full px-4 py-3 border border-slate-300 rounded-xl focus:outline-none focus:border-blue-500">
            </div>
            <div class="flex items-center justify-between text-sm">
              <label class="flex items-center gap-2"><input type="checkbox" class="accent-blue-600"> Remember me</label>
              <a href="#" class="text-blue-600 hover:underline">Forgot password?</a>
            </div>
            <button type="submit" class="w-full py-3.5 bg-slate-900 hover:bg-slate-800 transition text-white rounded-2xl font-medium">Sign in to intranet</button>
          </form>
          <div class="mt-5 text-center text-xs text-slate-500">Protected by APC Security • MFA enforced</div>
        </div>
      </div>
    </div>
    <div class="hidden lg:block">
      <div class="hero-bg rounded-3xl h-[480px] flex items-end p-10 text-white">
        <div>
          <div class="uppercase tracking-[3px] text-xs mb-1 opacity-75">NEW YORK • LONDON • SINGAPORE</div>
          <div class="text-5xl font-semibold tracking-tighter leading-none">Arden Point Capital</div>
          <div class="mt-2 text-xl opacity-90">Private Markets • Research Excellence</div>
        </div>
      </div>
    </div>
  </div>`;
  res.status(200).type('text/html').send(intranetPage('Sign in', loginBody));
});

router.post('/intranet/login', (req, res) => {
  recordHit(req, 'intranet_login_probe');
  const errorBody = `
  <div class="max-w-md mx-auto">
    <div class="bg-red-50 border border-red-200 text-red-700 px-5 py-4 rounded-2xl mb-6">Invalid credentials. Please verify your username and password.</div>
    <div class="bg-white border border-slate-200 rounded-2xl p-8 shadow-sm">
      <form action="/intranet/login" method="post" class="space-y-5">
        <div><label class="block text-sm font-medium mb-1.5">Email address</label><input type="email" name="username" required class="w-full px-4 py-3 border border-slate-300 rounded-xl"></div>
        <div><label class="block text-sm font-medium mb-1.5">Password</label><input type="password" name="password" required class="w-full px-4 py-3 border border-slate-300 rounded-xl"></div>
        <button type="submit" class="w-full py-3.5 bg-slate-900 text-white rounded-2xl font-medium">Sign in</button>
      </form>
    </div>
  </div>`;
  res.status(200).type('text/html').send(intranetPage('Sign in', errorBody));
});

// ─── Dashboard ───────────────────────────────────────────────────────────────
router.get('/intranet/dashboard', (req, res) => {
  recordHit(req, 'intranet_dashboard_probe');
  const dashBody = `
  <div class="mb-8">
    <div class="rounded-3xl bg-gradient-to-br from-slate-900 to-slate-800 text-white p-10 flex items-center justify-between">
      <div>
        <div class="text-blue-400 text-sm tracking-widest">GOOD MORNING, ALEX</div>
        <div class="text-4xl font-semibold tracking-tighter mt-1">Welcome back to APC.</div>
        <div class="mt-2 text-slate-400">Last login: Today at 07:42 • New York HQ</div>
      </div>
      <div class="text-right">
        <div class="text-xs uppercase tracking-widest opacity-60">MARKET STATUS</div>
        <div class="text-emerald-400 font-medium">Markets Open • +1.8%</div>
      </div>
    </div>
  </div>

  <!-- Professional Image Carousel -->
  <div class="mb-10">
    <div class="flex items-center justify-between mb-3 px-1">
      <div class="font-medium">Company Highlights</div>
      <div class="text-xs text-slate-500">Q1 2026 • Internal</div>
    </div>
    <div id="carousel" class="carousel relative h-64 rounded-3xl overflow-hidden shadow border border-slate-200 bg-slate-900">
      <div class="slide absolute inset-0 bg-[url('https://picsum.photos/id/1015/1200/630')] bg-cover opacity-100" style="background-position:center 30%"></div>
      <div class="slide absolute inset-0 bg-[url('https://picsum.photos/id/1005/1200/630')] bg-cover opacity-0" style="background-position:center 40%"></div>
      <div class="slide absolute inset-0 bg-[url('https://picsum.photos/id/1016/1200/630')] bg-cover opacity-0" style="background-position:center 20%"></div>
      <div class="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/70 p-6 text-white">
        <div class="text-sm opacity-75">NEW YORK HQ — Q1 OFFSITE</div>
        <div class="font-semibold text-xl tracking-tight">Driving innovation in private markets</div>
      </div>
    </div>
  </div>

  <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
    <a href="/intranet/hr/employees" class="modern-card block bg-white border border-slate-200 rounded-3xl p-8 hover:border-blue-200">
      <div class="text-blue-600 mb-2">👥</div>
      <div class="font-semibold text-xl">Human Resources</div>
      <div class="text-sm text-slate-500 mt-1">Employee directory, benefits, policies</div>
    </a>
    <a href="/intranet/finance/ledgers" class="modern-card block bg-white border border-slate-200 rounded-3xl p-8 hover:border-blue-200">
      <div class="text-blue-600 mb-2">📈</div>
      <div class="font-semibold text-xl">Finance &amp; Treasury</div>
      <div class="text-sm text-slate-500 mt-1">Ledgers, reports, reconciliation</div>
    </a>
    <a href="/intranet/it/tickets" class="modern-card block bg-white border border-slate-200 rounded-3xl p-8 hover:border-blue-200">
      <div class="text-blue-600 mb-2">🛠️</div>
      <div class="font-semibold text-xl">IT Service Desk</div>
      <div class="text-sm text-slate-500 mt-1">Support tickets and system status</div>
    </a>
  </div>

  <div class="mt-8 text-center">
    <form action="/intranet/dashboard" method="post" class="inline">
      <button class="px-5 py-2 text-sm border border-slate-300 hover:bg-white rounded-2xl transition">Refresh session &amp; sync</button>
    </form>
  </div>`;
  res.status(200).type('text/html').send(intranetPage('Intranet Dashboard', dashBody, `
    <script>
      setTimeout(() => {
        const slides = document.querySelectorAll('#carousel .slide');
        let idx = 0;
        setInterval(() => {
          slides.forEach(s => s.style.opacity = '0');
          slides[idx].style.opacity = '1';
          idx = (idx + 1) % slides.length;
        }, 4200);
      }, 800);
    </script>
  `));
});

router.post('/intranet/dashboard', (req, res) => {
  recordHit(req, 'intranet_dashboard_probe');
  res.status(200).type('text/html').send(intranetPage('Intranet Dashboard', `<div class="max-w-md mx-auto bg-white border rounded-3xl p-8 text-center"><p class="mb-4">Session refreshed successfully. All systems synced.</p><a href="/intranet/dashboard" class="text-blue-600 hover:underline">Return to dashboard</a></div>`));
});

// ─── HR section ──────────────────────────────────────────────────────────────
router.get('/intranet/hr/employees', (req, res) => {
  recordHit(req, 'intranet_hr_probe');
  const hrBody = `
  <div class="flex gap-3 mb-6"><a href="/intranet/hr/employees" class="px-4 py-1.5 bg-blue-600 text-white rounded-full text-sm">Directory</a><a href="/intranet/hr/benefits" class="px-4 py-1.5 hover:bg-white border rounded-full text-sm">Benefits Portal</a></div>
  <div class="bg-white border border-slate-200 rounded-3xl overflow-hidden">
    <div class="px-8 py-6 border-b flex items-center justify-between"><div class="font-medium">Employee Directory — New York &amp; London</div><input placeholder="Search employees..." class="text-sm border px-4 py-2 rounded-2xl w-72"></div>
    <table class="w-full text-sm"><thead class="bg-slate-50"><tr><th class="text-left px-8 py-4 font-medium">Name</th><th class="text-left py-4 font-medium">Department</th><th class="text-left py-4 font-medium">Email</th><th></th></tr></thead>
      <tbody class="divide-y">
        <tr><td class="px-8 py-4 font-medium">Alex Rivera</td><td class="py-4 text-slate-600">Research • VP</td><td class="py-4 text-blue-600">arivera@internal.example</td><td class="pr-8 text-right"><a href="#" class="text-xs px-3 py-1 border rounded">View profile</a></td></tr>
        <tr><td class="px-8 py-4 font-medium">Jordan Hale</td><td class="py-4 text-slate-600">Operations</td><td class="py-4 text-blue-600">jhale@internal.example</td><td class="pr-8 text-right"><a href="#" class="text-xs px-3 py-1 border rounded">View profile</a></td></tr>
        <tr><td class="px-8 py-4 font-medium">Morgan Ellis</td><td class="py-4 text-slate-600">Finance • Director</td><td class="py-4 text-blue-600">mellis@internal.example</td><td class="pr-8 text-right"><a href="#" class="text-xs px-3 py-1 border rounded">View profile</a></td></tr>
      </tbody>
    </table>
  </div>
  <form action="/intranet/hr/employees" method="post" class="mt-6 flex gap-3"><input name="search" placeholder="Filter by name or title" class="flex-1 border px-5 py-3 rounded-2xl"><button class="px-8 py-3 bg-slate-900 text-white rounded-2xl text-sm">Search directory</button></form>`;
  res.status(200).type('text/html').send(intranetPage('Employee Directory', hrBody));
});

router.post('/intranet/hr/employees', (req, res) => {
  recordHit(req, 'intranet_hr_probe');
  res.status(200).type('text/html').send(intranetPage('Employee Directory', `<div class="max-w-md">Search results for “${req.body?.search || ''}” returned restricted access. Please contact HR for assistance.<br><br><a href="/intranet/hr/employees" class="underline">Back to directory</a></div>`));
});

router.get('/intranet/hr/benefits', (req, res) => {
  recordHit(req, 'intranet_hr_probe');
  const benefitsBody = `<div class="max-w-2xl"><div class="prose prose-sm mb-8 text-slate-600">Update your benefits elections and beneficiary information. All changes are reviewed by HR within 48 hours.</div>
  <form action="/intranet/hr/benefits" method="post" class="bg-white border rounded-3xl p-8 space-y-6">
    <div><label class="text-sm">Primary beneficiary full name</label><input name="beneficiary" class="mt-1 w-full border px-4 py-3 rounded-2xl" placeholder="Jane Doe"></div>
    <div><label class="text-sm">Relationship</label><select class="mt-1 w-full border px-4 py-3 rounded-2xl"><option>Spouse / Partner</option><option>Child</option><option>Parent</option></select></div>
    <button class="bg-blue-600 text-white px-8 py-3 rounded-2xl">Submit beneficiary update</button>
  </form></div>`;
  res.status(200).type('text/html').send(intranetPage('Benefits Portal', benefitsBody));
});

router.post('/intranet/hr/benefits', (req, res) => {
  recordHit(req, 'intranet_hr_probe');
  res.status(200).type('text/html').send(intranetPage('Benefits Portal', `<div class="max-w-md text-center mx-auto"><div class="text-emerald-600 text-4xl mb-3">✓</div><div class="font-semibold">Update submitted successfully.</div><div class="text-sm text-slate-600 mt-1">Reference: HR-${Date.now().toString(36)}</div><div class="mt-6"><a href="/intranet/hr/benefits" class="underline">Back to benefits</a></div></div>`));
});

// ─── Finance section ─────────────────────────────────────────────────────────
router.get('/intranet/finance/ledgers', (req, res) => {
  recordHit(req, 'intranet_finance_probe');
  const finBody = `
  <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
    <div class="bg-white border rounded-3xl p-8"><div class="text-xs uppercase tracking-widest text-emerald-600">Q1 2026</div><div class="text-4xl font-semibold tracking-tighter mt-2">$4,812,309.44</div><div class="text-sm text-slate-500">Operating USD • Last reconciled May 11</div></div>
    <div class="bg-white border rounded-3xl p-8"><div class="text-xs uppercase tracking-widest text-emerald-600">Q1 2026</div><div class="text-4xl font-semibold tracking-tighter mt-2">€1,204,882.00</div><div class="text-sm text-slate-500">EUR Treasury • Last reconciled May 9</div></div>
  </div>
  <form action="/intranet/finance/ledgers" method="post" class="text-center"><button class="px-8 py-3 text-sm border border-slate-300 rounded-2xl hover:bg-white">Request full reconciliation report (PDF)</button></form>`;
  res.status(200).type('text/html').send(intranetPage('Treasury Ledgers', finBody));
});

router.post('/intranet/finance/ledgers', (req, res) => {
  recordHit(req, 'intranet_finance_probe');
  res.status(200).type('text/html').send(intranetPage('Treasury Ledgers', `<div class="max-w-md mx-auto text-center">Report APC-FIN-${Date.now().toString(36)} has been generated and emailed to your secure inbox.<br><br><a href="/intranet/finance/ledgers" class="underline">Back to ledgers</a></div>`));
});

// ─── IT section ──────────────────────────────────────────────────────────────
router.get('/intranet/it/tickets', (req, res) => {
  recordHit(req, 'intranet_it_probe');
  const itBody = `
  <div class="max-w-xl">
    <div class="mb-8">Open a new support ticket. Our IT team typically responds within 2 business hours during market days.</div>
    <form action="/intranet/it/tickets" method="post" class="bg-white border rounded-3xl p-8 space-y-6">
      <div><label class="block text-sm mb-1.5">Subject</label><input name="subject" value="VPN access issue" class="w-full border px-4 py-3 rounded-2xl"></div>
      <div><label class="block text-sm mb-1.5">Description</label><textarea name="desc" rows="4" class="w-full border px-4 py-3 rounded-2xl" placeholder="Please describe the issue..."></textarea></div>
      <button class="bg-slate-900 text-white px-8 py-3 rounded-2xl">Open ticket</button>
    </form>
  </div>`;
  res.status(200).type('text/html').send(intranetPage('IT Service Desk', itBody));
});

router.post('/intranet/it/tickets', (req, res) => {
  recordHit(req, 'intranet_it_probe');
  res.status(200).type('text/html').send(intranetPage('IT Service Desk', `<div class="max-w-md mx-auto text-center"><div class="text-emerald-600 text-4xl mb-3">✓</div><div class="font-semibold">Ticket #IT-${Date.now().toString(36)} created.</div><div class="text-sm text-slate-600 mt-1">Expect reply within 2 business hours.</div><div class="mt-6"><a href="/intranet/it/tickets" class="underline">Back to service desk</a></div></div>`));
});

export default router;
