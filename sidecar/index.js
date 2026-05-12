#!/usr/bin/env node
// MySQL Pharmaceutical Honeypot Sidecar + legacy banners for FTP/Postgres.
// - 3306: Full minimal MySQL protocol responder advertising old vulnerable version.
//   Accepts any credentials (easy access). Serves infinite deterministic pharma data.
// - 21/5432: Simple banners (unchanged behavior).
// All connections logged to stdout. No deps beyond node:net + crypto.

import net from 'node:net';
import { createHash } from 'node:crypto';

// ─── Shared seeded PRNG (copied from data-room.js for determinism) ───────────
function seededRand(seed) {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (Math.imul(31, h) + seed.charCodeAt(i)) | 0;
  return () => {
    h ^= h << 13;
    h ^= h >> 17;
    h ^= h << 5;
    return (h >>> 0) / 0xffffffff;
  };
}
function pick(arr, r) {
  return arr[Math.floor(r() * arr.length)];
}
function pickN(arr, n, r) {
  const out = [];
  const copy = [...arr];
  for (let i = 0; i < Math.min(n, copy.length); i++) {
    const idx = Math.floor(r() * copy.length);
    out.push(copy.splice(idx, 1)[0]);
  }
  return out;
}

// ─── Pharmaceutical word lists (real drug names + plausible corporate data) ───
const DRUGS = [
  'Keytruda (pembrolizumab)', 'Ozempic (semaglutide)', 'Humira (adalimumab)',
  'Eliquis (apixaban)', 'Xarelto (rivaroxaban)', 'Revlimid (lenalidomide)',
  'Opdivo (nivolumab)', 'Eylea (aflibercept)', 'Stelara (ustekinumab)',
  'Biktarvy (bictegravir/emtricitabine/tenofovir)', 'Skyrizi (risankizumab)',
  'Dupixent (dupilumab)', 'Rinvoq (upadacitinib)', 'Venclexta (venetoclax)',
  'Imbruvica (ibrutinib)', 'Tagrisso (osimertinib)', 'Darzalex (daratumumab)',
];
const LAB_TESTS = [
  'Purity HPLC', 'Impurities GC-MS', 'Endotoxin LAL', 'Sterility 14-day',
  'Dissolution USP <711>', 'Assay Potency', 'Related Substances',
  'Heavy Metals ICP-MS', 'Microbial Limits', 'Particulate Matter',
];
const DOCTOR_FIRST = ['Elena', 'Marcus', 'Sofia', 'Liam', 'Aisha', 'Raj', 'Priya', 'Javier', 'Mei', 'Omar'];
const DOCTOR_LAST = ['Vasquez', 'Hale', 'Kaur', 'Nguyen', 'Patel', 'Morales', 'Kim', 'Alvarez', 'Singh', 'Chen'];
const VENDORS = ['Lonza AG', 'Catalent Pharma', 'Thermo Fisher Scientific', 'Siegfried AG', 'Recipharm AB', 'Fresenius Kabi'];
const INVOICE_TYPES = ['API Manufacturing', 'Stability Study', 'Clinical Supply', 'Regulatory Filing Fee', 'Cold Chain Logistics', 'Deviation Investigation'];
const STATUSES = ['PAID', 'PENDING_APPROVAL', 'DISPUTED', 'PARTIAL'];

// ─── Row generators (deterministic, seeded, pharma-themed) ────────────────────
function genInvoiceRow(seed) {
  const r = seededRand(seed);
  const drug = pick(DRUGS, r);
  const vendor = pick(VENDORS, r);
  const year = 2023 + Math.floor(r() * 4);
  const month = 1 + Math.floor(r() * 12);
  const day = 1 + Math.floor(r() * 28);
  const date = `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
  const amount = (1200000 + Math.floor(r() * 46000000)).toFixed(2);
  const po = `VF-${year}${String(month).padStart(2, '0')}-${10000 + Math.floor(r() * 90000)}`;
  return {
    id: Math.floor(r() * 1000000),
    po_number: po,
    drug_sku: drug,
    vendor,
    amount_usd: amount,
    invoice_date: date,
    status: pick(STATUSES, r),
  };
}

function genLabResultRow(seed) {
  const r = seededRand(seed);
  const drug = pick(DRUGS, r);
  const test = pick(LAB_TESTS, r);
  const doctor = `${pick(DOCTOR_FIRST, r)} ${pick(DOCTOR_LAST, r)}`;
  const purity = (98.5 + r() * 1.4).toFixed(2);
  const year = 2024 + Math.floor(r() * 3);
  const month = 1 + Math.floor(r() * 12);
  const day = 1 + Math.floor(r() * 28);
  const date = `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
  return {
    id: Math.floor(r() * 1000000),
    batch_id: `BATCH-${year}${String(month).padStart(2, '0')}-${100000 + Math.floor(r() * 900000)}`,
    drug_name: drug,
    test_name: test,
    result_value: `${purity}%`,
    researcher: `Dr. ${doctor}`,
    test_date: date,
    status: r() > 0.95 ? 'FAIL' : 'PASS',
  };
}

function genLeakedCredRow(seed, idx) {
  const r = seededRand(seed);
  const first = pick(DOCTOR_FIRST, r);
  const last = pick(DOCTOR_LAST, r);
  const email = `${first.toLowerCase()}.${last.toLowerCase()}@vitaforgelabs.example`;
  // Plausible-looking high-cost bcrypt (cost 12-14) to waste cracking time
  const cost = 12 + Math.floor(r() * 3);
  const hash = `$2b$${cost}$${createHash('sha256').update(seed + idx).digest('base64').slice(0, 22)}$${createHash('sha256').update(seed + 'salt' + idx).digest('base64').slice(0, 31)}`;
  return {
    id: idx,
    email,
    hash,
    hash_type: 'bcrypt',
    cost,
    leak_source: '2025-11_VitaForge_Internal',
    crack_status: cost > 13 ? 'unbroken' : (r() > 0.7 ? 'partial' : 'unbroken'),
  };
}

// ─── MySQL minimal protocol helpers (enough for nmap -sV + basic clients) ─────
function buildMySQLPacket(payload, sequence = 0) {
  const len = payload.length;
  const header = Buffer.from([
    len & 0xff,
    (len >> 8) & 0xff,
    (len >> 16) & 0xff,
    sequence,
  ]);
  return Buffer.concat([header, payload]);
}

function buildHandshakeV10() {
  // Old vulnerable version string so scanners flag it
  const version = '5.5.23-0ubuntu0.14.04.1';
  const serverVersion = Buffer.from(version + '\0');
  const connId = Buffer.from([0x08, 0x00, 0x00, 0x00]);
  const authData = Buffer.alloc(8, 0x2a); // dummy scramble
  const filler = Buffer.from([0x00]);
  const capLower = Buffer.from([0xff, 0xff]);
  const charset = Buffer.from([0x21]); // utf8
  const status = Buffer.from([0x02, 0x00]);
  const capUpper = Buffer.from([0xff, 0xdf]);
  const authPluginLen = Buffer.from([0x00]);
  const reserved = Buffer.alloc(10, 0);
  const authPluginName = Buffer.from('mysql_native_password\0');

  const payload = Buffer.concat([
    Buffer.from([0x0a]), // protocol version
    serverVersion,
    connId,
    authData,
    filler,
    capLower,
    charset,
    status,
    capUpper,
    authPluginLen,
    reserved,
    authData, // second part (empty for minimal)
    authPluginName,
  ]);
  return buildMySQLPacket(payload, 0);
}

function buildOKPacket(affected = 0, lastInsert = 0) {
  const payload = Buffer.from([
    0x00, // OK header
    affected & 0xff,
    (affected >> 8) & 0xff,
    lastInsert & 0xff,
    (lastInsert >> 8) & 0xff,
    0x00, 0x00, // status flags
    0x00, 0x00, // warnings
  ]);
  return buildMySQLPacket(payload, 1);
}

function buildERRPacket(code, msg) {
  const msgBuf = Buffer.from(msg);
  const payload = Buffer.concat([
    Buffer.from([0xff]),
    Buffer.from([code & 0xff, (code >> 8) & 0xff]),
    Buffer.from('#'),
    Buffer.from('HY000'),
    msgBuf,
  ]);
  return buildMySQLPacket(payload, 1);
}

// Very minimal result set for SELECT (column count + rows)
function buildResultSet(columns, rows) {
  // Column count packet
  const colCount = Buffer.from([columns.length]);
  let packets = [buildMySQLPacket(colCount, 1)];

  // Column definitions (simplified)
  for (const col of columns) {
    const name = Buffer.from(col + '\0');
    const colDef = Buffer.concat([
      Buffer.from([0x03, 0x64, 0x65, 0x66]), // catalog
      Buffer.from([0x00]), // db
      Buffer.from([0x00]), // table
      Buffer.from([0x00]), // org table
      name,
      name,
      Buffer.from([0x0c, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    ]);
    packets.push(buildMySQLPacket(colDef, packets.length));
  }

  // EOF after columns
  packets.push(buildMySQLPacket(Buffer.from([0xfe, 0x00, 0x00, 0x02, 0x00]), packets.length));

  // Rows
  for (const row of rows) {
    const values = Object.values(row).map((v) => {
      const s = String(v);
      return Buffer.concat([Buffer.from([s.length]), Buffer.from(s)]);
    });
    const rowBuf = Buffer.concat(values);
    packets.push(buildMySQLPacket(rowBuf, packets.length));
  }

  // Final EOF
  packets.push(buildMySQLPacket(Buffer.from([0xfe, 0x00, 0x00, 0x02, 0x00]), packets.length));

  return Buffer.concat(packets);
}

// ─── Query router + pharma data generation ────────────────────────────────────
function handleQuery(query, socket) {
  const q = query.toLowerCase().trim();
  console.log(`[mysql-honeypot] query="${query.slice(0, 120)}"`);

  if (q.startsWith('show databases')) {
    const cols = ['Database'];
    const rows = [
      { Database: 'pharma_erp' },
      { Database: 'clinical_warehouse' },
      { Database: 'regulatory_archive' },
      { Database: 'leaked_data' },
    ];
    socket.write(buildResultSet(cols, rows));
    return;
  }

  if (q.startsWith('show tables')) {
    const cols = ['Tables_in_pharma_erp'];
    const rows = [
      { Tables_in_pharma_erp: 'invoices' },
      { Tables_in_pharma_erp: 'lab_results' },
      { Tables_in_pharma_erp: 'batch_records' },
      { Tables_in_pharma_erp: 'stability_studies' },
      { Tables_in_pharma_erp: 'clinical_trials' },
      { Tables_in_pharma_erp: 'investigator_payments' },
      { Tables_in_pharma_erp: 'password_backup' },
    ];
    socket.write(buildResultSet(cols, rows));
    return;
  }

  if (q.includes('select') && q.includes('from invoices')) {
    const limit = q.includes('limit') ? parseInt(q.split('limit')[1]) || 50 : 50;
    const cols = ['id', 'po_number', 'drug_sku', 'vendor', 'amount_usd', 'invoice_date', 'status'];
    const rows = [];
    for (let i = 0; i < limit; i++) {
      rows.push(genInvoiceRow(`invoice:${i}`));
    }
    socket.write(buildResultSet(cols, rows));
    return;
  }

  if (q.includes('select') && q.includes('from lab_results')) {
    const limit = q.includes('limit') ? parseInt(q.split('limit')[1]) || 50 : 50;
    const cols = ['id', 'batch_id', 'drug_name', 'test_name', 'result_value', 'researcher', 'test_date', 'status'];
    const rows = [];
    for (let i = 0; i < limit; i++) {
      rows.push(genLabResultRow(`lab:${i}`));
    }
    socket.write(buildResultSet(cols, rows));
    return;
  }

  if (q.includes('select') && q.includes('from password_backup')) {
    const limit = q.includes('limit') ? Math.min(parseInt(q.split('limit')[1]) || 1000, 500000) : 1000;
    const cols = ['id', 'email', 'hash', 'hash_type', 'cost', 'leak_source', 'crack_status'];
    const rows = [];
    for (let i = 0; i < limit; i++) {
      rows.push(genLeakedCredRow(`cred:${i}`, i));
    }
    socket.write(buildResultSet(cols, rows));
    return;
  }

  // Default OK for other queries (SHOW, USE, etc.)
  socket.write(buildOKPacket());
}

// ─── MySQL connection handler (greeting + trivial auth + query loop) ─────────
function startMySQLHoneypot() {
  const server = net.createServer((socket) => {
    const remote = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[mysql-honeypot] ${new Date().toISOString()} connect ${remote} -> :3306`);

    // Send old vulnerable greeting so nmap -sV reports 5.5.23
    socket.write(buildHandshakeV10());

    let authed = false;
    let buffer = Buffer.alloc(0);

    socket.on('data', (data) => {
      buffer = Buffer.concat([buffer, data]);

      if (!authed) {
        // Consume handshake response, always reply OK (no real auth)
        console.log(`[mysql-honeypot] auth attempt from ${remote}`);
        socket.write(buildOKPacket());
        authed = true;
        buffer = Buffer.alloc(0);
        return;
      }

      // Parse COM_QUERY (first byte 0x03)
      if (buffer.length > 5 && buffer[4] === 0x03) {
        const queryLen = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16);
        const query = buffer.slice(5, 5 + queryLen - 1).toString('utf8');
        handleQuery(query, socket);
        buffer = Buffer.alloc(0);
      }
    });

    socket.on('error', () => {});
    socket.on('close', () => {});
    setTimeout(() => {
      if (!socket.destroyed) socket.destroy();
    }, 300000); // 5 min max per connection
  });

  server.listen(3306, () => {
    console.log('[mysql-honeypot] listening on :3306 (old 5.5.23 + pharma infinite data)');
  });
  server.on('error', (e) => console.error('[mysql-honeypot] error:', e.message));
}

// ─── Legacy banner servers (FTP + Postgres) ───────────────────────────────────
const BANNER_PORTS = [
  { port: 21, banner: '220 ProFTPD 1.3.9 Server [internal.ardenpointcapital.example]\r\n' },
  { port: 5432, banner: 'PostgreSQL 16.2 on x86_64-pc-linux-gnu\r\n' },
];

function startBannerServer({ port, banner }) {
  const server = net.createServer((socket) => {
    const remote = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[sidecar] ${new Date().toISOString()} connect ${remote} -> :${port}`);
    socket.write(banner);
    socket.once('data', () => socket.end());
    socket.on('error', () => {});
    setTimeout(() => socket.destroy(), 5000);
  });
  server.listen(port, () => console.log(`[sidecar] listening on :${port}`));
  server.on('error', (e) => console.error(`[sidecar] port ${port} error:`, e.message));
}

// ─── Startup ──────────────────────────────────────────────────────────────────
startMySQLHoneypot();
for (const cfg of BANNER_PORTS) startBannerServer(cfg);

process.on('SIGINT', () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));
