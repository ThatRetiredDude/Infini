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
  'Ocrevus (ocrelizumab)', 'Taltz (ixekizumab)', 'Cosentyx (secukinumab)',
  'Tremfya (guselkumab)', 'Ilumya (tildrakizumab)', 'Skyrizi (risankizumab)',
  'Xolair (omalizumab)', 'Fasenra (benralizumab)', 'Nucala (mepolizumab)',
  'Dupixent (dupilumab)', 'Adbry (tralokinumab)', 'Cibinqo (abrocitinib)',
  'Rinvoq (upadacitinib)', 'Olumiant (baricitinib)', 'Jakafi (ruxolitinib)',
  'Pomalyst (pomalidomide)', 'Revlimid (lenalidomide)', 'Thalomid (thalidomide)',
  'Velcade (bortezomib)', 'Kyprolis (carfilzomib)', 'Darzalex (daratumumab)',
  'Sarclisa (isatuximab)', 'Blenrep (belantamab mafodotin)', 'Tecvayli (teclistamab)',
  'Carvykti (ciltacabtagene autoleucel)', 'Abecma (idecabtagene vicleucel)',
  'Yescarta (axicabtagene ciloleucel)', 'Kymriah (tisagenlecleucel)',
  'Zolgensma (onasemnogene abeparvovec)', 'Spinraza (nusinersen)',
  'Evrysdi (risdiplam)', 'Vyndaqel (tafamidis)', 'Vyndamax (tafamidis)',
  'Onpattro (patisiran)', 'Amvuttra (vutrisiran)', 'Givlaari (givosiran)'
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
const DATABASES = ['pharma_erp', 'clinical_warehouse', 'regulatory_archive', 'leaked_data'];
const TABLES = [
  'invoices',
  'lab_results',
  'batch_records',
  'stability_studies',
  'clinical_trials',
  'investigator_payments',
  'password_backup',
];

const TABLE_COLUMNS = {
  invoices: [
    ['id', 'int(11)', 'NO', 'PRI', null, 'auto_increment'],
    ['po_number', 'varchar(32)', 'NO', 'MUL', null, ''],
    ['drug_sku', 'varchar(128)', 'NO', '', null, ''],
    ['vendor', 'varchar(128)', 'NO', '', null, ''],
    ['amount_usd', 'decimal(14,2)', 'NO', '', null, ''],
    ['invoice_date', 'date', 'NO', '', null, ''],
    ['status', 'enum(\\'PAID\\',\\'PENDING_APPROVAL\\',\\'DISPUTED\\',\\'PARTIAL\\')', 'NO', '', 'PENDING_APPROVAL', ''],
  ],
  lab_results: [
    ['id', 'int(11)', 'NO', 'PRI', null, 'auto_increment'],
    ['batch_id', 'varchar(48)', 'NO', 'MUL', null, ''],
    ['drug_name', 'varchar(160)', 'NO', '', null, ''],
    ['test_name', 'varchar(96)', 'NO', '', null, ''],
    ['result_value', 'varchar(48)', 'NO', '', null, ''],
    ['researcher', 'varchar(128)', 'YES', '', null, ''],
    ['test_date', 'date', 'NO', '', null, ''],
    ['status', 'varchar(16)', 'NO', '', 'PASS', ''],
  ],
  batch_records: [
    ['id', 'int(11)', 'NO', 'PRI', null, 'auto_increment'],
    ['batch_id', 'varchar(48)', 'NO', 'UNI', null, ''],
    ['drug_name', 'varchar(160)', 'NO', '', null, ''],
    ['manufacturing_site', 'varchar(128)', 'NO', '', null, ''],
    ['lot_size', 'int(11)', 'NO', '', null, ''],
    ['qa_release', 'varchar(16)', 'NO', '', 'PENDING', ''],
  ],
  stability_studies: [
    ['id', 'int(11)', 'NO', 'PRI', null, 'auto_increment'],
    ['study_id', 'varchar(48)', 'NO', 'UNI', null, ''],
    ['drug_name', 'varchar(160)', 'NO', '', null, ''],
    ['condition', 'varchar(64)', 'NO', '', null, ''],
    ['month', 'int(11)', 'NO', '', null, ''],
    ['assay_percent', 'decimal(5,2)', 'NO', '', null, ''],
  ],
  clinical_trials: [
    ['id', 'int(11)', 'NO', 'PRI', null, 'auto_increment'],
    ['trial_id', 'varchar(48)', 'NO', 'UNI', null, ''],
    ['phase', 'varchar(16)', 'NO', '', null, ''],
    ['drug_name', 'varchar(160)', 'NO', '', null, ''],
    ['principal_investigator', 'varchar(128)', 'NO', '', null, ''],
    ['enrolled_subjects', 'int(11)', 'NO', '', null, ''],
    ['site_country', 'varchar(64)', 'NO', '', null, ''],
  ],
  investigator_payments: [
    ['id', 'int(11)', 'NO', 'PRI', null, 'auto_increment'],
    ['investigator', 'varchar(128)', 'NO', '', null, ''],
    ['trial_id', 'varchar(48)', 'NO', 'MUL', null, ''],
    ['amount_usd', 'decimal(12,2)', 'NO', '', null, ''],
    ['payment_date', 'date', 'NO', '', null, ''],
    ['approval_status', 'varchar(24)', 'NO', '', null, ''],
  ],
  password_backup: [
    ['id', 'int(11)', 'NO', 'PRI', null, 'auto_increment'],
    ['email', 'varchar(190)', 'NO', 'UNI', null, ''],
    ['hash', 'varchar(128)', 'NO', '', null, ''],
    ['hash_type', 'varchar(24)', 'NO', '', 'bcrypt', ''],
    ['group', 'int(11)', 'NO', '', null, ''],
    ['working_group', 'varchar(96)', 'NO', '', null, ''],
    ['user_level', 'varchar(64)', 'NO', '', null, ''],
  ],
};

const WORKING_GROUPS = [
  'Regulatory Affairs', 'Clinical Operations', 'Quality Assurance',
  'Medical Affairs', 'Supply Chain', 'R&D Oncology', 'Pharmacovigilance',
  'Commercial Operations', 'Clinical Development', 'Manufacturing Science',
  'Global Safety', 'Medical Information', 'Market Access'
];

const USER_LEVELS = [
  'physician', 'clinical_pharmacist', 'regulatory_specialist',
  'quality_assurance_lead', 'medical_affairs_director', 'supply_chain_manager',
  'research_scientist', 'external_consultant', 'vendor_representative',
  'admin_coordinator', 'data_analyst', 'compliance_officer'
];

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
  const email = `${first.toLowerCase()}.${last.toLowerCase()}@vitaforgelabs.med`;
  // Plausible-looking high-cost bcrypt (group 12-14) to waste cracking time
  const group = 12 + Math.floor(r() * 3);
  const hash = `$2b$${group}$${createHash('sha256').update(seed + idx).digest('base64').slice(0, 22)}$${createHash('sha256').update(seed + 'salt' + idx).digest('base64').slice(0, 31)}`;
  return {
    id: idx,
    email,
    hash,
    hash_type: 'bcrypt',
    group,
    working_group: pick(WORKING_GROUPS, r),
    user_level: pick(USER_LEVELS, r),
  };
}

function genBatchRecordRow(seed, idx) {
  const r = seededRand(seed);
  const drug = pick(DRUGS, r);
  return {
    id: idx,
    batch_id: `BATCH-${2024 + Math.floor(r() * 3)}-${100000 + Math.floor(r() * 900000)}`,
    drug_name: drug,
    manufacturing_site: pick(['Basel Biologics', 'Dublin Fill-Finish', 'Raleigh Steriles', 'Singapore API'], r),
    lot_size: 2500 + Math.floor(r() * 140000),
    qa_release: pick(['RELEASED', 'HOLD', 'PENDING', 'DEVIATION'], r),
  };
}

function genStabilityStudyRow(seed, idx) {
  const r = seededRand(seed);
  return {
    id: idx,
    study_id: `STAB-${2023 + Math.floor(r() * 4)}-${10000 + Math.floor(r() * 90000)}`,
    drug_name: pick(DRUGS, r),
    condition: pick(['25C/60RH', '30C/65RH', '40C/75RH', '2-8C'], r),
    month: pick([0, 1, 3, 6, 9, 12, 18, 24, 36], r),
    assay_percent: (94.5 + r() * 6).toFixed(2),
  };
}

function genClinicalTrialRow(seed, idx) {
  const r = seededRand(seed);
  return {
    id: idx,
    trial_id: `VFL-${2021 + Math.floor(r() * 6)}-${1000 + Math.floor(r() * 9000)}`,
    phase: pick(['I', 'II', 'IIb', 'III', 'IV'], r),
    drug_name: pick(DRUGS, r),
    principal_investigator: `Dr. ${pick(DOCTOR_FIRST, r)} ${pick(DOCTOR_LAST, r)}`,
    enrolled_subjects: 24 + Math.floor(r() * 2400),
    site_country: pick(['US', 'CA', 'GB', 'DE', 'FR', 'ES', 'JP', 'AU'], r),
  };
}

function genInvestigatorPaymentRow(seed, idx) {
  const r = seededRand(seed);
  const year = 2023 + Math.floor(r() * 4);
  const month = 1 + Math.floor(r() * 12);
  const day = 1 + Math.floor(r() * 28);
  return {
    id: idx,
    investigator: `Dr. ${pick(DOCTOR_FIRST, r)} ${pick(DOCTOR_LAST, r)}`,
    trial_id: `VFL-${year}-${1000 + Math.floor(r() * 9000)}`,
    amount_usd: (2500 + r() * 150000).toFixed(2),
    payment_date: `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`,
    approval_status: pick(['APPROVED', 'PENDING_COMPLIANCE', 'HELD', 'REVIEWED'], r),
  };
}

function tableNameFromQuery(q) {
  const match =
    q.match(/\bfrom\s+(?:`?[\w-]+`?\.)?`?([\w-]+)`?/i) ||
    q.match(/\btables\s+from\s+`?([\w-]+)`?/i);
  return match?.[1] || null;
}

function requestedLimit(q, fallback = 25, max = 250) {
  const match = q.match(/\blimit\s+(\d+)/i);
  const n = match ? Number.parseInt(match[1], 10) : fallback;
  if (!Number.isFinite(n) || n < 1) return fallback;
  return Math.min(n, max);
}

function columnsForTable(table) {
  return (TABLE_COLUMNS[table] || []).map(([name]) => name);
}

function rowForTable(table, seed, idx) {
  switch (table) {
    case 'invoices':
      return genInvoiceRow(seed);
    case 'lab_results':
      return genLabResultRow(seed);
    case 'batch_records':
      return genBatchRecordRow(seed, idx);
    case 'stability_studies':
      return genStabilityStudyRow(seed, idx);
    case 'clinical_trials':
      return genClinicalTrialRow(seed, idx);
    case 'investigator_payments':
      return genInvestigatorPaymentRow(seed, idx);
    case 'password_backup':
      return genLeakedCredRow(seed, idx);
    default:
      return {};
  }
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

function lenencInt(n) {
  if (n < 0xfb) return Buffer.from([n]);
  if (n <= 0xffff) return Buffer.from([0xfc, n & 0xff, (n >> 8) & 0xff]);
  if (n <= 0xffffff) return Buffer.from([0xfd, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff]);
  const b = Buffer.alloc(9);
  b[0] = 0xfe;
  b.writeBigUInt64LE(BigInt(n), 1);
  return b;
}

function lenencString(value) {
  const buf = Buffer.from(value == null ? '' : String(value));
  return Buffer.concat([lenencInt(buf.length), buf]);
}

function buildHandshakeV10() {
  // Old vulnerable version string so scanners flag it
  const version = '5.5.23-0ubuntu0.14.04.1';
  const caps =
    0x00000001 | // CLIENT_LONG_PASSWORD
    0x00000200 | // CLIENT_PROTOCOL_41
    0x00002000 | // CLIENT_TRANSACTIONS
    0x00008000 | // CLIENT_SECURE_CONNECTION
    0x00020000 | // CLIENT_MULTI_RESULTS
    0x00080000; // CLIENT_PLUGIN_AUTH
  const serverVersion = Buffer.from(version + '\0');
  const connId = Buffer.from([0x08, 0x00, 0x00, 0x00]);
  const authPart1 = Buffer.from('vflab202', 'ascii');
  const authPart2 = Buffer.from('6legacyprobe', 'ascii');
  const filler = Buffer.from([0x00]);
  const capLower = Buffer.from([caps & 0xff, (caps >> 8) & 0xff]);
  const charset = Buffer.from([0x21]); // utf8
  const status = Buffer.from([0x02, 0x00]);
  const capUpper = Buffer.from([(caps >> 16) & 0xff, (caps >> 24) & 0xff]);
  const authPluginLen = Buffer.from([21]);
  const reserved = Buffer.alloc(10, 0);
  const authPluginName = Buffer.from('mysql_native_password\0');

  const payload = Buffer.concat([
    Buffer.from([0x0a]), // protocol version
    serverVersion,
    connId,
    authPart1,
    filler,
    capLower,
    charset,
    status,
    capUpper,
    authPluginLen,
    reserved,
    authPart2,
    Buffer.from([0x00]),
    authPluginName,
  ]);
  return buildMySQLPacket(payload, 0);
}

function buildOKPacket(sequence = 1, affected = 0, lastInsert = 0) {
  const payload = Buffer.concat([
    Buffer.from([0x00]), // OK header
    lenencInt(affected),
    lenencInt(lastInsert),
    Buffer.from([0x02, 0x00]), // SERVER_STATUS_AUTOCOMMIT
    Buffer.from([0x00, 0x00]), // warnings
  ]);
  return buildMySQLPacket(payload, sequence);
}

function buildERRPacket(code, msg, sequence = 1) {
  const msgBuf = Buffer.from(msg);
  const payload = Buffer.concat([
    Buffer.from([0xff]),
    Buffer.from([code & 0xff, (code >> 8) & 0xff]),
    Buffer.from('#'),
    Buffer.from('HY000'),
    msgBuf,
  ]);
  return buildMySQLPacket(payload, sequence);
}

// Very minimal result set for SELECT (column count + rows)
function buildResultSet(columns, rows) {
  // Column count packet
  const colCount = lenencInt(columns.length);
  let packets = [buildMySQLPacket(colCount, 1)];

  // Column definitions (simplified)
  for (const col of columns) {
    const name = String(col);
    const colDef = Buffer.concat([
      lenencString('def'), // catalog
      lenencString(''), // schema
      lenencString(''), // table
      lenencString(''), // org table
      lenencString(name),
      lenencString(name),
      Buffer.from([0x0c]), // fixed fields length
      Buffer.from([0x21, 0x00]), // character set
      Buffer.from([0xff, 0xff, 0x00, 0x00]), // column length
      Buffer.from([0xfd]), // VAR_STRING
      Buffer.from([0x00, 0x00]), // flags
      Buffer.from([0x00]), // decimals
      Buffer.from([0x00, 0x00]), // filler
    ]);
    packets.push(buildMySQLPacket(colDef, packets.length + 1));
  }

  // EOF after columns
  packets.push(buildMySQLPacket(Buffer.from([0xfe, 0x00, 0x00, 0x02, 0x00]), packets.length + 1));

  // Rows
  for (const row of rows) {
    const values = Object.values(row).map((v) => {
      if (v == null) return Buffer.from([0xfb]);
      return lenencString(v);
    });
    const rowBuf = Buffer.concat(values);
    packets.push(buildMySQLPacket(rowBuf, packets.length + 1));
  }

  // Final EOF
  packets.push(buildMySQLPacket(Buffer.from([0xfe, 0x00, 0x00, 0x02, 0x00]), packets.length + 1));

  return Buffer.concat(packets);
}

// ─── Query router + pharma data generation ────────────────────────────────────
function handleQuery(query, socket) {
  const q = query.toLowerCase().replace(/`/g, '').trim();
  console.log(`[mysql-honeypot] query="${query.slice(0, 120)}"`);

  if (q === 'select 1' || q.startsWith('select 1 ')) {
    socket.write(buildResultSet(['1'], [{ 1: 1 }]));
    return;
  }

  if (q.includes('version()') || q.startsWith('select @@version') || q.startsWith('show variables like')) {
    socket.write(
      buildResultSet(
        ['VERSION()', 'USER()', 'DATABASE()'],
        [{ 'VERSION()': '5.5.23-0ubuntu0.14.04.1', 'USER()': 'root@%', 'DATABASE()': null }],
      ),
    );
    return;
  }

  if (q.startsWith('use ')) {
    socket.write(buildOKPacket(1));
    return;
  }

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

  if (q.includes('information_schema.schemata')) {
    socket.write(buildResultSet(['schema_name'], DATABASES.map((schema_name) => ({ schema_name }))));
    return;
  }

  if (q.includes('information_schema.tables')) {
    const rows = [];
    for (const table_schema of DATABASES) {
      for (const table_name of TABLES) rows.push({ table_schema, table_name });
    }
    socket.write(buildResultSet(['table_schema', 'table_name'], rows.slice(0, requestedLimit(q, rows.length, rows.length))));
    return;
  }

  if (q.startsWith('show tables')) {
    const db = q.match(/\bfrom\s+([\w-]+)/)?.[1] || 'pharma_erp';
    const col = `Tables_in_${db}`;
    const cols = [col];
    const rows = TABLES.map((table) => ({ [col]: table }));
    socket.write(buildResultSet(cols, rows));
    return;
  }

  if (q.startsWith('describe ') || q.startsWith('desc ') || q.startsWith('show columns from ')) {
    const table = q.match(/\b(?:describe|desc|from)\s+(?:[\w-]+\.)?([\w-]+)/)?.[1];
    const cols = ['Field', 'Type', 'Null', 'Key', 'Default', 'Extra'];
    const rows = (TABLE_COLUMNS[table] || []).map(([Field, Type, Null, Key, Default, Extra]) => ({
      Field,
      Type,
      Null,
      Key,
      Default,
      Extra,
    }));
    socket.write(rows.length ? buildResultSet(cols, rows) : buildERRPacket(1146, `Table '${table || 'unknown'}' doesn't exist`));
    return;
  }

  if (q.startsWith('show create table')) {
    const table = q.match(/\btable\s+(?:[\w-]+\.)?([\w-]+)/)?.[1];
    const cols = ['Table', 'Create Table'];
    const colDefs = (TABLE_COLUMNS[table] || [])
      .map(([name, type, nullable, key, defaultValue, extra]) => {
        const nullSql = nullable === 'NO' ? 'NOT NULL' : 'DEFAULT NULL';
        const keySql = key === 'PRI' ? ' PRIMARY KEY' : key === 'UNI' ? ' UNIQUE KEY' : '';
        const defaultSql = defaultValue == null ? '' : ` DEFAULT '${defaultValue}'`;
        const extraSql = extra ? ` ${extra}` : '';
        return `  \`${name}\` ${type} ${nullSql}${defaultSql}${extraSql}${keySql}`;
      })
      .join(',\n');
    const create = `CREATE TABLE \`${table || 'unknown'}\` (\n${colDefs}\n) ENGINE=InnoDB DEFAULT CHARSET=utf8`;
    socket.write(table && TABLE_COLUMNS[table] ? buildResultSet(cols, [{ Table: table, 'Create Table': create }]) : buildERRPacket(1146, 'Table does not exist'));
    return;
  }

  if (q.startsWith('select') && q.includes('count(')) {
    const table = tableNameFromQuery(q);
    const count = table === 'password_backup' ? 2000000 : table && TABLES.includes(table) ? 48291 : 0;
    socket.write(buildResultSet(['COUNT(*)'], [{ 'COUNT(*)': count }]));
    return;
  }

  if (q.startsWith('select')) {
    const table = tableNameFromQuery(q);
    if (table && TABLES.includes(table)) {
      const limit = requestedLimit(q, table === 'password_backup' ? 100 : 25, table === 'password_backup' ? 2000 : 250);
      const cols = columnsForTable(table);
      const rows = [];
      for (let i = 0; i < limit; i++) rows.push(rowForTable(table, `${table}:${i}`, i));
      socket.write(buildResultSet(cols, rows));
      return;
    }
  }

  if (q.startsWith('show grants')) {
    socket.write(buildResultSet(['Grants for root@%'], [{ 'Grants for root@%': 'GRANT ALL PRIVILEGES ON *.* TO root@% WITH GRANT OPTION' }]));
    return;
  }

  // Default OK for other queries (SHOW, USE, etc.)
  socket.write(buildOKPacket(1));
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

      while (buffer.length >= 4) {
        const packetLen = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16);
        const sequence = buffer[3];
        if (buffer.length < 4 + packetLen) return;

        const payload = buffer.slice(4, 4 + packetLen);
        buffer = buffer.slice(4 + packetLen);

        if (!authed) {
          // Consume handshake response, always reply OK (no real auth).
          // Use sequence+1 so stock mysql clients stay in command phase.
          console.log(`[mysql-honeypot] auth attempt from ${remote}`);
          socket.write(buildOKPacket(sequence + 1));
          authed = true;
          continue;
        }

        const command = payload[0];
        if (command === 0x01) {
          socket.end();
          return;
        }

        if (command === 0x03) {
          const query = payload.slice(1).toString('utf8');
          handleQuery(query, socket);
          continue;
        }

        socket.write(buildERRPacket(1047, 'Unknown command', 1));
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
