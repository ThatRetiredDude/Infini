/**
 * Tails Cowrie JSON line-delimited log, inserts into network_sensor_events,
 * enriches IPs, optional CSV mirror, artifact retention under COWRIE_HOME.
 */

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { getOne, run } from './db.js';
import { enrichIp } from './ip-enrichment.js';
import { recordProtocolDecoyEvent } from './decoy-events.js';

let _interval = null;
let _lastPollMs = 0;

function networkIngestEnabled() {
  return String(process.env.INFINI_NETWORK_HONEYPOT_ENABLED || '').trim() === '1';
}

export function defaultCowrieJsonLogPath() {
  const explicit = process.env.COWRIE_JSON_LOG;
  if (explicit) return path.resolve(explicit);
  const home = process.env.COWRIE_HOME || '/data/cowrie';
  const candidates = [
    path.join(home, 'var/log/cowrie/cowrie.json'),
    path.join(home, 'log/cowrie.json'),
    path.join(home, 'var/log/cowrie.json'),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return candidates[0];
}

function readCursor(logPath) {
  const r = getOne(`SELECT byte_offset FROM ingest_file_cursor WHERE log_path = ?`, [logPath]);
  return r ? Number(r.byte_offset) || 0 : 0;
}

function writeCursor(logPath, byteOffset) {
  run(
    `INSERT INTO ingest_file_cursor (log_path, byte_offset, updated_at)
     VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
     ON CONFLICT(log_path) DO UPDATE SET
       byte_offset = excluded.byte_offset,
       updated_at = excluded.updated_at`,
    [logPath, byteOffset],
  );
}

function appendCsvLine(row) {
  const dir = process.env.ACCESS_LOG_CSV_DIR;
  if (!dir) return;
  const p = path.resolve(dir, 'network_sensor_events.csv');
  try {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const line = [
      row.hit_at,
      row.peer_ip ?? '',
      row.session_id ?? '',
      row.protocol ?? '',
      row.event_type,
      row.cowrie_eventid,
      String(row.payload_json || '').replace(/\r?\n/g, ' ').slice(0, 4000),
    ]
      .map((c) => (/,|\n|"/.test(String(c)) ? `"${String(c).replace(/"/g, '""')}"` : c))
      .join(',');
    fs.appendFileSync(p, line + '\r\n', { flag: 'a' });
  } catch (e) {
    console.warn('[cowrie-ingest] csv append failed:', e?.message || e);
  }
}

function inferProtocol(obj) {
  if (obj.protocol) return String(obj.protocol).toLowerCase().slice(0, 32);
  const eid = String(obj.eventid || '');
  if (eid.includes('telnet')) return 'telnet';
  if (eid.includes('ftp')) return 'ftp';
  return 'ssh';
}

function stableEventId(obj, rawLine) {
  if (obj.eventid && String(obj.eventid).length > 0) {
    return String(obj.eventid).slice(0, 256);
  }
  const h = createHash('sha256').update(rawLine).digest('hex').slice(0, 40);
  return `synth_${h}`;
}

function parseHitTime(obj) {
  const t = obj.timestamp || obj.time || obj.date;
  if (typeof t === 'string' && t.length > 4) {
    try {
      return new Date(t).toISOString();
    } catch {
      /* fall through */
    }
  }
  return new Date().toISOString();
}

function peerIpFrom(obj) {
  const ip = obj.src_ip || obj.peer_ip || obj.ip;
  if (!ip) return null;
  return String(ip).slice(0, 128);
}

/**
 * Poll log file once; safe to call even when file is missing (no-op).
 * @returns {number} number of new rows inserted
 */
export function pollCowrieLogOnce() {
  if (!networkIngestEnabled()) return 0;
  const logPath = defaultCowrieJsonLogPath();
  let st;
  try {
    st = fs.statSync(logPath);
  } catch {
    return 0;
  }
  if (!st.isFile() || st.size === 0) return 0;

  let offset = readCursor(logPath);
  if (st.size < offset) offset = 0;

  const toRead = st.size - offset;
  if (toRead <= 0) return 0;

  const fd = fs.openSync(logPath, 'r');
  try {
    const buf = Buffer.alloc(toRead);
    fs.readSync(fd, buf, 0, toRead, offset);
    const chunk = buf.toString('utf8');
    writeCursor(logPath, st.size);
    const lines = chunk.split(/\r?\n/).filter((l) => l.trim());

    let inserted = 0;
    for (const line of lines) {
      let obj;
      try {
        obj = JSON.parse(line);
      } catch {
        continue;
      }
      const cowrie_eventid = stableEventId(obj, line);
      const eventType = String(obj.eventid || 'unknown').slice(0, 256);
      const peerIp = peerIpFrom(obj);
      const sessionId = obj.session != null ? String(obj.session).slice(0, 128) : null;
      const sensorName = obj.sensor != null ? String(obj.sensor).slice(0, 128) : null;
      const protocol = inferProtocol(obj);
      const payloadJson = JSON.stringify(obj).slice(0, 500_000);
      const hitAt = parseHitTime(obj);

      let result;
      try {
        result = run(
          `INSERT OR IGNORE INTO network_sensor_events
             (hit_at, peer_ip, session_id, sensor_name, protocol, event_type, cowrie_eventid, payload_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            hitAt,
            peerIp,
            sessionId,
            sensorName,
            protocol,
            eventType,
            cowrie_eventid,
            payloadJson,
          ],
        );
      } catch (e) {
        console.warn('[cowrie-ingest] insert failed:', e?.message || e);
        continue;
      }

      if (!result.changes) continue;
      inserted += 1;
      _lastPollMs = Date.now();

      const rowId = Number(result.lastInsertRowid);
      appendCsvLine({
        hit_at: hitAt,
        peer_ip: peerIp,
        session_id: sessionId,
        protocol,
        event_type: eventType,
        cowrie_eventid,
        payload_json: payloadJson,
      });
      recordProtocolDecoyEvent({
        hit_at: hitAt,
        peer_ip: peerIp,
        session_id: sessionId,
        sensor_name: sensorName,
        protocol,
        event_type: eventType,
        cowrie_eventid,
        payload_json: payloadJson,
      });

      if (peerIp && peerIp !== 'unknown') {
        enrichIp(peerIp)
          .then((info) => {
            if (!info) return;
            try {
              run(`UPDATE network_sensor_events SET enrichment = ? WHERE id = ?`, [
                JSON.stringify(info),
                rowId,
              ]);
            } catch {
              /* ignore */
            }
          })
          .catch(() => {});
      }
    }
    return inserted;
  } finally {
    fs.closeSync(fd);
  }
}

/** Delete old files under Cowrie downloads dir (best-effort). */
export function runArtifactRetentionSweep() {
  const days = Math.max(1, Math.min(3650, Number(process.env.COWRIE_ARTIFACT_RETENTION_DAYS) || 14));
  const home = process.env.COWRIE_HOME || '/data/cowrie';
  const dl = path.join(home, 'var/lib/cowrie/downloads');
  const cutoff = Date.now() - days * 86400_000;
  try {
    if (!fs.existsSync(dl)) return;
    const walk = (dir) => {
      for (const name of fs.readdirSync(dir)) {
        const p = path.join(dir, name);
        let st;
        try {
          st = fs.statSync(p);
        } catch {
          continue;
        }
        if (st.isDirectory()) walk(p);
        else if (st.isFile() && st.mtimeMs < cutoff) {
          try {
            fs.unlinkSync(p);
          } catch {
            /* ignore */
          }
        }
      }
    };
    walk(dl);
  } catch (e) {
    console.warn('[cowrie-ingest] retention sweep:', e?.message || e);
  }
}

export function getCowrieIngestHealth() {
  const enabled = networkIngestEnabled();
  const logPath = defaultCowrieJsonLogPath();
  let log_exists = false;
  let log_bytes = 0;
  try {
    const st = fs.statSync(logPath);
    log_exists = st.isFile();
    log_bytes = st.size;
  } catch {
    /* missing */
  }

  const lastHit = getOne(`SELECT MAX(hit_at) AS t FROM network_sensor_events`);
  let last_event_age_sec = null;
  if (lastHit?.t) {
    const ts = new Date(lastHit.t).getTime();
    if (Number.isFinite(ts)) last_event_age_sec = Math.max(0, (Date.now() - ts) / 1000);
  }

  return {
    enabled,
    log_path: logPath,
    log_exists,
    log_bytes,
    last_event_age_sec,
    last_poll_ms_ago: _lastPollMs ? (Date.now() - _lastPollMs) / 1000 : null,
  };
}

/**
 * Start interval polling. Idempotent.
 * @returns {() => void} stop function
 */
export function startCowrieIngestLoop({ intervalMs = 3000 } = {}) {
  if (_interval) return () => {};
  if (!networkIngestEnabled()) {
    return () => {};
  }

  const tick = () => {
    try {
      pollCowrieLogOnce();
    } catch (e) {
      console.warn('[cowrie-ingest] poll error:', e?.message || e);
    }
  };
  tick();
  _interval = setInterval(tick, intervalMs);

  const retentionMs = 24 * 60 * 60 * 1000;
  const retIv = setInterval(() => {
    try {
      runArtifactRetentionSweep();
    } catch {
      /* ignore */
    }
  }, retentionMs);
  retIv.unref?.();

  return () => {
    if (_interval) {
      clearInterval(_interval);
      _interval = null;
    }
    clearInterval(retIv);
  };
}
