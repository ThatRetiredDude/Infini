/**
 * server/ip-enrichment.js
 *
 * Passive IP enrichment — queries free/paid threat intelligence APIs to build
 * a profile of a suspicious IP address. All lookups are read-only, fire-and-
 * forget, and never touch the remote host directly.
 *
 * Sources (only called if the relevant integration is configured + enabled):
 *   1. ipinfo.io     — ASN, org, country, city, hosting flag (50k/mo free)
 *   2. AbuseIPDB     — abuse confidence + report count (1k/day free)
 *   3. GreyNoise     — scanner / bot classification (Community API, free)
 *
 * Results are cached in-process for 1 hour per IP so the same address hitting
 * multiple decoys doesn't burn quota. Private/loopback IPs are skipped.
 */

import { getServiceCredentials } from './integrations.js';

const _cache = new Map();
const CACHE_TTL_MS = 60 * 60 * 1000;

function cacheGet(ip) {
  const entry = _cache.get(ip);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL_MS) {
    _cache.delete(ip);
    return null;
  }
  return entry.data;
}

function cacheSet(ip, data) {
  _cache.set(ip, { ts: Date.now(), data });
  if (_cache.size > 2000) {
    let oldestKey = null;
    let oldestTs = Infinity;
    for (const [k, v] of _cache) {
      if (v.ts < oldestTs) {
        oldestTs = v.ts;
        oldestKey = k;
      }
    }
    if (oldestKey) _cache.delete(oldestKey);
  }
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of _cache) {
    if (now - entry.ts > CACHE_TTL_MS) _cache.delete(ip);
  }
}, 30 * 60 * 1000).unref();

const PRIVATE_RE = /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1$|fd|fc|localhost)/i;

function isPrivateIp(ip) {
  return !ip || PRIVATE_RE.test(ip);
}

async function queryIpInfo(ip) {
  try {
    const creds = getServiceCredentials('ipinfo');
    const token = creds?.api_key;
    const url = token
      ? `https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${token}`
      : `https://ipinfo.io/${encodeURIComponent(ip)}/json`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return null;
    const j = await res.json();
    return {
      country: j.country || null,
      region: j.region || null,
      city: j.city || null,
      org: j.org || null,
      asn: (j.org || '').split(' ')[0] || null,
      hostname: j.hostname || null,
      is_hosting:
        /amazon|google|microsoft|digitalocean|linode|vultr|ovh|cloudflare|hetzner|aws|azure|gcp|fastly|akamai/i.test(
          j.org || '',
        ),
      timezone: j.timezone || null,
    };
  } catch {
    return null;
  }
}

async function queryAbuseIpDb(ip) {
  try {
    const creds = getServiceCredentials('abuseipdb');
    if (!creds?.api_key) return null;
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
    const res = await fetch(url, {
      headers: { Key: creds.api_key, Accept: 'application/json' },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const j = await res.json();
    const d = j.data || {};
    return {
      abuse_confidence: d.abuseConfidenceScore ?? null,
      total_reports: d.totalReports ?? null,
      last_reported: d.lastReportedAt || null,
      is_tor: d.isTor ?? null,
      is_public: d.isPublic ?? null,
      usage_type: d.usageType || null,
      isp: d.isp || null,
      domain: d.domain || null,
      country_code: d.countryCode || null,
    };
  } catch {
    return null;
  }
}

async function queryGreyNoise(ip) {
  try {
    const creds = getServiceCredentials('greynoise');
    const key = creds?.api_key;
    const url = `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`;
    const headers = { Accept: 'application/json' };
    if (key) headers.key = key;
    const res = await fetch(url, { headers, signal: AbortSignal.timeout(5000) });
    if (res.status === 404) return { classification: 'unknown', noise: false, riot: false };
    if (!res.ok) return null;
    const j = await res.json();
    return {
      classification: j.classification || 'unknown',
      noise: j.noise ?? false,
      riot: j.riot ?? false,
      name: j.name || null,
      link: j.link || null,
      last_seen: j.last_seen || null,
      message: j.message || null,
    };
  } catch {
    return null;
  }
}

function buildSummary(ipinfo, abuseipdb, greynoise) {
  const flags = [];
  if (ipinfo?.is_hosting) flags.push('hosting');
  if (abuseipdb?.is_tor) flags.push('tor');
  if (abuseipdb?.abuse_confidence >= 50) flags.push('high-abuse');
  else if (abuseipdb?.abuse_confidence >= 20) flags.push('moderate-abuse');
  if (greynoise?.noise) flags.push('internet-scanner');
  if (greynoise?.classification === 'malicious') flags.push('greynoise-malicious');
  if (greynoise?.classification === 'benign') flags.push('greynoise-benign');

  let threat_level = 'unknown';
  if (flags.includes('greynoise-malicious') || flags.includes('high-abuse')) threat_level = 'high';
  else if (flags.includes('moderate-abuse') || flags.includes('internet-scanner')) threat_level = 'medium';
  else if (flags.length > 0) threat_level = 'low';

  return {
    country: ipinfo?.country || abuseipdb?.country_code || null,
    org: ipinfo?.org || abuseipdb?.isp || null,
    asn: ipinfo?.asn || null,
    abuse_score: abuseipdb?.abuse_confidence ?? null,
    greynoise_class: greynoise?.classification || null,
    greynoise_name: greynoise?.name || null,
    flags,
    threat_level,
  };
}

/**
 * Enrich an IP address with passive threat intelligence.
 * Returns an object suitable for storing as JSON, or null if nothing came back.
 *
 * Options:
 *   only — string. Run only one source (e.g. 'ipinfo'). Used by integration tests.
 */
export async function enrichIp(ip, { only = null } = {}) {
  if (!ip || isPrivateIp(ip)) return null;

  if (!only) {
    const cached = cacheGet(ip);
    if (cached) return cached;
  }

  const tasks = [];
  if (!only || only === 'ipinfo') tasks.push(queryIpInfo(ip));
  else tasks.push(Promise.resolve(null));
  if (!only || only === 'abuseipdb') tasks.push(queryAbuseIpDb(ip));
  else tasks.push(Promise.resolve(null));
  if (!only || only === 'greynoise') tasks.push(queryGreyNoise(ip));
  else tasks.push(Promise.resolve(null));

  const [ipinfo, abuseipdb, greynoise] = await Promise.all(tasks);
  if (!ipinfo && !abuseipdb && !greynoise) return null;

  const result = {
    enriched_at: new Date().toISOString(),
    ipinfo: ipinfo || null,
    abuseipdb: abuseipdb || null,
    greynoise: greynoise || null,
    summary: buildSummary(ipinfo, abuseipdb, greynoise),
  };

  if (!only) cacheSet(ip, result);
  return result;
}
