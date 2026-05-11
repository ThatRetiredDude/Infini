/**
 * Fetches and caches Tor bulk exit list from Tor Project (no signup).
 */

const TOR_BULK_EXIT_URL = 'https://check.torproject.org/torbulkexitlist';
const REFRESH_INTERVAL_MS = 60 * 60 * 1000;

let _exitSet = new Set();
let _lastFetch = 0;
let _fetchPromise = null;
let _fetchCount = 0;

async function fetchExits() {
  try {
    const res = await fetch(TOR_BULK_EXIT_URL, {
      signal: AbortSignal.timeout(15000),
      headers: { 'User-Agent': 'InfiniPot-security-monitor/1.0' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const ips = text
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));
    _exitSet = new Set(ips);
    _lastFetch = Date.now();
    _fetchCount++;
    console.log(`[TOR-FEED] Loaded ${_exitSet.size} exit nodes (fetch #${_fetchCount})`);
  } catch (err) {
    console.warn(
      `[TOR-FEED] Fetch failed: ${err.message} — using cached list (${_exitSet.size} entries)`,
    );
  }
}

async function ensureFresh() {
  if (Date.now() - _lastFetch > REFRESH_INTERVAL_MS) {
    if (!_fetchPromise) {
      _fetchPromise = fetchExits().finally(() => {
        _fetchPromise = null;
      });
    }
    await _fetchPromise;
  }
}

export async function filterTorExits(ips) {
  await ensureFresh();
  return new Set(ips.filter((ip) => _exitSet.has(ip)));
}

export function getTorFeedStats() {
  return {
    count: _exitSet.size,
    last_fetch: _lastFetch ? new Date(_lastFetch).toISOString() : null,
    fetch_count: _fetchCount,
    source: TOR_BULK_EXIT_URL,
  };
}

fetchExits().catch(() => {});
setInterval(() => {
  fetchExits().catch(() => {});
}, REFRESH_INTERVAL_MS).unref();
