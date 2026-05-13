/**
 * MazeTab — Data Room Activity admin view
 *
 * Sections:
 *   1. Stats bar (pipeline estimates, est. API cost, request delay, self-IDs)
 *   2. Self-ID captures callout (highlighted, no clicking required)
 *   3. Live feed (last 20 hits, auto-refreshes every 15s)
 *   4. UA fingerprint summary + depth histogram (side by side)
 *   5. Full IP table with per-IP drill-down panel
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { API_BASE, IpCell } from './shared.jsx';
import ExportShareBar from './ExportShareBar.jsx';

// ─── helpers ──────────────────────────────────────────────────────────────────

const TOKENS_PER_PAGE = 1000;
const PRICE_PER_M = 15; // GPT-4o input, $/M tokens

function fmtTokens(n) {
  if (!n) return '0';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${Math.round(n / 1_000)}K`;
  return String(n);
}

function fmtTime(ms) {
  if (!ms) return '—';
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min`;
  const h = (m / 60).toFixed(1);
  return `${h} hr`;
}

function fmtCost(hits) {
  const tokens = hits * TOKENS_PER_PAGE * 2;
  const cost = (tokens / 1_000_000) * PRICE_PER_M;
  return cost < 0.01 ? '<$0.01' : `$${cost.toFixed(2)}`;
}

function timeDataRoom(hits) { return fmtTime(hits * 1800); }

const THREAT_COLORS = {
  high:    'text-rose-300 bg-rose-500/10 border-rose-500/40',
  medium:  'text-amber-300 bg-amber-500/10 border-amber-500/40',
  low:     'text-zinc-300 bg-zinc-700/40 border-zinc-600/40',
  unknown: 'text-zinc-600 bg-zinc-800/40 border-zinc-700/40',
};
function ThreatBadge({ level }) {
  const c = THREAT_COLORS[level] || THREAT_COLORS.unknown;
  return <span className={`px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase ${c}`}>{level || '?'}</span>;
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({ label, value, sub, color = 'text-zinc-100' }) {
  return (
    <div className="rounded-xl border border-zinc-700 bg-zinc-900/60 p-4 space-y-0.5">
      <div className="text-[10px] text-zinc-500 uppercase tracking-wide">{label}</div>
      <div className={`text-xl font-bold font-mono ${color}`}>{value ?? '—'}</div>
      {sub && <div className="text-[10px] text-zinc-600">{sub}</div>}
    </div>
  );
}

function SelfIdCallout({ rows }) {
  const captured = rows.filter((r) => r.self_id_token);
  if (captured.length === 0) return null;
  return (
    <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/5 p-4 space-y-3">
      <div className="flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
        <span className="text-emerald-300 font-semibold text-sm">{captured.length} Self-Identification{captured.length !== 1 ? 's' : ''} Captured</span>
        <span className="text-zinc-500 text-xs ml-1">— external systems that responded to access prompts</span>
      </div>
      <div className="space-y-2">
        {captured.map((r) => {
          let parsed = null;
          try { parsed = JSON.parse(r.self_id_raw); } catch { /* raw */ }
          const fields = parsed ? Object.entries(parsed).filter(([k]) => !k.startsWith('_') && !k.startsWith('APC-')).slice(0, 6) : null;
          return (
            <div key={r.id} className="rounded-lg bg-zinc-900/60 border border-emerald-500/20 p-3 text-xs space-y-1">
              <div className="flex items-center gap-3 flex-wrap">
                <span className="font-mono text-zinc-200">{r.ip}</span>
                <span className="text-zinc-500">{r.date}</span>
                <span className="text-zinc-500">hits: {r.hit_count}</span>
                <span className="font-mono text-emerald-400 text-[10px]">{r.self_id_token}</span>
              </div>
              {fields ? (
                <div className="grid grid-cols-2 md:grid-cols-3 gap-x-4 gap-y-0.5 mt-1">
                  {fields.map(([k, v]) => (
                    <div key={k} className="flex gap-1.5">
                      <span className="text-zinc-500 shrink-0">{k}:</span>
                      <span className="text-zinc-200 break-all">{String(v).slice(0, 100)}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-zinc-400 break-all">{r.self_id_raw?.slice(0, 300)}</div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function LiveFeed({ toast }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);
  const intervalRef = useRef(null);

  const fetch_ = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/admin/security/maze/live`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed');
      setRows(data.rows || []);
      setLastRefresh(new Date());
    } catch (e) {
      if (!silent) toast('error', 'Live feed error: ' + e.message);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    fetch_();
    intervalRef.current = setInterval(() => fetch_(true), 15000);
    return () => clearInterval(intervalRef.current);
  }, [fetch_]);

  return (
    <div className="rounded-xl border border-zinc-700 bg-zinc-900/50 overflow-hidden">
      <div className="px-4 py-3 border-b border-zinc-700 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-sm font-medium text-zinc-300">Live Feed</span>
          <span className="text-zinc-600 text-xs">— auto-refreshes every 15s</span>
        </div>
        <div className="flex items-center gap-3">
          {lastRefresh && <span className="text-[10px] text-zinc-600">{lastRefresh.toLocaleTimeString()}</span>}
          <button onClick={() => fetch_()} disabled={loading}
            className="px-3 py-1 rounded border border-zinc-700 text-zinc-500 hover:text-zinc-300 text-xs transition-colors disabled:opacity-40">
            {loading ? '…' : '↻'}
          </button>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-xs min-w-[700px]">
          <thead className="bg-zinc-900/80">
            <tr>
              {['IP', 'Last Active', 'Hits', 'Depth', 'Threat', 'UA', 'Self-ID'].map((h) => (
                <th key={h} className="px-3 py-2 text-[10px] text-zinc-500 uppercase tracking-wide text-left">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/60">
            {loading && rows.length === 0 && (
              <tr><td colSpan={7} className="px-3 py-4 text-zinc-600 italic text-center">Loading…</td></tr>
            )}
            {!loading && rows.length === 0 && (
              <tr><td colSpan={7} className="px-3 py-4 text-zinc-600 italic text-center">No activity yet</td></tr>
            )}
            {rows.map((r, i) => {
              const s = r.enrich_summary;
              return (
                <tr key={r.ip + r.date} className={`${i === 0 ? 'bg-violet-500/5' : ''} hover:bg-zinc-800/30`}>
                  <td className="px-3 py-1.5 font-mono text-zinc-200">{r.ip}</td>
                  <td className="px-3 py-1.5 text-zinc-500 whitespace-nowrap">{r.last_seen ? new Date(r.last_seen).toLocaleTimeString() : '—'}</td>
                  <td className="px-3 py-1.5 text-zinc-100 font-semibold">{r.hit_count}</td>
                  <td className="px-3 py-1.5 text-zinc-400">{r.max_depth}</td>
                  <td className="px-3 py-1.5">
                    {s?.threat_level ? <ThreatBadge level={s.threat_level} /> : <span className="text-zinc-700">—</span>}
                  </td>
                  <td className="px-3 py-1.5 text-zinc-500 max-w-[180px] truncate" title={r.ua}>{r.ua || '—'}</td>
                  <td className="px-3 py-1.5">
                    {r.self_id_token
                      ? <span className="text-emerald-400 text-[10px] font-bold">CAPTURED</span>
                      : <span className="text-zinc-700">—</span>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DepthHistogram({ data }) {
  if (!data?.length) return <div className="text-zinc-600 text-xs italic">No data yet</div>;
  const maxHits = Math.max(...data.map((d) => d.hits), 1);
  return (
    <div className="space-y-1.5">
      {data.map((d) => (
        <div key={d.max_depth} className="flex items-center gap-2 text-xs">
          <span className="text-zinc-500 w-14 shrink-0">Depth {d.max_depth}</span>
          <div className="flex-1 bg-zinc-800 rounded h-3 overflow-hidden">
            <div className="h-full bg-indigo-500/60 rounded transition-all"
              style={{ width: `${Math.max(2, (d.hits / maxHits) * 100)}%` }} />
          </div>
          <span className="text-zinc-400 w-24 text-right shrink-0">{d.hits?.toLocaleString()} hits · {d.ips} IP{d.ips !== 1 ? 's' : ''}</span>
        </div>
      ))}
    </div>
  );
}

function UaSummary({ data }) {
  if (!data?.length) return <div className="text-zinc-600 text-xs italic">No data yet</div>;
  const maxHits = Math.max(...data.map((d) => d.hits), 1);
  return (
    <div className="space-y-1.5">
      {data.map((d) => (
        <div key={d.family} className="flex items-center gap-2 text-xs">
          <span className="text-zinc-300 w-44 shrink-0 truncate" title={d.family}>{d.family}</span>
          <div className="flex-1 bg-zinc-800 rounded h-3 overflow-hidden">
            <div className="h-full bg-violet-500/50 rounded transition-all"
              style={{ width: `${Math.max(2, (d.hits / maxHits) * 100)}%` }} />
          </div>
          <span className="text-zinc-500 w-28 text-right shrink-0 text-[10px]">{d.hits?.toLocaleString()} hits · {d.ips} IP{d.ips !== 1 ? 's' : ''}</span>
        </div>
      ))}
    </div>
  );
}

function IpDrillDown({ ip, onClose, toast }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/admin/security/maze/ip/${encodeURIComponent(ip)}`)
      .then((r) => r.json())
      .then((d) => { setData(d); setLoading(false); })
      .catch((e) => { toast('error', 'Drill-down error: ' + e.message); setLoading(false); });
  }, [ip, toast]);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-16 px-4" onClick={onClose}>
      <div className="bg-zinc-900 border border-zinc-700 rounded-2xl shadow-2xl w-full max-w-3xl max-h-[80vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}>
        <div className="sticky top-0 bg-zinc-900 border-b border-zinc-700 px-6 py-4 flex items-center justify-between">
          <div>
            <div className="font-mono text-zinc-100 font-semibold">{ip}</div>
            <div className="text-zinc-500 text-xs">Per-IP drill-down — all sessions</div>
          </div>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-200 text-xl">✕</button>
        </div>

        {loading && <div className="px-6 py-8 text-zinc-500 italic text-center">Loading…</div>}
        {!loading && data && (
          <div className="p-6 space-y-6">
            {/* Summary stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <StatCard label="Total hits" value={Number(data.summary?.total_hits || 0).toLocaleString()} color="text-zinc-100" />
              <StatCard label="Active days" value={data.summary?.total_days} color="text-indigo-300" />
              <StatCard label="Max depth reached" value={data.summary?.deepest} color="text-violet-300" />
              <StatCard label="Peak hits/day" value={data.summary?.peak_hits_day?.toLocaleString()} color="text-amber-300" />
            </div>

            {/* Token / cost / time */}
            <div className="rounded-xl border border-zinc-700 bg-zinc-800/40 px-5 py-4 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
              <div>
                <div className="text-zinc-500 mb-0.5">Tokens generated</div>
                <div className="text-zinc-200 font-semibold font-mono">{fmtTokens(data.summary?.tokens_generated)}</div>
              </div>
              <div>
                <div className="text-zinc-500 mb-0.5">LLM pipeline est.</div>
                <div className="text-violet-300 font-semibold font-mono">{fmtTokens(data.summary?.tokens_pipeline_est)}</div>
              </div>
              <div>
                <div className="text-zinc-500 mb-0.5">Est. API cost burned</div>
                <div className="text-emerald-300 font-bold font-mono">{fmtCost(Number(data.summary?.total_hits || 0))}</div>
                <div className="text-zinc-600 text-[10px]">at GPT-4o rate</div>
              </div>
              <div>
                <div className="text-zinc-500 mb-0.5">Data room delay time</div>
                <div className="text-amber-300 font-semibold">{timeDataRoom(Number(data.summary?.total_hits || 0))}</div>
                <div className="text-zinc-600 text-[10px]">~1.8s avg delay/req</div>
              </div>
            </div>

            {/* Enrichment */}
            {data.summary?.enrichment && (() => {
              const e = typeof data.summary.enrichment === 'string'
                ? JSON.parse(data.summary.enrichment) : data.summary.enrichment;
              return (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                  {e.ipinfo && (
                    <div className="rounded-lg bg-zinc-800/60 border border-zinc-700/60 p-3 space-y-1">
                      <div className="text-zinc-400 font-semibold text-[10px] uppercase tracking-wide">IPInfo</div>
                      {e.ipinfo.country && <div className="text-zinc-300">Country: <span className="text-zinc-100">{e.ipinfo.country}{e.ipinfo.city ? ` / ${e.ipinfo.city}` : ''}</span></div>}
                      {e.ipinfo.org && <div className="text-zinc-300 break-all">Org: <span className="text-zinc-100">{e.ipinfo.org}</span></div>}
                      {e.ipinfo.hostname && <div className="text-zinc-300 font-mono break-all">{e.ipinfo.hostname}</div>}
                      {e.ipinfo.is_hosting && <div className="text-amber-300">⚠ Hosting/Cloud</div>}
                    </div>
                  )}
                  {e.abuseipdb && (
                    <div className="rounded-lg bg-zinc-800/60 border border-zinc-700/60 p-3 space-y-1">
                      <div className="text-zinc-400 font-semibold text-[10px] uppercase tracking-wide">AbuseIPDB</div>
                      <div className="text-zinc-300">Score: <span className={`font-bold ${(e.abuseipdb.abuse_confidence ?? 0) >= 50 ? 'text-rose-300' : 'text-emerald-300'}`}>{e.abuseipdb.abuse_confidence ?? '—'}%</span></div>
                      {e.abuseipdb.total_reports != null && <div className="text-zinc-400">{e.abuseipdb.total_reports} reports</div>}
                      {e.abuseipdb.is_tor && <div className="text-rose-300">TOR exit node</div>}
                      {e.abuseipdb.isp && <div className="text-zinc-400 break-all">{e.abuseipdb.isp}</div>}
                    </div>
                  )}
                  {e.greynoise && (
                    <div className="rounded-lg bg-zinc-800/60 border border-zinc-700/60 p-3 space-y-1">
                      <div className="text-zinc-400 font-semibold text-[10px] uppercase tracking-wide">GreyNoise</div>
                      <div className="text-zinc-300">Class: <span className={`font-bold ${e.greynoise.classification === 'malicious' ? 'text-rose-300' : e.greynoise.classification === 'benign' ? 'text-emerald-300' : 'text-zinc-300'}`}>{e.greynoise.classification}</span></div>
                      {e.greynoise.noise && <div className="text-amber-300">Known internet scanner</div>}
                      {e.greynoise.name && <div className="text-zinc-300">{e.greynoise.name}</div>}
                    </div>
                  )}
                </div>
              );
            })()}

            {/* UA */}
            {data.summary?.top_ua && (
              <div className="text-xs">
                <div className="text-zinc-500 mb-1">User-agent</div>
                <div className="font-mono text-zinc-300 bg-zinc-800/60 rounded p-2 break-all">{data.summary.top_ua}</div>
              </div>
            )}

            {/* Per-day timeline */}
            <div>
              <div className="text-zinc-400 font-semibold text-xs uppercase tracking-wide mb-2">Daily Timeline</div>
              <div className="rounded-xl border border-zinc-700 overflow-hidden overflow-x-auto">
                <table className="w-full text-xs min-w-[500px]">
                  <thead className="bg-zinc-900/80">
                    <tr>
                      {['Date', 'Hits', 'Max Depth', 'Delay Time', 'Tokens (pipeline)', 'Self-ID'].map((h) => (
                        <th key={h} className="px-3 py-2 text-[10px] text-zinc-500 uppercase tracking-wide text-left">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800">
                    {data.days?.map((d) => (
                      <tr key={d.date} className="hover:bg-zinc-800/30">
                        <td className="px-3 py-1.5 text-zinc-300 whitespace-nowrap">{d.date}</td>
                        <td className="px-3 py-1.5 text-zinc-100 font-semibold">{d.hit_count}</td>
                        <td className="px-3 py-1.5 text-zinc-400">{d.max_depth}</td>
                        <td className="px-3 py-1.5 text-amber-300">{timeDataRoom(d.hit_count)}</td>
                        <td className="px-3 py-1.5 text-violet-300 font-mono">{fmtTokens(d.hit_count * TOKENS_PER_PAGE * 2)}</td>
                        <td className="px-3 py-1.5">
                          {d.self_id_token
                            ? <span className="text-emerald-400 text-[10px] font-bold">CAPTURED</span>
                            : <span className="text-zinc-700">—</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Main tab ─────────────────────────────────────────────────────────────────

export default function MazeTab({ toast, readOnly = false }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState(null);
  const [filter, setFilter] = useState({ ip: '', since: '', until: '', self_id_only: false });
  const [page, setPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [drillIp, setDrillIp] = useState(null);
  const limit = 100;

  const loadRows = useCallback(async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * limit;
      const params = new URLSearchParams({ limit, offset });
      if (filter.ip) params.set('ip', filter.ip);
      if (filter.since) params.set('since', filter.since);
      if (filter.until) params.set('until', filter.until);
      if (filter.self_id_only) params.set('self_id_only', 'true');
      const res = await fetch(`${API_BASE}/admin/security/maze?${params}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed');
      setRows(data.rows || []);
      setTotalCount(data.totalCount || 0);
      setTotalPages(Math.max(1, Math.ceil((data.totalCount || 0) / limit)));
    } catch (e) {
      toast('error', 'Failed to load data room hits: ' + e.message);
    } finally {
      setLoading(false);
    }
  }, [page, filter, toast]);

  const loadStats = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/admin/security/maze/stats`);
      const data = await res.json();
      if (res.ok) setStats(data);
    } catch { /* stats are non-critical */ }
  }, []);

  useEffect(() => { loadRows(); }, [loadRows]);
  useEffect(() => { loadStats(); }, [loadStats]);

  const flt = (k, v) => { setFilter((f) => ({ ...f, [k]: v })); setPage(1); };
  const t = stats?.totals || {};

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-xl font-semibold text-zinc-100">Data Room Activity</h2>
          <p className="text-zinc-400 text-sm mt-0.5">
            {totalCount.toLocaleString()} unique IP·day combinations.
            {t.unique_ips > 0 && <span className="ml-2">{t.unique_ips.toLocaleString()} total unique IPs.</span>}
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <ExportShareBar rows={rows} filename="data-room-hits" source="maze" filters={filter} toast={toast} readOnly={readOnly} />
          <button onClick={() => { loadRows(); loadStats(); }} disabled={loading}
            className="px-4 py-2 rounded-lg bg-indigo-500 hover:bg-indigo-600 disabled:opacity-50 text-white text-sm font-medium transition-colors">
            {loading ? 'Loading…' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Stats bar */}
      {t.total_hits > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <StatCard label="Total data room requests" value={Number(t.total_hits).toLocaleString()} color="text-zinc-100" />
          <StatCard label="Tokens generated" value={fmtTokens(t.tokens_generated)} sub="~1K/page" color="text-indigo-300" />
          <StatCard label="LLM pipeline est." value={fmtTokens(t.tokens_pipeline_est)} sub="input + output" color="text-violet-300" />
          <StatCard label="Est. API cost" value={`$${t.cost_usd_est?.toLocaleString(undefined, { minimumFractionDigits: 2 })}`} sub="pipeline estimate" color="text-emerald-300" />
          <StatCard label="Request delay time" value={fmtTime(t.time_ms_est)} sub="~1.8s avg delay/req" color="text-amber-300" />
        </div>
      )}

      {/* Self-ID callout */}
      <SelfIdCallout rows={rows} />

      {/* Live feed */}
      <LiveFeed toast={toast} />

      {/* UA summary + depth histogram */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="rounded-xl border border-zinc-700 bg-zinc-900/50 p-4">
            <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wide mb-3">Request UA Fingerprints</div>
            <UaSummary data={stats.ua_summary} />
          </div>
          <div className="rounded-xl border border-zinc-700 bg-zinc-900/50 p-4">
            <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wide mb-3">Max Depth Distribution</div>
            <DepthHistogram data={stats.depth_histogram} />
            <div className="mt-3 text-[10px] text-zinc-600">
              Depth 0–1 = quick probe · Depth 5+ = sustained data-room traversal
            </div>
          </div>
        </div>
      )}

      {/* How it works (collapsed) */}
      <details className="rounded-xl border border-zinc-700/60 bg-zinc-900/30">
        <summary className="px-4 py-3 text-xs text-zinc-500 cursor-pointer hover:text-zinc-300 transition-colors select-none">
          How the data room works — 1,000,000+ pages ▾
        </summary>
        <div className="px-4 pb-4 text-xs text-zinc-500 space-y-1 border-t border-zinc-700/40 pt-3">
          <div>Entry: <code className="text-zinc-300">GET /api/secrets/explore</code> + <code className="text-zinc-300">/api/secrets/explore/sitemap.xml</code> — off-screen data-room links</div>
          <div>Structure: SHA-256 UUID tree, 10 children × 10 pages per node = 1.2M addressable URLs at depth 5</div>
          <div>Page types: Investment Memo · Counterparty Profile · Deal Room Index · Wire Reconciliation (deterministic by SHA256(pathId)[2]%4)</div>
          <div>Content: 80–120 entries per word list → billions of unique title/body combos. Every page is distinct.</div>
          <div>Delays: scanner-like UAs get 1500–3000ms; depth adds 150ms/level. Depth 5 waits 2–4s per request.</div>
          <div>Self-ID capture: 3 external access prompts per page (JSON field, plaintext block, HTML comment) → POST /api/secrets/explore/identify</div>
          <div>robots.txt: Disallow + sitemap listing exposes restricted-looking data-room paths.</div>
          <div>Deduplication: UNIQUE(ip, date) — 1 row per IP per day, hit_count accumulates.</div>
        </div>
      </details>

      {/* Filters */}
      <div className="flex flex-wrap gap-2 items-center">
        <button onClick={() => flt('self_id_only', !filter.self_id_only)}
          className={`px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors ${
            filter.self_id_only ? 'border-emerald-500/60 bg-emerald-500/15 text-emerald-300' : 'border-zinc-700 text-zinc-400 hover:border-zinc-500'
          }`}>
          Self-ID captures only
        </button>
        <button onClick={() => setFilter({ ip: '', since: '', until: '', self_id_only: false })}
          className="px-3 py-1.5 rounded-lg border border-zinc-700 text-zinc-500 hover:text-zinc-300 text-xs transition-colors">
          Clear filters
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 p-4 bg-zinc-900/50 rounded-xl border border-zinc-700">
        <div>
          <label className="block text-xs text-zinc-400 mb-1">IP</label>
          <input type="text" value={filter.ip} onChange={(e) => flt('ip', e.target.value)} placeholder="1.2.3.4"
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none" />
        </div>
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Since</label>
          <input type="date" value={filter.since} onChange={(e) => flt('since', e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none" />
        </div>
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Until</label>
          <input type="date" value={filter.until} onChange={(e) => flt('until', e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none" />
        </div>
      </div>

      {/* IP table */}
      <div className="rounded-xl border border-zinc-700 overflow-hidden overflow-x-auto">
        <table className="w-full text-sm text-left min-w-[900px]">
          <thead className="bg-zinc-900/80 border-b border-zinc-700">
            <tr>
              {['IP / Intel', 'Threat', 'Date', 'Hits', 'Delay Time', 'Tokens (pipeline)', 'Depth', 'UA', 'Self-ID'].map((h) => (
                <th key={h} className="px-3 py-3 text-[10px] font-semibold text-zinc-400 uppercase tracking-wide">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {loading && <tr><td colSpan={9} className="px-4 py-8 text-zinc-500 italic text-center">Loading…</td></tr>}
            {!loading && rows.length === 0 && (
              <tr><td colSpan={9} className="px-4 py-8 text-zinc-500 italic text-center">No data room hits yet. Monitoring is active.</td></tr>
            )}
            {!loading && rows.map((r) => {
              const s = r.enrichment?.summary;
              return (
                <tr key={r.id}
                  className={`hover:bg-zinc-800/40 cursor-pointer ${r.self_id_token ? 'border-l-2 border-emerald-500/60' : ''}`}
                  onClick={() => setDrillIp(r.ip)}>
                  <td className="px-3 py-2.5">
                    <IpCell ip={r.ip} enrichment={r.enrichment}
                      isTor={r.enrichment?.abuseipdb?.is_tor || false}
                      isRepeat={(r.distinct_days || 0) >= 5}
                      onClick={() => setDrillIp(r.ip)} />
                    {s?.greynoise_name && <div className="text-zinc-600 text-[10px] mt-0.5">{s.greynoise_name}</div>}
                  </td>
                  <td className="px-3 py-2.5">
                    {s ? <ThreatBadge level={s.threat_level} /> : <span className="text-zinc-700 text-[10px]">—</span>}
                  </td>
                  <td className="px-3 py-2.5 text-zinc-500 text-xs whitespace-nowrap">{r.date}</td>
                  <td className="px-3 py-2.5 text-zinc-100 font-bold text-sm">{r.hit_count?.toLocaleString()}</td>
                  <td className="px-3 py-2.5 text-amber-300 text-xs">{timeDataRoom(r.hit_count)}</td>
                  <td className="px-3 py-2.5 text-violet-300 text-xs font-mono">{fmtTokens(r.hit_count * TOKENS_PER_PAGE * 2)}</td>
                  <td className="px-3 py-2.5">
                    <div className="flex items-center gap-1.5">
                      <div className="w-12 bg-zinc-800 rounded h-1.5 overflow-hidden">
                        <div className="h-full bg-indigo-500/70 rounded" style={{ width: `${Math.min(100, (r.max_depth / 8) * 100)}%` }} />
                      </div>
                      <span className="text-zinc-300 text-xs">{r.max_depth}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2.5 text-zinc-500 text-xs max-w-[140px] truncate" title={r.ua}>{r.ua || '—'}</td>
                  <td className="px-3 py-2.5">
                    {r.self_id_token
                      ? <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-[10px] font-bold">CAPTURED</span>
                      : <span className="text-zinc-700 text-[10px]">—</span>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-4">
          <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}
            className="px-4 py-2 rounded-lg border border-zinc-700 text-zinc-400 hover:text-zinc-200 disabled:opacity-30 transition-colors">
            Previous
          </button>
          <span className="text-zinc-400 text-sm">Page {page} of {totalPages}</span>
          <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages}
            className="px-4 py-2 rounded-lg border border-zinc-700 text-zinc-400 hover:text-zinc-200 disabled:opacity-30 transition-colors">
            Next
          </button>
        </div>
      )}

      {/* Per-IP drill-down modal */}
      {drillIp && <IpDrillDown ip={drillIp} onClose={() => setDrillIp(null)} toast={toast} />}
    </div>
  );
}
