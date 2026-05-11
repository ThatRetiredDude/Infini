import { useState, useEffect, useCallback } from 'react';
import { API_BASE, IpCell } from './shared.jsx';
import ExportShareBar from './ExportShareBar.jsx';

const SOURCE_LABELS = {
  system_prompt_probe: 'System Prompt Probe',
  dossier_dump_probe: 'Dossier Dump Probe',
  eval_probe: 'Eval Probe',
  eval_results_probe: 'Eval Results Probe',
};

const SOURCE_COLORS = {
  system_prompt_probe: 'text-rose-300 bg-rose-500/10 border-rose-500/30',
  dossier_dump_probe: 'text-amber-300 bg-amber-500/10 border-amber-500/30',
  eval_probe: 'text-violet-300 bg-violet-500/10 border-violet-500/30',
  eval_results_probe: 'text-sky-300 bg-sky-500/10 border-sky-500/30',
};

const THREAT_COLORS = {
  high: 'text-rose-300 bg-rose-500/10 border-rose-500/40',
  medium: 'text-amber-300 bg-amber-500/10 border-amber-500/40',
  low: 'text-zinc-300 bg-zinc-700/40 border-zinc-600/40',
  unknown: 'text-zinc-500 bg-zinc-800/40 border-zinc-700/40',
};

function SourceBadge({ source }) {
  const c = SOURCE_COLORS[source] || 'text-zinc-400 bg-zinc-700/40 border-zinc-600/40';
  return (
    <span className={`px-1.5 py-0.5 rounded border text-[10px] font-medium ${c}`}>
      {SOURCE_LABELS[source] || source}
    </span>
  );
}

function ThreatBadge({ level }) {
  const c = THREAT_COLORS[level] || THREAT_COLORS.unknown;
  return (
    <span className={`px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase ${c}`}>
      {level || '?'}
    </span>
  );
}

function EnrichmentPanel({ enrichment }) {
  if (!enrichment) {
    return <div className="text-zinc-600 text-xs italic">Enrichment pending…</div>;
  }
  const { summary, ipinfo, abuseipdb, greynoise } = enrichment;
  return (
    <div className="space-y-3 text-xs">
      {/* Summary flags */}
      {summary?.flags?.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {summary.flags.map((f) => (
            <span key={f} className="px-1.5 py-0.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-[10px]">{f}</span>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* ipinfo */}
        {ipinfo && (
          <div className="rounded-lg bg-zinc-800/60 border border-zinc-700/60 p-3 space-y-1">
            <div className="text-zinc-400 font-semibold text-[10px] uppercase tracking-wide">IPInfo</div>
            {ipinfo.country && <div className="text-zinc-300">Country: <span className="text-zinc-100">{ipinfo.country}</span>{ipinfo.city ? ` / ${ipinfo.city}` : ''}</div>}
            {ipinfo.org && <div className="text-zinc-300 break-all">Org: <span className="text-zinc-100">{ipinfo.org}</span></div>}
            {ipinfo.hostname && <div className="text-zinc-300 break-all">Hostname: <span className="text-zinc-100 font-mono">{ipinfo.hostname}</span></div>}
            {ipinfo.is_hosting && <div className="text-amber-300">⚠ Hosting / Cloud provider</div>}
          </div>
        )}

        {/* AbuseIPDB */}
        {abuseipdb && (
          <div className="rounded-lg bg-zinc-800/60 border border-zinc-700/60 p-3 space-y-1">
            <div className="text-zinc-400 font-semibold text-[10px] uppercase tracking-wide">AbuseIPDB</div>
            <div className="text-zinc-300">Abuse score: <span className={`font-bold ${(abuseipdb.abuse_confidence ?? 0) >= 50 ? 'text-rose-300' : (abuseipdb.abuse_confidence ?? 0) >= 20 ? 'text-amber-300' : 'text-emerald-300'}`}>{abuseipdb.abuse_confidence ?? '—'}%</span></div>
            {abuseipdb.total_reports != null && <div className="text-zinc-300">Reports: <span className="text-zinc-100">{abuseipdb.total_reports}</span></div>}
            {abuseipdb.is_tor && <div className="text-rose-300">TOR exit node</div>}
            {abuseipdb.usage_type && <div className="text-zinc-300">Usage: <span className="text-zinc-100">{abuseipdb.usage_type}</span></div>}
            {abuseipdb.isp && <div className="text-zinc-300 break-all">ISP: <span className="text-zinc-100">{abuseipdb.isp}</span></div>}
          </div>
        )}

        {/* GreyNoise */}
        {greynoise && (
          <div className="rounded-lg bg-zinc-800/60 border border-zinc-700/60 p-3 space-y-1">
            <div className="text-zinc-400 font-semibold text-[10px] uppercase tracking-wide">GreyNoise</div>
            <div className="text-zinc-300">Classification: <span className={`font-bold ${greynoise.classification === 'malicious' ? 'text-rose-300' : greynoise.classification === 'benign' ? 'text-emerald-300' : 'text-zinc-300'}`}>{greynoise.classification || 'unknown'}</span></div>
            {greynoise.noise && <div className="text-amber-300">Known internet scanner</div>}
            {greynoise.riot && <div className="text-emerald-300">Known good (CDN/DNS)</div>}
            {greynoise.name && <div className="text-zinc-300">Name: <span className="text-zinc-100">{greynoise.name}</span></div>}
            {greynoise.last_seen && <div className="text-zinc-500">Last seen: {greynoise.last_seen}</div>}
          </div>
        )}
      </div>
    </div>
  );
}

export default function HoneypotTab({ toast }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({ ip: '', source: '', ua_like: '', since: '', until: '' });
  const [page, setPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [expandedId, setExpandedId] = useState(null);
  const [hpStats, setHpStats] = useState(null);
  const [hpLures, setHpLures] = useState(null);
  const limit = 100;

  const loadMeta = useCallback(async () => {
    try {
      const [statsRes, luresRes] = await Promise.all([
        fetch(`${API_BASE}/admin/security/honeypot/stats`),
        fetch(`${API_BASE}/admin/security/lures`),
      ]);
      const st = statsRes.ok ? await statsRes.json().catch(() => null) : null;
      const lu = luresRes.ok ? await luresRes.json().catch(() => null) : null;
      if (st) setHpStats(st);
      if (lu?.rows) setHpLures(lu);
    } catch {
      /* non-critical */
    }
  }, []);

  useEffect(() => {
    loadMeta();
  }, [loadMeta]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * limit;
      const params = new URLSearchParams({ limit, offset });
      if (filter.ip) params.set('ip', filter.ip);
      if (filter.source) params.set('source', filter.source);
      if (filter.ua_like) params.set('ua_like', filter.ua_like);
      if (filter.since) params.set('since', filter.since);
      if (filter.until) params.set('until', filter.until);
      const res = await fetch(`${API_BASE}/admin/security/honeypot?${params}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed');
      setRows(data.rows || []);
      setTotalCount(data.totalCount || 0);
      setTotalPages(Math.max(1, Math.ceil((data.totalCount || 0) / limit)));
    } catch (e) {
      toast('error', 'Failed to load decoy hits: ' + e.message);
    } finally {
      setLoading(false);
    }
  }, [page, filter, toast]);

  useEffect(() => { load(); }, [load]);

  const flt = (k, v) => { setFilter((f) => ({ ...f, [k]: v })); setPage(1); };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-xl font-semibold text-zinc-100">Decoy Endpoint Hits</h2>
          <p className="text-zinc-400 text-sm mt-0.5">
            {totalCount.toLocaleString()} hits on decoy AI endpoints. Any hit here is automated.
            Expand a row to see passive threat intelligence.
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <ExportShareBar rows={rows} filename="decoy-hits" source="honeypot" filters={filter} toast={toast} />
          <button onClick={() => { loadMeta(); load(); }} disabled={loading}
            className="px-4 py-2 rounded-lg bg-indigo-500 hover:bg-indigo-600 disabled:opacity-50 text-white text-sm font-medium transition-colors">
            {loading ? 'Loading…' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Decoy endpoints legend */}
      <div className="rounded-xl border border-zinc-700 bg-zinc-900/50 p-4 text-xs space-y-1.5">
        <div className="text-zinc-400 font-semibold mb-2 uppercase tracking-wide text-[10px]">Active Decoy Endpoints</div>
        {[
          ['GET /api/ai/system-prompt', 'system_prompt_probe', 'Returns bait "system prompt" object'],
          ['GET /api/ai/internal/dossier-dump', 'dossier_dump_probe', 'Returns bait paginated dossier structure'],
          ['POST /api/ai/eval', 'eval_probe', 'Returns bait eval job response (202)'],
          ['GET /api/ai/explore', '—', 'Spider trap — infinite procedural document tree (see Maze tab)'],
        ].map(([path, src, desc]) => (
          <div key={path} className="flex items-start gap-3">
            <code className="text-zinc-300 font-mono w-64 shrink-0">{path}</code>
            {src !== '—' ? <SourceBadge source={src} /> : <span className="text-zinc-600 text-[10px]">maze</span>}
            <span className="text-zinc-500">{desc}</span>
          </div>
        ))}
      </div>

      {/* Roll-ups + lure inventory */}
      {hpStats?.totals && (
        <div className="rounded-xl border border-zinc-700 bg-zinc-900/40 p-4 space-y-4">
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Aggregates</div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-center">
            {[
              ['All-time hits', hpStats.totals.hits_all],
              ['24h', hpStats.totals.hits_24h],
              ['7d', hpStats.totals.hits_7d],
              ['Distinct IPs (24h)', hpStats.totals.distinct_ips_24h],
              ['Distinct IPs (all)', hpStats.totals.distinct_ips_all],
              ['Sources seen', hpStats.totals.distinct_sources_seen],
            ].map(([label, val]) => (
              <div key={label} className="rounded-lg border border-zinc-800 bg-zinc-950/60 px-3 py-2">
                <div className="text-[9px] text-zinc-500 uppercase">{label}</div>
                <div className="text-lg font-mono font-semibold text-indigo-200">{Number(val || 0).toLocaleString()}</div>
              </div>
            ))}
          </div>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <div className="text-[10px] text-zinc-500 uppercase mb-2">By source (7d)</div>
              <ul className="text-xs space-y-1 max-h-36 overflow-y-auto">
                {(hpStats.by_source || []).slice(0, 12).map((r) => (
                  <li key={r.source} className="flex justify-between gap-2 text-zinc-300 border-b border-zinc-800/80 pb-1">
                    <span className="font-mono truncate">{r.source}</span>
                    <span className="text-zinc-500 shrink-0">{Number(r.hits).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <div className="text-[10px] text-zinc-500 uppercase mb-2">Top paths (24h)</div>
              <ul className="text-xs space-y-1 max-h-36 overflow-y-auto font-mono">
                {(hpStats.top_paths || []).slice(0, 10).map((r, i) => (
                  <li key={i} className="flex justify-between gap-2 text-zinc-400 border-b border-zinc-800/80 pb-1">
                    <span className="truncate" title={r.path}>{r.path || '—'}</span>
                    <span className="shrink-0">{Number(r.hits).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {hpLures?.rows && hpLures.rows.length > 0 && (
        <div className="rounded-xl border border-zinc-700 overflow-hidden">
          <div className="px-4 py-2 bg-zinc-900 border-b border-zinc-700 text-[10px] font-semibold text-zinc-400 uppercase tracking-wide">
            Mounted lures inventory
          </div>
          <div className="max-h-52 overflow-y-auto">
            <table className="w-full text-xs text-left">
              <thead className="bg-zinc-900/80 sticky top-0 text-zinc-500">
                <tr>
                  <th className="px-3 py-2">Source</th>
                  <th className="px-3 py-2">Path</th>
                  <th className="px-3 py-2 text-right">Hits</th>
                  <th className="px-3 py-2">Last hit</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800">
                {hpLures.rows.slice(0, 60).map((r) => (
                  <tr key={r.source} className="text-zinc-300 hover:bg-zinc-900/40">
                    <td className="px-3 py-1.5 font-mono text-[11px]">{r.source}</td>
                    <td className="px-3 py-1.5 text-zinc-500 max-w-[200px] truncate" title={r.path}>{r.path}</td>
                    <td className="px-3 py-1.5 text-right tabular-nums">{Number(r.hits || 0).toLocaleString()}</td>
                    <td className="px-3 py-1.5 text-zinc-500 whitespace-nowrap">{r.last_hit ? new Date(r.last_hit).toLocaleString() : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 p-4 bg-zinc-900/50 rounded-xl border border-zinc-700">
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Source</label>
          <select value={filter.source} onChange={(e) => flt('source', e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none">
            <option value="">All</option>
            {Object.entries(SOURCE_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </div>
        {[
          { key: 'ip', label: 'IP', placeholder: '1.2.3.4' },
          { key: 'ua_like', label: 'UA contains', placeholder: 'python-requests…' },
        ].map(({ key, label, placeholder }) => (
          <div key={key}>
            <label className="block text-xs text-zinc-400 mb-1">{label}</label>
            <input type="text" value={filter[key]} onChange={(e) => flt(key, e.target.value)}
              placeholder={placeholder}
              className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none" />
          </div>
        ))}
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

      {/* Table */}
      <div className="rounded-xl border border-zinc-700 overflow-hidden overflow-x-auto">
        <table className="w-full text-sm text-left min-w-[900px]">
          <thead className="bg-zinc-900/80 border-b border-zinc-700">
            <tr>
              {['Time', 'IP', 'Threat', 'Source', 'Method', 'User Agent', 'Intel'].map((h) => (
                <th key={h} className="px-4 py-3 text-xs font-semibold text-zinc-400 uppercase tracking-wide">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {loading && <tr><td colSpan={7} className="px-4 py-8 text-zinc-500 italic text-center">Loading…</td></tr>}
            {!loading && rows.length === 0 && <tr><td colSpan={7} className="px-4 py-8 text-zinc-500 italic text-center">No decoy hits yet.</td></tr>}
            {!loading && rows.map((r) => {
              const expanded = expandedId === r.id;
              const enrich = r.enrichment;
              const summary = enrich?.summary;
              return (
                <>
                  <tr key={r.id} className="hover:bg-zinc-800/40 cursor-pointer" onClick={() => setExpandedId(expanded ? null : r.id)}>
                    <td className="px-4 py-2.5 text-zinc-400 text-xs whitespace-nowrap">{new Date(r.hit_at).toLocaleString()}</td>
                    <td className="px-4 py-2.5">
                      <IpCell ip={r.ip} enrichment={r.enrichment}
                        isTor={r.enrichment?.abuseipdb?.is_tor || false} />
                    </td>
                    <td className="px-4 py-2.5">
                      {summary ? <ThreatBadge level={summary.threat_level} /> : <span className="text-zinc-700 text-[10px]">—</span>}
                    </td>
                    <td className="px-4 py-2.5"><SourceBadge source={r.source} /></td>
                    <td className="px-4 py-2.5 font-mono text-xs text-zinc-400">{r.method}</td>
                    <td className="px-4 py-2.5 text-zinc-400 text-xs max-w-xs truncate" title={r.ua}>{r.ua || '—'}</td>
                    <td className="px-4 py-2.5">
                      {summary?.flags?.length > 0
                        ? <div className="flex flex-wrap gap-1">{summary.flags.slice(0, 2).map((f) => <span key={f} className="px-1 py-0.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-[10px]">{f}</span>)}</div>
                        : <span className="text-zinc-700 text-[10px]">{enrich ? 'clean' : '…'}</span>}
                    </td>
                  </tr>
                  {expanded && (
                    <tr key={`${r.id}-exp`} className="bg-zinc-900/60">
                      <td colSpan={7} className="px-6 py-4">
                        <div className="space-y-4">
                          <EnrichmentPanel enrichment={r.enrichment} />
                          {r.body_excerpt && (
                            <div>
                              <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wide mb-1">Request body</div>
                              <pre className="text-xs text-zinc-300 bg-zinc-800/60 rounded p-3 whitespace-pre-wrap break-all border border-zinc-700/60 max-h-40 overflow-y-auto">
                                {r.body_excerpt}
                              </pre>
                            </div>
                          )}
                          <div className="flex gap-6 text-xs text-zinc-500">
                            {r.referer && <span>Referer: {r.referer}</span>}
                            {r.token && <span>Token param: {r.token}</span>}
                            <span>Hit ID: {r.id}</span>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
          </tbody>
        </table>
      </div>

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
    </div>
  );
}
