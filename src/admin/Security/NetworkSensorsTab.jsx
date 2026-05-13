import { useState, useEffect, useCallback, Fragment } from 'react';
import { API_BASE, IpCell } from './shared.jsx';
import ExportShareBar from './ExportShareBar.jsx';

function EnrichmentPanel({ enrichment }) {
  if (!enrichment) {
    return <div className="text-zinc-600 text-xs italic">Enrichment pending…</div>;
  }
  const { summary, ipinfo, abuseipdb, greynoise } = enrichment;
  return (
    <div className="space-y-3 text-xs">
      {summary?.flags?.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {summary.flags.map((f) => (
            <span key={f} className="px-1.5 py-0.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-[10px]">{f}</span>
          ))}
        </div>
      )}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {ipinfo && (
          <div className="rounded-lg bg-zinc-800/60 border border-zinc-700/60 p-3 space-y-1">
            <div className="text-zinc-400 font-semibold text-[10px] uppercase tracking-wide">IPInfo</div>
            {ipinfo.country && <div className="text-zinc-300">Country: <span className="text-zinc-100">{ipinfo.country}</span></div>}
            {ipinfo.org && <div className="text-zinc-300 break-all">Org: <span className="text-zinc-100">{ipinfo.org}</span></div>}
          </div>
        )}
        {abuseipdb && (
          <div className="rounded-lg bg-zinc-800/60 border border-zinc-700/60 p-3 space-y-1">
            <div className="text-zinc-400 font-semibold text-[10px] uppercase tracking-wide">AbuseIPDB</div>
            <div className="text-zinc-300">Abuse score: <span className="font-bold text-amber-300">{abuseipdb.abuse_confidence ?? '—'}%</span></div>
          </div>
        )}
        {greynoise && (
          <div className="rounded-lg bg-zinc-800/60 border border-zinc-700/60 p-3 space-y-1">
            <div className="text-zinc-400 font-semibold text-[10px] uppercase tracking-wide">GreyNoise</div>
            <div className="text-zinc-300">Class: <span className="font-bold">{greynoise.classification || 'unknown'}</span></div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function NetworkSensorsTab({ toast, readOnly = false }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({ ip: '', protocol: '', event_type: '', since: '', until: '' });
  const [page, setPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [expandedId, setExpandedId] = useState(null);
  const [stats, setStats] = useState(null);
  const limit = 100;

  const loadStats = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/admin/security/network-sensor/stats`);
      const st = res.ok ? await res.json().catch(() => null) : null;
      if (st) setStats(st);
    } catch { /* non-critical */ }
  }, []);

  useEffect(() => { loadStats(); }, [loadStats]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * limit;
      const params = new URLSearchParams({ limit, offset });
      if (filter.ip) params.set('ip', filter.ip);
      if (filter.protocol) params.set('protocol', filter.protocol);
      if (filter.event_type) params.set('event_type', filter.event_type);
      if (filter.since) params.set('since', filter.since);
      if (filter.until) params.set('until', filter.until);
      const res = await fetch(`${API_BASE}/admin/security/network-sensor?${params}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed');
      setRows(data.rows || []);
      setTotalCount(data.totalCount || 0);
      setTotalPages(Math.max(1, Math.ceil((data.totalCount || 0) / limit)));
    } catch (e) {
      toast('error', 'Failed to load network sensor events: ' + e.message);
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
          <h2 className="text-xl font-semibold text-zinc-100">SSH / Telnet Decoys</h2>
          <p className="text-zinc-400 text-sm mt-0.5">
            {totalCount.toLocaleString()} SSH, Telnet, and FTP-style events from Cowrie logs. Expand a row for payload + threat intel.
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <ExportShareBar rows={rows} filename="network-sensor-events" source="network_sensor" filters={filter} toast={toast} readOnly={readOnly} />
          <button onClick={() => { loadStats(); load(); }} disabled={loading}
            className="px-4 py-2 rounded-lg bg-indigo-500 hover:bg-indigo-600 disabled:opacity-50 text-white text-sm font-medium transition-colors">
            {loading ? 'Loading…' : 'Refresh'}
          </button>
        </div>
      </div>

      {stats?.totals && (
        <div className="rounded-xl border border-zinc-700 bg-zinc-900/40 p-4 space-y-4">
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Aggregates</div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 text-center">
            {[
              ['All-time events', stats.totals.events_all],
              ['24h', stats.totals.events_24h],
              ['7d', stats.totals.events_7d],
              ['Distinct IPs (24h)', stats.totals.distinct_ips_24h],
              ['Distinct IPs (all)', stats.totals.distinct_ips_all],
            ].map(([label, val]) => (
              <div key={label} className="rounded-lg border border-zinc-800 bg-zinc-950/60 px-3 py-2">
                <div className="text-[9px] text-zinc-500 uppercase">{label}</div>
                <div className="text-lg font-mono font-semibold text-cyan-200">{Number(val || 0).toLocaleString()}</div>
              </div>
            ))}
          </div>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <div className="text-[10px] text-zinc-500 uppercase mb-2">By protocol (7d)</div>
              <ul className="text-xs space-y-1 max-h-32 overflow-y-auto">
                {(stats.by_protocol || []).map((r) => (
                  <li key={r.protocol} className="flex justify-between gap-2 text-zinc-300 border-b border-zinc-800/80 pb-1">
                    <span className="font-mono">{r.protocol || '—'}</span>
                    <span className="text-zinc-500">{Number(r.hits).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <div className="text-[10px] text-zinc-500 uppercase mb-2">Top protocol event types (7d)</div>
              <ul className="text-xs space-y-1 max-h-32 overflow-y-auto font-mono">
                {(stats.by_event || []).slice(0, 14).map((r, i) => (
                  <li key={i} className="flex justify-between gap-2 text-zinc-400 border-b border-zinc-800/80 pb-1">
                    <span className="truncate" title={r.event_type}>{r.event_type}</span>
                    <span className="shrink-0">{Number(r.hits).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 p-4 bg-zinc-900/50 rounded-xl border border-zinc-700">
        {[
          { key: 'protocol', label: 'Protocol', placeholder: 'ssh', type: 'text' },
          { key: 'event_type', label: 'Event type contains', placeholder: 'cowrie.login', type: 'text' },
          { key: 'ip', label: 'Peer IP', placeholder: '1.2.3.4', type: 'text' },
        ].map(({ key, label, placeholder, type }) => (
          <div key={key}>
            <label className="block text-xs text-zinc-400 mb-1">{label}</label>
            <input type={type} value={filter[key]} onChange={(e) => flt(key, e.target.value)}
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

      <div className="rounded-xl border border-zinc-700 overflow-hidden overflow-x-auto">
        <table className="w-full text-sm text-left min-w-[900px]">
          <thead className="bg-zinc-900/80 border-b border-zinc-700">
            <tr>
              {['Time', 'IP', 'Protocol', 'Event', 'Session', 'Intel'].map((h) => (
                <th key={h} className="px-4 py-3 text-xs font-semibold text-zinc-400 uppercase tracking-wide">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {loading && <tr><td colSpan={6} className="px-4 py-8 text-zinc-500 italic text-center">Loading…</td></tr>}
            {!loading && rows.length === 0 && <tr><td colSpan={6} className="px-4 py-8 text-zinc-500 italic text-center">No network sensor events yet.</td></tr>}
            {!loading && rows.map((r) => {
              const expanded = expandedId === r.id;
              return (
                <Fragment key={r.id}>
                  <tr className="hover:bg-zinc-800/40 cursor-pointer" onClick={() => setExpandedId(expanded ? null : r.id)}>
                    <td className="px-4 py-2.5 text-zinc-400 text-xs whitespace-nowrap">{new Date(r.hit_at).toLocaleString()}</td>
                    <td className="px-4 py-2.5">
                      <IpCell ip={r.peer_ip} enrichment={r.enrichment} isTor={r.enrichment?.abuseipdb?.is_tor || false} />
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-cyan-300">{r.protocol || '—'}</td>
                    <td className="px-4 py-2.5 text-zinc-400 text-xs max-w-xs truncate font-mono" title={r.event_type}>{r.event_type}</td>
                    <td className="px-4 py-2.5 text-zinc-500 text-[10px] font-mono truncate max-w-[100px]" title={r.session_id}>{r.session_id || '—'}</td>
                    <td className="px-4 py-2.5 text-zinc-600 text-[10px]">{r.enrichment ? 'yes' : '…'}</td>
                  </tr>
                  {expanded && (
                    <tr className="bg-zinc-900/60">
                      <td colSpan={6} className="px-6 py-4">
                        <EnrichmentPanel enrichment={r.enrichment} />
                        <pre className="mt-3 text-xs text-zinc-400 bg-zinc-800/60 rounded p-3 overflow-x-auto max-h-48 overflow-y-auto border border-zinc-700/60">
                          {JSON.stringify(r.payload_json, null, 2)}
                        </pre>
                        <div className="text-[10px] text-zinc-600 mt-2">Event id: {r.cowrie_eventid} · Row {r.id}</div>
                      </td>
                    </tr>
                  )}
                </Fragment>
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
