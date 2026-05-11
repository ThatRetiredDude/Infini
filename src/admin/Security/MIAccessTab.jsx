import { useState, useEffect, useCallback } from 'react';
import { API_BASE } from './shared.jsx';
import ExportShareBar from './ExportShareBar.jsx';

export default function MIAccessTab({ toast }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({ ip: '', ua_like: '', referer_like: '', token_null: '', since: '', until: '' });
  const [page, setPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const limit = 100;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * limit;
      const params = new URLSearchParams({ limit, offset });
      if (filter.ip) params.set('ip', filter.ip);
      if (filter.ua_like) params.set('ua_like', filter.ua_like);
      if (filter.referer_like) params.set('referer_like', filter.referer_like);
      if (filter.token_null) params.set('token_null', filter.token_null);
      if (filter.since) params.set('since', filter.since);
      if (filter.until) params.set('until', filter.until);
      const res = await fetch(`${API_BASE}/admin/security/mi-access?${params}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed');
      setRows(data.rows || []);
      setTotalCount(data.totalCount || 0);
      setTotalPages(Math.max(1, Math.ceil((data.totalCount || 0) / limit)));
    } catch (e) {
      toast('error', 'Failed to load MI access log: ' + e.message);
    } finally {
      setLoading(false);
    }
  }, [page, filter, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const flt = (k, v) => { setFilter((f) => ({ ...f, [k]: v })); setPage(1); };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-xl font-semibold text-zinc-100">MI Access Log</h2>
          <p className="text-zinc-400 text-sm mt-0.5">
            {totalCount.toLocaleString()} total hits. Rows with no token = direct hidden-link follower.
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <ExportShareBar rows={rows} filename="mi-access" source="mi_access" filters={filter} toast={toast} />
          <button onClick={load} disabled={loading}
            className="px-4 py-2 rounded-lg bg-indigo-500 hover:bg-indigo-600 disabled:opacity-50 text-white text-sm font-medium transition-colors">
            {loading ? 'Loading…' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Quick-toggle tokenless rows */}
      <div className="flex gap-2">
        <button
          onClick={() => flt('token_null', filter.token_null === 'true' ? '' : 'true')}
          className={`px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors ${
            filter.token_null === 'true'
              ? 'border-rose-500/60 bg-rose-500/15 text-rose-300'
              : 'border-zinc-700 text-zinc-400 hover:border-zinc-500'
          }`}
        >
          Tokenless only
        </button>
        <button
          onClick={() => setFilter({ ip: '', ua_like: '', referer_like: '', token_null: '', since: '', until: '' })}
          className="px-3 py-1.5 rounded-lg border border-zinc-700 text-zinc-500 hover:text-zinc-300 text-xs transition-colors"
        >
          Clear filters
        </button>
      </div>

      {/* Filters */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3 p-4 bg-zinc-900/50 rounded-xl border border-zinc-700">
        {[
          { key: 'ip', label: 'IP', placeholder: '1.2.3.4' },
          { key: 'ua_like', label: 'UA contains', placeholder: 'python-requests…' },
          { key: 'referer_like', label: 'Referrer contains', placeholder: 'reddit.com' },
        ].map(({ key, label, placeholder }) => (
          <div key={key}>
            <label className="block text-xs text-zinc-400 mb-1">{label}</label>
            <input type="text" value={filter[key]} onChange={(e) => flt(key, e.target.value)}
              placeholder={placeholder}
              className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none" />
          </div>
        ))}
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Token</label>
          <select value={filter.token_null} onChange={(e) => flt('token_null', e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none">
            <option value="">All</option>
            <option value="true">No token (direct follow)</option>
            <option value="false">Has token (SPA load)</option>
          </select>
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

      {/* Table */}
      <div className="rounded-xl border border-zinc-700 overflow-hidden overflow-x-auto">
        <table className="w-full text-sm text-left min-w-[700px]">
          <thead className="bg-zinc-900/80 border-b border-zinc-700">
            <tr>
              {['Time', 'IP', 'User Agent', 'Referrer', 'Token'].map((h) => (
                <th key={h} className="px-4 py-3 text-xs font-semibold text-zinc-400 uppercase tracking-wide">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {loading && <tr><td colSpan={5} className="px-4 py-8 text-zinc-500 italic text-center">Loading…</td></tr>}
            {!loading && rows.length === 0 && <tr><td colSpan={5} className="px-4 py-8 text-zinc-500 italic text-center">No rows.</td></tr>}
            {!loading && rows.map((r) => (
              <tr key={r.id} className={`hover:bg-zinc-800/40 ${!r.token ? 'border-l-2 border-rose-500/50' : ''}`}>
                <td className="px-4 py-2.5 text-zinc-400 text-xs whitespace-nowrap">{new Date(r.hit_at).toLocaleString()}</td>
                <td className="px-4 py-2.5 font-mono text-xs text-zinc-200">{r.ip || '—'}</td>
                <td className="px-4 py-2.5 text-zinc-400 text-xs max-w-xs truncate" title={r.user_agent}>{r.user_agent || '—'}</td>
                <td className="px-4 py-2.5 text-zinc-400 text-xs max-w-xs truncate" title={r.referer}>{r.referer || '—'}</td>
                <td className="px-4 py-2.5">
                  {r.token
                    ? <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-[10px] text-zinc-400 font-mono">{String(r.token).slice(0, 20)}</span>
                    : <span className="px-1.5 py-0.5 rounded bg-rose-500/15 border border-rose-500/30 text-rose-300 text-[10px]">HONEYPOT</span>}
                </td>
              </tr>
            ))}
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
