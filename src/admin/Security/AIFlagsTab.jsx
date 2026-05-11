import { useState, useEffect, useCallback } from 'react';
import { API_BASE, SeverityBadge, ActionBadge, ReasonChips, DisabledUsersPanel } from './shared.jsx';
import ExportShareBar from './ExportShareBar.jsx';

export default function AIFlagsTab({ toast }) {
  const [flags, setFlags] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({ severity: '', route: '', channel: '', user_id: '', ip: '', date_from: '', date_to: '' });
  const [page, setPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [expandedId, setExpandedId] = useState(null);
  const [disabling, setDisabling] = useState(false);
  const [refreshDisabled, setRefreshDisabled] = useState(0);
  const limit = 50;

  const loadFlags = useCallback(async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * limit;
      const params = new URLSearchParams({ limit, offset });
      if (filter.severity) params.set('severity', filter.severity);
      if (filter.route) params.set('route', filter.route);
      if (filter.channel) params.set('channel', filter.channel);
      if (filter.user_id) params.set('user_id', filter.user_id);
      if (filter.ip) params.set('ip', filter.ip);
      if (filter.date_from) params.set('date_from', filter.date_from);
      if (filter.date_to) params.set('date_to', filter.date_to);
      const res = await fetch(`${API_BASE}/admin/security/ai-flags?${params}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to load');
      setFlags(data.flags || []);
      setTotalCount(data.totalCount || 0);
      setTotalPages(Math.max(1, Math.ceil((data.totalCount || 0) / limit)));
    } catch (e) {
      toast('error', 'Failed to load AI flags: ' + e.message);
    } finally {
      setLoading(false);
    }
  }, [page, filter, toast]);

  useEffect(() => { loadFlags(); }, [loadFlags]);

  const manualDisable = async (userId, username) => {
    if (!userId) return;
    const reason = prompt(`Reason for disabling AI access for ${username || userId}?`);
    if (reason === null) return;
    setDisabling(true);
    try {
      const res = await fetch(`${API_BASE}/admin/ai-flags/users/${userId}/disable`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: reason || 'Manually disabled by admin' }),
      });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || 'Failed');
      toast('success', `AI access disabled for ${username || userId}`);
      setRefreshDisabled((n) => n + 1);
    } catch (e) {
      toast('error', 'Disable failed: ' + e.message);
    } finally {
      setDisabling(false);
    }
  };

  const flt = (k, v) => { setFilter((f) => ({ ...f, [k]: v })); setPage(1); };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-xl font-semibold text-zinc-100">AI Safety Flags</h2>
          <p className="text-zinc-400 text-sm mt-0.5">
            {totalCount.toLocaleString()} flagged inputs. HIGH blocks; 3 HIGHs in 24h auto-revokes access.
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <ExportShareBar rows={flags} filename="ai-flags" source="ai_flags" filters={filter} toast={toast} />
          <button onClick={loadFlags} disabled={loading}
            className="px-4 py-2 rounded-lg bg-indigo-500 hover:bg-indigo-600 disabled:opacity-50 text-white text-sm font-medium transition-colors">
            {loading ? 'Loading…' : 'Refresh'}
          </button>
        </div>
      </div>

      <div className="flex flex-wrap gap-3 text-xs">
        <span className="flex items-center gap-1.5"><SeverityBadge severity="high" /> Block + auto-revoke</span>
        <span className="flex items-center gap-1.5"><SeverityBadge severity="medium" /> Warn + defense prompt</span>
        <span className="flex items-center gap-1.5"><SeverityBadge severity="low" /> Log only</span>
      </div>

      {/* Disabled users */}
      <div className="rounded-xl border border-zinc-700 bg-zinc-900/50 p-5">
        <h3 className="text-sm font-semibold text-zinc-200 mb-4">Currently Disabled Accounts</h3>
        <DisabledUsersPanel key={refreshDisabled} toast={toast} onRestored={() => setRefreshDisabled((n) => n + 1)} />
      </div>

      {/* Filters */}
      <div className="grid grid-cols-2 md:grid-cols-7 gap-3 p-4 bg-zinc-900/50 rounded-xl border border-zinc-700">
        {[
          { key: 'severity', label: 'Severity', options: [['', 'All'], ['high', 'HIGH'], ['medium', 'MEDIUM'], ['low', 'LOW']] },
          { key: 'route', label: 'Route', options: [['', 'All'], ['chat', 'chat'], ['brief', 'brief']] },
          { key: 'channel', label: 'Channel', options: [['', 'All'], ['chat', 'chat'], ['brief', 'brief']] },
        ].map(({ key, label, options }) => (
          <div key={key}>
            <label className="block text-xs text-zinc-400 mb-1">{label}</label>
            <select value={filter[key]} onChange={(e) => flt(key, e.target.value)}
              className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none">
              {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </div>
        ))}
        {[
          { key: 'user_id', label: 'User ID', placeholder: 'Filter by user ID…' },
          { key: 'ip', label: 'IP', placeholder: 'e.g. 1.2.3.4' },
        ].map(({ key, label, placeholder }) => (
          <div key={key}>
            <label className="block text-xs text-zinc-400 mb-1">{label}</label>
            <input type="text" value={filter[key]} onChange={(e) => flt(key, e.target.value)}
              placeholder={placeholder}
              className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none" />
          </div>
        ))}
        <div>
          <label className="block text-xs text-zinc-400 mb-1">From</label>
          <input type="date" value={filter.date_from} onChange={(e) => flt('date_from', e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none" />
        </div>
        <div>
          <label className="block text-xs text-zinc-400 mb-1">To</label>
          <input type="date" value={filter.date_to} onChange={(e) => flt('date_to', e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none" />
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-zinc-700 overflow-hidden">
        <table className="w-full text-sm text-left">
          <thead className="bg-zinc-900/80 border-b border-zinc-700">
            <tr>
              {['Time', 'User', 'Route/Channel', 'Severity', 'Action', 'Reasons', 'IP', 'Actions'].map((h) => (
                <th key={h} className="px-4 py-3 text-xs font-semibold text-zinc-400 uppercase tracking-wide">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {loading && <tr><td colSpan={8} className="px-4 py-8 text-zinc-500 italic text-center">Loading…</td></tr>}
            {!loading && flags.length === 0 && <tr><td colSpan={8} className="px-4 py-8 text-zinc-500 italic text-center">No flags matching current filter.</td></tr>}
            {!loading && flags.map((f) => {
              const expanded = expandedId === f.id;
              const reasons = Array.isArray(f.reasons) ? f.reasons : [];
              return (
                <>
                  <tr key={f.id} className="hover:bg-zinc-800/40 cursor-pointer" onClick={() => setExpandedId(expanded ? null : f.id)}>
                    <td className="px-4 py-3 text-zinc-400 text-xs whitespace-nowrap">{new Date(f.created_at).toLocaleString()}</td>
                    <td className="px-4 py-3 text-zinc-200 text-xs">
                      <div>{f.username || '—'}</div>
                      <div className="text-zinc-500 font-mono text-[10px]">{String(f.user_id).slice(0, 12)}…</div>
                    </td>
                    <td className="px-4 py-3 text-zinc-400 text-xs font-mono">
                      <div>{f.route}</div>
                      {f.channel && f.channel !== f.route && <div className="text-zinc-600">{f.channel}</div>}
                    </td>
                    <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                    <td className="px-4 py-3"><ActionBadge action={f.action_taken} /></td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {reasons.slice(0, 3).map((r) => (
                          <span key={r} className="px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-[10px] text-zinc-400">{r}</span>
                        ))}
                        {reasons.length > 3 && <span className="text-[10px] text-zinc-500">+{reasons.length - 3}</span>}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-zinc-500 text-xs font-mono">{f.ip || '—'}</td>
                    <td className="px-4 py-3">
                      <button
                        onClick={(e) => { e.stopPropagation(); manualDisable(f.user_id, f.username); }}
                        disabled={disabling}
                        className="px-2 py-1 rounded bg-rose-600/20 hover:bg-rose-600/40 text-rose-300 text-[11px] font-medium border border-rose-600/30"
                      >
                        Disable AI
                      </button>
                    </td>
                  </tr>
                  {expanded && (
                    <tr key={`${f.id}-exp`} className="bg-zinc-900/60">
                      <td colSpan={8} className="px-6 py-4">
                        <div className="space-y-2">
                          <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wide mb-2">Input excerpt</div>
                          <pre className="text-xs text-zinc-300 bg-zinc-800/60 rounded-lg p-3 whitespace-pre-wrap break-all border border-zinc-700/60 max-h-48 overflow-y-auto">
                            {f.input_excerpt || '(empty)'}
                          </pre>
                          <div className="flex gap-6 text-xs text-zinc-500 mt-2">
                            <span>IP: {f.ip || '—'}</span>
                            {f.ua && <span>UA: {f.ua.slice(0, 80)}</span>}
                            {f.path && <span>Path: {f.path}</span>}
                            <span>Flag ID: {f.id}</span>
                          </div>
                          <ReasonChips reasons={reasons} />
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

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-4">
          <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}
            className="px-4 py-2 rounded-lg border border-zinc-700 text-zinc-400 hover:text-zinc-200 disabled:opacity-30 transition-colors">
            Previous
          </button>
          <span className="text-zinc-400 text-sm">Page {page} of {totalPages} ({totalCount.toLocaleString()} total)</span>
          <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages}
            className="px-4 py-2 rounded-lg border border-zinc-700 text-zinc-400 hover:text-zinc-200 disabled:opacity-30 transition-colors">
            Next
          </button>
        </div>
      )}
    </div>
  );
}
