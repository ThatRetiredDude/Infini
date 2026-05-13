import { Fragment, useCallback, useEffect, useState } from 'react';
import { API_BASE, SeverityBadge, ReasonChips } from './shared.jsx';

const SOURCE_LABELS = {
  honeypot: 'HTTP Decoy',
  fake_data: 'Fake Data',
  protocol: 'SSH / Telnet',
  access_trail: 'Access Trail',
  submitted_input: 'Submitted Input',
};

function JsonBlock({ value }) {
  if (!value) return null;
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  if (!text || text === '{}') return null;
  return (
    <pre className="text-xs text-zinc-400 bg-zinc-800/60 rounded p-3 overflow-x-auto max-h-48 overflow-y-auto border border-zinc-700/60">
      {text}
    </pre>
  );
}

export default function EventLogTable({ toast, mode = 'requests' }) {
  const isAbuse = mode === 'abuse';
  const [armed, setArmed] = useState(isAbuse);
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [expandedId, setExpandedId] = useState(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [filter, setFilter] = useState({
    source: '',
    decoy_id: '',
    action: '',
    severity: '',
    ip: '',
    method: '',
    protocol: '',
    event_type: '',
    path_contains: '',
    has_payload: '',
    since: '',
    until: '',
    sort: 'newest',
  });
  const limit = 100;

  const load = useCallback(async () => {
    if (!armed) return;
    setLoading(true);
    try {
      const offset = (page - 1) * limit;
      const params = new URLSearchParams({ limit, offset, sort: filter.sort || 'newest' });
      Object.entries(filter).forEach(([key, value]) => {
        if (value && key !== 'sort') params.set(key, value);
      });
      const endpoint = isAbuse ? 'abuse-logs' : 'requests';
      const res = await fetch(`${API_BASE}/admin/security/${endpoint}?${params}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed');
      setRows(data.rows || []);
      setTotalCount(data.totalCount || 0);
      setTotalPages(Math.max(1, Math.ceil((data.totalCount || 0) / limit)));
    } catch (e) {
      toast('error', `Failed to load ${isAbuse ? 'abuse logs' : 'requests'}: ${e.message}`);
    } finally {
      setLoading(false);
    }
  }, [armed, filter, isAbuse, page, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const flt = (key, value) => {
    setFilter((f) => ({ ...f, [key]: value }));
    setPage(1);
  };

  if (!armed) {
    return (
      <div className="rounded-xl border border-zinc-700 bg-zinc-900/50 p-6 space-y-4">
        <div>
          <h2 className="text-xl font-semibold text-zinc-100">All Requests</h2>
          <p className="text-zinc-400 text-sm mt-1">
            Full raw request and protocol event review is loaded on demand so the dashboard stays fast.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setArmed(true)}
          className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium"
        >
          Load request logs
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-xl font-semibold text-zinc-100">{isAbuse ? 'Abuse Logs' : 'All Requests'}</h2>
          <p className="text-zinc-400 text-sm mt-0.5">
            {totalCount.toLocaleString()} {isAbuse ? 'suspicious events' : 'captured events'} across decoys and submitted inputs.
          </p>
        </div>
        <button onClick={load} disabled={loading}
          className="px-4 py-2 rounded-lg bg-indigo-500 hover:bg-indigo-600 disabled:opacity-50 text-white text-sm font-medium transition-colors">
          {loading ? 'Loading…' : 'Refresh'}
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-6 gap-3 p-4 bg-zinc-900/50 rounded-xl border border-zinc-700">
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Source</label>
          <select value={filter.source} onChange={(e) => flt('source', e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300">
            <option value="">All</option>
            <option value="honeypot">HTTP Decoys</option>
            <option value="fake_data">Fake Data</option>
            <option value="protocol">SSH / Telnet</option>
            <option value="access_trail">Access Trail</option>
            <option value="submitted_input">Submitted Input</option>
          </select>
        </div>
        {[
          ['decoy_id', 'Decoy ID', 'password_dump'],
          ['action', 'Action', 'download_attempt'],
          ['ip', 'IP', '1.2.3.4'],
          ['path_contains', 'Path contains', '/admin'],
          ['event_type', 'Event type', 'login'],
          ['protocol', 'Protocol', 'ssh'],
          ['method', 'Method', 'POST'],
        ].map(([key, label, placeholder]) => (
          <div key={key}>
            <label className="block text-xs text-zinc-400 mb-1">{label}</label>
            <input value={filter[key]} onChange={(e) => flt(key, e.target.value)} placeholder={placeholder}
              className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300 placeholder-zinc-500" />
          </div>
        ))}
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Payload</label>
          <select value={filter.has_payload} onChange={(e) => flt('has_payload', e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300">
            <option value="">Any</option>
            <option value="true">Has payload</option>
            <option value="false">No payload</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Severity</label>
          <select value={filter.severity} onChange={(e) => flt('severity', e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300">
            <option value="">All</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Sort</label>
          <select value={filter.sort} onChange={(e) => flt('sort', e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300">
            <option value="newest">Newest</option>
            <option value="oldest">Oldest</option>
            <option value="severity">Severity</option>
            <option value="ip_frequency">IP frequency</option>
            <option value="payload_size">Payload size</option>
            <option value="action">Action</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Since</label>
          <input type="date" value={filter.since} onChange={(e) => flt('since', e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300" />
        </div>
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Until</label>
          <input type="date" value={filter.until} onChange={(e) => flt('until', e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1.5 text-sm text-zinc-300" />
        </div>
      </div>

      <div className="rounded-xl border border-zinc-700 overflow-hidden overflow-x-auto">
        <table className="w-full text-sm text-left min-w-[1100px]">
          <thead className="bg-zinc-900/80 border-b border-zinc-700">
            <tr>
              {['Time', 'Source', 'Decoy', 'Action', 'Severity', 'IP', 'Method / Protocol', 'Path'].map((h) => (
                <th key={h} className="px-4 py-3 text-xs font-semibold text-zinc-400 uppercase tracking-wide">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {loading && <tr><td colSpan={8} className="px-4 py-8 text-zinc-500 italic text-center">Loading…</td></tr>}
            {!loading && rows.length === 0 && <tr><td colSpan={8} className="px-4 py-8 text-zinc-500 italic text-center">No events matching current filters.</td></tr>}
            {!loading && rows.map((r) => {
              const expanded = expandedId === r.id;
              return (
                <Fragment key={r.id}>
                  <tr className="hover:bg-zinc-800/40 cursor-pointer" onClick={() => setExpandedId(expanded ? null : r.id)}>
                    <td className="px-4 py-2.5 text-zinc-400 text-xs whitespace-nowrap">{new Date(r.created_at).toLocaleString()}</td>
                    <td className="px-4 py-2.5 text-zinc-300 text-xs">{SOURCE_LABELS[r.source] || r.source}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-zinc-300">{r.decoy_id}</td>
                    <td className="px-4 py-2.5 text-zinc-400 text-xs">{r.action}</td>
                    <td className="px-4 py-2.5"><SeverityBadge severity={r.severity} /></td>
                    <td className="px-4 py-2.5 font-mono text-xs text-zinc-300">{r.ip || '—'}</td>
                    <td className="px-4 py-2.5 text-xs text-zinc-400">{r.method || r.protocol || '—'} {r.event_type ? `· ${r.event_type}` : ''}</td>
                    <td className="px-4 py-2.5 text-zinc-500 text-xs max-w-xs truncate" title={r.path}>{r.path || '—'}</td>
                  </tr>
                  {expanded && (
                    <tr className="bg-zinc-900/60">
                      <td colSpan={8} className="px-6 py-4 space-y-3">
                        <ReasonChips reasons={r.reasons} />
                        <div className="grid md:grid-cols-2 gap-3 text-xs">
                          <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 space-y-1">
                            <div className="text-zinc-500 uppercase tracking-wide text-[10px]">Request</div>
                            <div className="text-zinc-300">UA: {r.user_agent || '—'}</div>
                            <div className="text-zinc-300">Referer: {r.referer || '—'}</div>
                            <div className="text-zinc-300">Token: {r.token || '—'}</div>
                            <div className="text-zinc-300">Body hash: {r.body_hash || '—'}</div>
                          </div>
                          <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 space-y-1">
                            <div className="text-zinc-500 uppercase tracking-wide text-[10px]">Event</div>
                            <div className="text-zinc-300">Type: {r.event_type || '—'}</div>
                            <div className="text-zinc-300">Session: {r.session_key || '—'}</div>
                            <div className="text-zinc-300">Payload size: {Number(r.payload_size || 0).toLocaleString()} bytes</div>
                          </div>
                        </div>
                        {r.body_excerpt && (
                          <pre className="text-xs text-zinc-300 bg-zinc-800/60 rounded p-3 whitespace-pre-wrap break-all border border-zinc-700/60 max-h-48 overflow-y-auto">
                            {r.body_excerpt}
                          </pre>
                        )}
                        <JsonBlock value={r.headers_excerpt} />
                        <JsonBlock value={r.payload_json} />
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
