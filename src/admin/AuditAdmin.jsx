import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';

export default function AuditAdmin({ onToast }) {
  const [entries, setEntries] = useState([]);
  const [cursor, setCursor] = useState(null);
  const [totalApprox, setTotalApprox] = useState(0);
  const [loading, setLoading] = useState(true);

  const toast = useCallback((type, text) => onToast?.({ type, text }), [onToast]);

  const loadInitial = useCallback(async () => {
    setLoading(true);
    try {
      const first = await api.get('/api/admin/audit?limit=40');
      setEntries(Array.isArray(first.entries) ? first.entries : []);
      setCursor(first.next_cursor || null);
      setTotalApprox(first.total_approx || 0);
    } catch (e) {
      toast('error', e.message || String(e));
      setEntries([]);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  const loadMore = useCallback(async () => {
    if (!cursor) return;
    try {
      const next = await api.get(`/api/admin/audit?limit=40&after=${encodeURIComponent(cursor)}`);
      setEntries((prev) => [...prev, ...(next.entries || [])]);
      setCursor(next.next_cursor || null);
      setTotalApprox(next.total_approx || 0);
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }, [cursor, toast]);

  useEffect(() => {
    loadInitial();
  }, [loadInitial]);

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl text-ink-100 font-semibold">Audit log</h2>
        <p className="text-xs text-ink-500 mt-1">
          {totalApprox ? `~${totalApprox} rows (approx)` : ''}{' '}
          {loading ? 'Loading…' : ''}
        </p>
      </div>

      <div className="rounded-lg border border-ink-700 overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-ink-900 text-ink-400">
            <tr>
              <th className="p-2">ID</th>
              <th className="p-2">When</th>
              <th className="p-2">Action</th>
              <th className="p-2">Actor</th>
              <th className="p-2">Target</th>
              <th className="p-2">IP</th>
              <th className="p-2">Payload</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((row) => (
              <tr key={row.id} className="border-t border-ink-800 hover:bg-ink-900/50">
                <td className="p-2 font-mono text-ink-500">{row.id}</td>
                <td className="p-2 font-mono text-ink-300 whitespace-nowrap">{row.createdAt}</td>
                <td className="p-2 text-ink-200">{row.actionType}</td>
                <td className="p-2 text-ink-300">{row.actorUsername || row.actorId || '—'}</td>
                <td className="p-2 text-ink-400">
                  {row.targetType}
                  <span className="text-ink-600"> / </span>
                  {row.targetId || '—'}
                </td>
                <td className="p-2 font-mono text-ink-500">{row.ip || '—'}</td>
                <td className="p-2 max-w-[200px] truncate text-ink-500">{row.payload || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {cursor && (
        <button type="button" className="btn-ghost text-sm" onClick={loadMore}>
          Load more
        </button>
      )}
    </div>
  );
}
