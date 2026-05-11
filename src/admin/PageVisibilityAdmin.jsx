import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';

const OPTIONS = ['public', 'hidden', 'admin_only'];

export default function PageVisibilityAdmin({ onToast }) {
  const [pages, setPages] = useState({ home: 'public', blog: 'public', donations: 'public' });
  const [loading, setLoading] = useState(true);
  const toast = useCallback((type, text) => onToast?.({ type, text }), [onToast]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.get('/api/site/visibility');
      const next = data?.pages ?? data;
      setPages({
        home: next.home ?? 'public',
        blog: next.blog ?? 'public',
        donations: next.donations ?? 'public',
      });
    } catch (e) {
      toast('error', e.message || String(e));
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  async function save() {
    try {
      const out = await api.patch('/api/admin/site/visibility', { pages });
      toast('success', 'Visibility updated');
      if (out?.pages) {
        setPages({
          home: out.pages.home,
          blog: out.pages.blog,
          donations: out.pages.donations,
        });
      }
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }

  return (
    <div className="space-y-4 max-w-xl">
      <div>
        <h2 className="text-xl text-ink-100 font-semibold">Page visibility</h2>
        <p className="text-sm text-ink-500 mt-1">
          Controls SPA nav plus public APIs backed by{' '}
          <span className="font-mono">/api/blog</span>, <span className="font-mono">/api/carousel</span>.
          Administrators always preview gated pages when signed in.
        </p>
      </div>

      {loading ? (
        <p className="text-ink-400 text-sm">Loading…</p>
      ) : (
        <div className="card p-6 space-y-4">
          {['home', 'blog', 'donations'].map((key) => (
            <label key={key} className="flex items-center gap-4 justify-between text-sm">
              <span className="text-ink-200 capitalize font-medium">{key}</span>
              <select
                className="input max-w-[200px]"
                value={pages[key]}
                onChange={(e) => setPages((prev) => ({ ...prev, [key]: e.target.value }))}
              >
                {OPTIONS.map((o) => (
                  <option key={o} value={o}>
                    {o}
                  </option>
                ))}
              </select>
            </label>
          ))}
          <button type="button" className="btn-primary mt-4" onClick={save}>
            Save visibility
          </button>
        </div>
      )}
    </div>
  );
}
