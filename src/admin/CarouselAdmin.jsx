import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';

const EMPTY = {
  title: '',
  body: '',
  url: '',
  thumbnail_url: '',
  type: 'link',
  display_at: '',
  pinned: false,
  sort_order: 0,
};

export default function CarouselAdmin({ onToast }) {
  const [items, setItems] = useState([]);
  const [form, setForm] = useState(EMPTY);
  const [selectedId, setSelectedId] = useState(null);

  const toast = useCallback((type, text) => onToast?.({ type, text }), [onToast]);

  const load = useCallback(async () => {
    try {
      const data = await api.get('/api/admin/carousel/items');
      setItems(Array.isArray(data.items) ? data.items : []);
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  async function upsert(e) {
    e?.preventDefault();
    if (!form.title?.trim() || !form.url?.trim()) {
      toast('error', 'Title and URL are required');
      return;
    }
    try {
      if (selectedId) {
        await api.put(`/api/admin/carousel/items/${selectedId}`, {
          ...form,
          type: form.type,
          pinned: !!form.pinned,
        });
        toast('success', 'Carousel item updated');
      } else {
        await api.post('/api/admin/carousel/items', {
          ...form,
          type: form.type,
          pinned: !!form.pinned,
        });
        toast('success', 'Carousel item added');
      }
      setForm(EMPTY);
      setSelectedId(null);
      await load();
    } catch (err) {
      toast('error', err.message || String(err));
    }
  }

  async function deleteItem(id) {
    if (!confirm('Remove this carousel item?')) return;
    try {
      await api.delete(`/api/admin/carousel/items/${id}`);
      toast('success', 'Removed');
      setForm(EMPTY);
      setSelectedId(null);
      await load();
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl text-ink-100 font-semibold">Carousel</h2>
        <p className="text-sm text-ink-500 mt-1">
          Homepage tiles surfaced via <span className="font-mono">/api/carousel</span>.
        </p>
      </div>

      <form onSubmit={upsert} className="card p-6 space-y-4 max-w-xl">
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="text-xs text-ink-500 mb-1 block">Type</label>
            <select
              className="w-full rounded border border-ink-600 bg-ink-950 px-3 py-2 text-sm"
              value={form.type}
              onChange={(e) => setForm((f) => ({ ...f, type: e.target.value }))}
            >
              <option value="link">link</option>
              <option value="video">video</option>
              <option value="social">social</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-ink-500 mb-1 block">Sort order</label>
            <input
              type="number"
              className="w-full rounded border border-ink-600 bg-ink-950 px-3 py-2 text-sm"
              value={form.sort_order}
              onChange={(e) => setForm((f) => ({ ...f, sort_order: Number(e.target.value) }))}
            />
          </div>
        </div>
        <div>
          <label className="text-xs text-ink-500 mb-1 block">Title</label>
          <input
            className="w-full rounded border border-ink-600 bg-ink-950 px-3 py-2 text-sm"
            value={form.title}
            onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))}
          />
        </div>
        <div>
          <label className="text-xs text-ink-500 mb-1 block">URL</label>
          <input
            className="w-full rounded border border-ink-600 bg-ink-950 px-3 py-2 text-sm"
            value={form.url}
            onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
          />
        </div>
        <div>
          <label className="text-xs text-ink-500 mb-1 block">Body (optional)</label>
          <textarea
            className="w-full rounded border border-ink-600 bg-ink-950 px-3 py-2 text-sm min-h-[60px]"
            value={form.body}
            onChange={(e) => setForm((f) => ({ ...f, body: e.target.value }))}
          />
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="text-xs text-ink-500 mb-1 block">Thumbnail URL</label>
            <input
              className="w-full rounded border border-ink-600 bg-ink-950 px-3 py-2 text-sm"
              value={form.thumbnail_url}
              onChange={(e) => setForm((f) => ({ ...f, thumbnail_url: e.target.value }))}
            />
          </div>
          <div>
            <label className="text-xs text-ink-500 mb-1 block">Display at (ISO)</label>
            <input
              className="w-full rounded border border-ink-600 bg-ink-950 px-3 py-2 text-sm font-mono text-xs"
              value={form.display_at}
              onChange={(e) => setForm((f) => ({ ...f, display_at: e.target.value }))}
              placeholder="2026-05-01T12:00:00.000Z"
            />
          </div>
        </div>
        <label className="flex items-center gap-2 text-sm text-ink-300">
          <input
            type="checkbox"
            checked={!!form.pinned}
            onChange={(e) => setForm((f) => ({ ...f, pinned: e.target.checked }))}
          />
          Pinned (surfaced above others)
        </label>

        <div className="flex gap-2">
          <button type="submit" className="btn-primary">
            {selectedId ? 'Update' : 'Add'}
          </button>
          <button type="button" className="btn-ghost" onClick={() => { setForm(EMPTY); setSelectedId(null); }}>
            Clear
          </button>
        </div>
      </form>

      <div className="card p-5">
        <h3 className="text-sm font-medium text-ink-200 mb-3">Existing items</h3>
        <ul className="space-y-3 text-sm">
          {items.map((it) => (
            <li key={it.id} className="flex flex-wrap items-start justify-between gap-2 border-b border-ink-800 pb-2">
              <div>
                <p className="text-ink-200 font-medium">
                  {it.pinned ? '📌 ' : ''}
                  {it.title}
                </p>
                <p className="font-mono text-xs text-accent break-all">{it.url}</p>
                <p className="text-ink-500 text-xs">{it.item_type}</p>
              </div>
              <div className="flex gap-1">
                <button
                  type="button"
                  className="btn-ghost text-xs"
                  onClick={() => {
                    setSelectedId(it.id);
                    setForm({
                      title: it.title,
                      body: it.body || '',
                      url: it.url,
                      thumbnail_url: it.thumbnail_url || '',
                      type: it.item_type,
                      display_at: it.display_at || '',
                      pinned: !!it.pinned,
                      sort_order: it.sort_order ?? 0,
                    });
                  }}
                >
                  Edit
                </button>
                <button type="button" className="btn-ghost text-xs text-rose-300" onClick={() => deleteItem(it.id)}>
                  Remove
                </button>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
