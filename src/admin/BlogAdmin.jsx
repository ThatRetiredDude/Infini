import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../lib/api.js';
import BlogEditor from './BlogEditor.jsx';

export default function BlogAdmin({ onToast }) {
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [form, setForm] = useState({
    title: '',
    slug: '',
    excerpt: '',
    body: '',
    cover_image_url: '',
    status: 'draft',
  });

  const toast = useCallback((type, text) => onToast?.({ type, text }), [onToast]);

  const loadList = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.get('/api/admin/blog/posts');
      setPosts(Array.isArray(data.posts) ? data.posts : []);
    } catch (e) {
      toast('error', e.message || String(e));
      setPosts([]);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadList();
  }, [loadList]);

  const coverFileRef = useRef(null);

  async function uploadCover() {
    if (!coverFileRef.current) return;
    coverFileRef.current.click();
  }

  async function handleCoverSelected(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const fd = new window.FormData();
      fd.append('file', file);
      const csrf = document.cookie.split(';').find(c => c.trim().startsWith('mi_csrf='))?.split('=')[1] || '';
      const headers = csrf ? { 'X-CSRF-Token': decodeURIComponent(csrf) } : {};
      const res = await fetch('/api/admin/uploads', { method: 'POST', credentials: 'include', headers, body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || 'upload_failed');
      if (data?.url) setForm(f => ({ ...f, cover_image_url: data.url }));
    } catch (err) {
      toast('error', 'Cover upload failed: ' + (err.message || err));
    } finally {
      e.target.value = '';
    }
  }

  function openNew() {
    setSelected(null);
    setForm({
      title: '',
      slug: '',
      excerpt: '',
      body: '',
      cover_image_url: '',
      status: 'draft',
    });
  }

  async function save() {
    if (!form.title?.trim()) {
      toast('error', 'Title is required');
      return;
    }
    try {
      if (!selected?.id) {
        const data = await api.post('/api/admin/blog/posts', {
          title: form.title.trim(),
          slug: form.slug?.trim(),
          excerpt: form.excerpt || '',
          body: form.body || '',
          cover_image_url: form.cover_image_url || null,
          status: form.status,
        });
        setSelected(data.post);
      } else {
        const data = await api.put(`/api/admin/blog/posts/${selected.id}`, form);
        setSelected(data.post);
      }
      toast('success', 'Post saved');
      await loadList();
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }

  async function publish() {
    setForm((f) => ({ ...f, status: 'published' }));
    try {
      if (!selected?.id) {
        const data = await api.post('/api/admin/blog/posts', {
          ...form,
          title: form.title.trim(),
          status: 'published',
        });
        setSelected(data.post);
      } else {
        const data = await api.put(`/api/admin/blog/posts/${selected.id}`, { ...form, status: 'published' });
        setSelected(data.post);
      }
      toast('success', 'Published');
      await loadList();
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }

  async function deletePost() {
    if (!selected?.id || !confirm('Delete this draft/post?')) return;
    try {
      await api.delete(`/api/admin/blog/posts/${selected.id}`);
      toast('success', 'Deleted');
      openNew();
      await loadList();
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3 justify-between">
        <div>
          <h2 className="text-xl text-ink-100 font-semibold">Blog</h2>
          <p className="text-sm text-ink-500 mt-1">Drafts and published posts (TipTap body → HTML).</p>
        </div>
        <button type="button" className="btn-primary" onClick={openNew}>
          New draft
        </button>
      </div>

      <div className="grid gap-6 lg:grid-cols-[220px,minmax(0,1fr)]">
        <div className="card p-4 max-h-[70vh] overflow-y-auto space-y-1">
          <p className="text-xs text-ink-500 uppercase tracking-wide mb-2">Posts</p>
          {loading && <p className="text-sm text-ink-400">Loading…</p>}
          {!loading &&
            posts.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => {
                  setSelected(p);
                  setForm({
                    title: p.title || '',
                    slug: p.slug || '',
                    excerpt: p.excerpt || '',
                    body: p.body || '',
                    cover_image_url: p.cover_image_url || '',
                    status: p.status || 'draft',
                  });
                }}
                className={`w-full text-left px-2 py-1.5 rounded text-sm truncate ${
                  selected?.id === p.id ? 'bg-ink-800 text-ink-100' : 'text-ink-400 hover:bg-ink-900'
                }`}
              >
                {p.status === 'draft' ? '◦ ' : '● '} {p.title}
              </button>
            ))}
        </div>

        <div className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-xs text-ink-500 mb-1">Title</label>
              <input
                className="w-full rounded border border-ink-600 bg-ink-950 px-3 py-2 text-sm"
                value={form.title}
                onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))}
              />
            </div>
            <div>
              <label className="block text-xs text-ink-500 mb-1">Slug</label>
              <input
                className="w-full rounded border border-ink-600 bg-ink-950 px-3 py-2 text-sm font-mono"
                value={form.slug}
                onChange={(e) => setForm((f) => ({ ...f, slug: e.target.value }))}
                placeholder="auto from title when empty"
              />
            </div>
            <div className="sm:col-span-2">
              <label className="block text-xs text-ink-500 mb-1">Excerpt</label>
              <textarea
                className="w-full rounded border border-ink-600 bg-ink-950 px-3 py-2 text-sm min-h-[72px]"
                value={form.excerpt}
                onChange={(e) => setForm((f) => ({ ...f, excerpt: e.target.value }))}
              />
            </div>
            <div className="sm:col-span-2">
              <label className="block text-xs text-ink-500 mb-1">Cover image</label>
              <div className="flex gap-2 items-center">
                <input
                  className="flex-1 rounded border border-ink-600 bg-ink-950 px-3 py-2 text-sm"
                  value={form.cover_image_url}
                  onChange={(e) => setForm((f) => ({ ...f, cover_image_url: e.target.value }))}
                  placeholder="https://... or upload"
                />
                <button type="button" className="btn-ghost text-xs" onClick={uploadCover}>Upload</button>
              </div>
              <input ref={coverFileRef} type="file" accept="image/*" className="hidden" onChange={handleCoverSelected} />
              {form.cover_image_url && (
                <img src={form.cover_image_url} alt="" className="mt-2 max-h-32 rounded border border-ink-700 object-cover" />
              )}
            </div>
            <div>
              <label className="block text-xs text-ink-500 mb-1">Status</label>
              <select
                className="w-full rounded border border-ink-600 bg-ink-950 px-3 py-2 text-sm"
                value={form.status}
                onChange={(e) => setForm((f) => ({ ...f, status: e.target.value }))}
              >
                <option value="draft">draft</option>
                <option value="published">published</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs text-ink-500 mb-3">Body</label>
            <BlogEditor html={form.body} onChange={(next) => setForm((f) => ({ ...f, body: next }))} />
          </div>

          <div className="flex flex-wrap gap-2">
            <button type="button" className="btn-primary" onClick={save}>
              Save
            </button>
            <button type="button" className="btn-ghost" onClick={publish}>
              Publish
            </button>
            {selected?.id && (
              <button type="button" className="btn-ghost text-rose-300" onClick={deletePost}>
                Delete
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
