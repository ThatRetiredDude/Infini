import { useCallback, useEffect, useState } from 'react';

export default function BlogList({ navigate }) {
  const [posts, setPosts] = useState([]);
  const [err, setErr] = useState(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/blog/posts');
      if (!res.ok) {
        throw new Error((await res.json().catch(() => ({}))).error || `failed_${res.status}`);
      }
      const data = await res.json();
      setPosts(Array.isArray(data.posts) ? data.posts : []);
      setErr(null);
    } catch (e) {
      setPosts([]);
      setErr(e.message || String(e));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="max-w-3xl mx-auto px-4 py-12">
      <h1 className="text-2xl mb-2">Blog</h1>
      <p className="text-ink-400 mb-8 text-sm">Published investigations and tooling notes.</p>

      {err && (
        <div className="card p-4 border-rose-800 text-rose-200 text-sm mb-6">{err}</div>
      )}

      <ul className="space-y-4">
        {posts.map((p) => (
          <li key={p.id}>
            <button
              type="button"
              onClick={() => navigate(`/blog/${encodeURIComponent(p.slug)}`)}
              className="w-full text-left card p-5 hover:border-accent/40 transition-colors"
            >
              <h2 className="text-lg text-ink-100 font-semibold mb-1">{p.title}</h2>
              {p.excerpt && <p className="text-sm text-ink-400 line-clamp-2">{p.excerpt}</p>}
              <p className="text-xs font-mono text-ink-500 mt-3">
                {p.published_at?.slice?.(0, 10)}
                {' · '}
                {Number(p.views || 0)} views
              </p>
            </button>
          </li>
        ))}
      </ul>

      {!posts.length && !err && (
        <p className="text-ink-500 text-sm">
          Nothing published yet. Draft from the Admin → Blog screen.
        </p>
      )}

      <button type="button" className="btn-ghost mt-8" onClick={() => navigate('/')}>
        ← Back home
      </button>
    </div>
  );
}
