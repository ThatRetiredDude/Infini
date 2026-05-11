import { useCallback, useEffect, useState } from 'react';
import { sanitizeBlogHtml } from '../lib/sanitizeBlogHtml.js';

export default function BlogPost({ slug, navigate }) {
  const [post, setPost] = useState(null);
  const [err, setErr] = useState(null);

  const safeSlug = String(slug || '').replace(/[^\w\-./]+/g, '').slice(0, 200);

  const load = useCallback(async () => {
    if (!safeSlug) {
      setErr('invalid_slug');
      return;
    }
    try {
      const res = await fetch(`/api/blog/posts/${encodeURIComponent(safeSlug)}`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `failed_${res.status}`);
      setPost(data.post);
      setErr(null);
    } catch (e) {
      setPost(null);
      setErr(e.message || String(e));
    }
  }, [safeSlug]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <article className="max-w-3xl mx-auto px-4 py-12">
      {err && (
        <div className="card p-4 border-rose-800 text-rose-200 text-sm mb-6">{err}</div>
      )}
      {!post ? null : (
        <>
          <p className="text-xs font-mono text-ink-500 mb-4">{safeSlug}</p>
          <h1 className="text-3xl mb-6">{post.title}</h1>
          {post.cover_image_url && (
            <img src={post.cover_image_url} alt="" className="w-full rounded-lg border border-ink-700 mb-8 max-h-[420px] object-cover" />
          )}
          <div
            className="text-ink-200 text-sm leading-relaxed space-y-4 [&_a]:text-accent [&_h1]:text-2xl [&_h2]:text-xl [&_ul]:list-disc [&_ul]:pl-5"
            dangerouslySetInnerHTML={{ __html: sanitizeBlogHtml(post.body || '') }}
          />
          <footer className="mt-12 text-xs text-ink-500 flex flex-wrap gap-4 justify-between border-t border-ink-800 pt-4">
            <span className="font-mono">{post.published_at?.slice?.(0, 16)} UTC</span>
            <span>{Number(post.views || 0)} views</span>
          </footer>
        </>
      )}
      <button type="button" className="btn-ghost mt-10" onClick={() => navigate('/blog')}>
        ← All posts
      </button>
    </article>
  );
}
