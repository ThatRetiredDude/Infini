import { useCallback, useEffect, useState } from 'react';

export default function HomePage({ navigate, branding }) {
  const [carouselItems, setCarouselItems] = useState([]);
  const [posts, setPosts] = useState([]);
  const [carouselErr, setCarouselErr] = useState(null);

  const load = useCallback(async () => {
    const [carouselOutcome, blogOutcome] = await Promise.allSettled([
      fetch('/api/carousel').then(async (res) => {
        if (!res.ok) {
          throw new Error(res.status === 404 ? 'carousel_unavailable' : `failed_${res.status}`);
        }
        const data = await res.json();
        return Array.isArray(data.items) ? data.items : [];
      }),
      fetch('/api/blog/posts?limit=6').then(async (res) => {
        if (!res.ok) return [];
        const data = await res.json();
        return Array.isArray(data.posts) ? data.posts : [];
      }),
    ]);

    if (carouselOutcome.status === 'fulfilled') {
      setCarouselItems(carouselOutcome.value);
      setCarouselErr(null);
    } else {
      setCarouselItems([]);
      setCarouselErr(carouselOutcome.reason?.message || String(carouselOutcome.reason));
    }

    if (blogOutcome.status === 'fulfilled') {
      setPosts(blogOutcome.value);
    } else {
      setPosts([]);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="max-w-4xl mx-auto px-4 py-16 space-y-12">
      <div className="card p-8">
        <p className="font-mono text-xs text-accent uppercase tracking-widest mb-2">
          {branding?.footer_text || 'Infini · MI'}
        </p>
        <h1 className="text-3xl md:text-4xl mb-4">
          A research blog with built-in security telemetry.
        </h1>
        <p className="text-ink-300 mb-6">
          The visible surface is a blog. The security layer records suspicious access patterns,
          enriches network signals, and makes them reviewable from the admin Security Hub.
        </p>
        <div className="flex flex-wrap gap-3">
          <button type="button" className="btn-primary" onClick={() => navigate('/blog')}>
            Read the blog
          </button>
          <button type="button" className="btn-ghost" onClick={() => navigate('/donations')}>
            Donate
          </button>
        </div>
      </div>

      {posts.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold text-ink-200 mb-4">Latest from the blog</h2>
          <div className="grid gap-4 sm:grid-cols-2">
            {posts.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => navigate(`/blog/${encodeURIComponent(p.slug)}`)}
                className="w-full text-left card p-5 hover:border-accent/40 transition-colors"
              >
                {p.cover_image_url ? (
                  <img
                    src={p.cover_image_url}
                    alt=""
                    className="w-full h-32 object-cover rounded-md mb-3 border border-ink-700"
                  />
                ) : (
                  <div className="h-32 rounded-md mb-3 border border-dashed border-ink-700 flex items-center justify-center text-xs text-ink-500 font-mono">
                    Post
                  </div>
                )}
                <h3 className="text-ink-100 font-medium mb-1">{p.title}</h3>
                {p.excerpt && <p className="text-ink-500 text-xs line-clamp-2">{p.excerpt}</p>}
                <p className="text-xs font-mono text-ink-500 mt-3">
                  {p.published_at?.slice?.(0, 10)}
                </p>
              </button>
            ))}
          </div>
          <button type="button" className="btn-ghost mt-4" onClick={() => navigate('/blog')}>
            View all posts →
          </button>
        </div>
      )}

      {carouselErr ? (
        <p className="text-xs text-ink-600 font-mono">Carousel: offline ({carouselErr}).</p>
      ) : carouselItems.length > 0 ? (
        <div>
          <h2 className="text-lg font-semibold text-ink-200 mb-4">Featured</h2>
          <div className="grid gap-4 sm:grid-cols-2">
            {carouselItems.map((item) => (
              <a
                key={item.id}
                href={item.url}
                target="_blank"
                rel="noopener noreferrer"
                className="card p-5 hover:border-accent/40 transition-colors no-underline block"
              >
                {item.thumbnail_url ? (
                  <img
                    src={item.thumbnail_url}
                    alt=""
                    className="w-full h-32 object-cover rounded-md mb-3 border border-ink-700"
                  />
                ) : (
                  <div className="h-32 rounded-md mb-3 border border-dashed border-ink-700 flex items-center justify-center text-xs text-ink-500 font-mono">
                    {item.type}
                  </div>
                )}
                <h3 className="text-ink-100 font-medium mb-1">{item.title}</h3>
                {item.body && <p className="text-ink-500 text-xs line-clamp-2">{item.body}</p>}
              </a>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}
