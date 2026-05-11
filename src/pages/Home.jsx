import { useCallback, useEffect, useState } from 'react';

export default function HomePage({ navigate }) {
  const [items, setItems] = useState([]);
  const [err, setErr] = useState(null);

  const loadCarousel = useCallback(async () => {
    try {
      const res = await fetch('/api/carousel');
      if (!res.ok) throw new Error('carousel_unavailable');
      const data = await res.json();
      setItems(Array.isArray(data.items) ? data.items : []);
      setErr(null);
    } catch (e) {
      setErr(e.message || String(e));
      setItems([]);
    }
  }, []);

  useEffect(() => {
    loadCarousel();
  }, [loadCarousel]);

  return (
    <div className="max-w-4xl mx-auto px-4 py-16 space-y-12">
      <div className="card p-8">
        <p className="font-mono text-xs text-accent uppercase tracking-widest mb-2">
          InfiniPot · MI
        </p>
        <h1 className="text-3xl md:text-4xl mb-4">
          A research blog wrapped around an AI honeypot.
        </h1>
        <p className="text-ink-300 mb-6">
          The visible surface is a blog. The invisible surface is an infinite maze designed to waste the
          time and compute of automated scrapers and large-language-model agents that scrape without
          permission. Hits are logged, enriched, and reviewable from the admin Security Hub.
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

      {err ? (
        <p className="text-xs text-ink-600 font-mono">Carousel: offline ({err}).</p>
      ) : items.length > 0 ? (
        <div>
          <h2 className="text-lg font-semibold text-ink-200 mb-4">Featured</h2>
          <div className="grid gap-4 sm:grid-cols-2">
            {items.map((item) => (
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
