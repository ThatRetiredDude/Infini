export default function HomePage({ navigate }) {
  return (
    <div className="max-w-3xl mx-auto px-4 py-16">
      <div className="card p-8">
        <p className="font-mono text-xs text-accent uppercase tracking-widest mb-2">
          InfiniPot · MI
        </p>
        <h1 className="text-3xl md:text-4xl mb-4">
          A research blog wrapped around an AI honeypot.
        </h1>
        <p className="text-ink-300 mb-6">
          The visible surface is a blog. The invisible surface is an infinite
          maze designed to waste the time and compute of automated scrapers and
          large-language-model agents that scrape without permission. Hits are
          logged, enriched, and reviewable from the admin Security Hub.
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
    </div>
  );
}
