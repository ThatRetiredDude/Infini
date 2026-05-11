export default function BlogList({ navigate }) {
  return (
    <div className="max-w-3xl mx-auto px-4 py-12">
      <h1 className="text-2xl mb-2">Blog</h1>
      <p className="text-ink-400 mb-8">
        Coming soon. Blog routes and admin editor will be ported over in Phase 3.
      </p>
      <div className="card p-6 text-sm text-ink-300">
        Placeholder. Once the <code className="font-mono">/api/blog</code>{' '}
        routes are wired and the TipTap admin editor is in, this list will
        render published posts.
      </div>
      <button type="button" className="btn-ghost mt-6" onClick={() => navigate('/')}>
        ← Back home
      </button>
    </div>
  );
}
