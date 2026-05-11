export default function BlogPost({ slug, navigate }) {
  return (
    <div className="max-w-3xl mx-auto px-4 py-12">
      <p className="text-xs text-ink-400 mb-2 font-mono">slug: {slug}</p>
      <h1 className="text-2xl mb-4">Blog post placeholder</h1>
      <p className="text-ink-400">The blog API is not wired yet. This page will render the published post once Phase 3 lands.</p>
      <button type="button" className="btn-ghost mt-6" onClick={() => navigate('/blog')}>
        ← All posts
      </button>
    </div>
  );
}
