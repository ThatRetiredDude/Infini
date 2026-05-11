export default function AdminShell({ user, authChecked, onRequireLogin, sub }) {
  if (!authChecked) {
    return (
      <div className="max-w-4xl mx-auto p-8 text-ink-400">Checking session…</div>
    );
  }
  if (!user) {
    return (
      <div className="max-w-2xl mx-auto p-8">
        <div className="card p-6">
          <h1 className="text-xl mb-2">Sign-in required</h1>
          <p className="text-ink-400 mb-4">
            The admin area requires an authenticated administrator.
          </p>
          <button type="button" className="btn-primary" onClick={onRequireLogin}>
            Sign in
          </button>
        </div>
      </div>
    );
  }
  if (user.role !== 'admin' && !user.is_admin) {
    return (
      <div className="max-w-2xl mx-auto p-8">
        <div className="card p-6">
          <h1 className="text-xl mb-2">Forbidden</h1>
          <p className="text-ink-400">
            Your account doesn&apos;t have admin privileges.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto p-6">
      <h1 className="text-2xl mb-4">Admin</h1>
      <p className="text-ink-400 mb-6">
        Welcome, <span className="text-ink-100">{user.username}</span>. The full
        admin UI (Security Hub, Blog editor, Carousel, Integrations, Audit Log,
        AI Log Review) will be ported in subsequent phases.
      </p>
      <div className="card p-4 font-mono text-xs text-ink-300">
        sub-route: {sub || '/'}
      </div>
    </div>
  );
}
