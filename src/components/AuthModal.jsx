import { useEffect, useState } from 'react';
import { login } from '../lib/api.js';

export default function AuthModal({ open, onClose, onAuthed }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!open) {
      setUsername('');
      setPassword('');
      setError(null);
      setBusy(false);
    }
  }, [open]);

  if (!open) return null;

  async function handleSubmit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { user } = await login(username.trim(), password);
      onAuthed?.(user);
    } catch (err) {
      setError(err?.data?.error === 'invalid_credentials' ? 'Invalid credentials.' : 'Sign-in failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/80 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="card p-6 w-full max-w-sm shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-lg mb-1">Sign in</h2>
        <p className="text-sm text-ink-400 mb-4">Admin access for Infini.</p>
        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="label" htmlFor="auth-username">Username</label>
            <input
              id="auth-username"
              className="input"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoFocus
              disabled={busy}
              required
            />
          </div>
          <div>
            <label className="label" htmlFor="auth-password">Password</label>
            <input
              id="auth-password"
              className="input"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={busy}
              required
            />
          </div>
          {error && <div className="text-sm text-danger">{error}</div>}
          <div className="flex gap-2 justify-end pt-2">
            <button type="button" className="btn-ghost" onClick={onClose} disabled={busy}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={busy}>
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
