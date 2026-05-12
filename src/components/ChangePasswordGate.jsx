import { useState } from 'react';
import { changePassword } from '../lib/api.js';

/** Blocks the app until seeded admin rotates password (cannot dismiss backdrop). */
export default function ChangePasswordGate({ user, onSuccess, onSignedOut }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [minLen, setMinLen] = useState(12);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);

    if (next !== confirm) {
      setError('New password and confirmation do not match.');
      return;
    }

    setBusy(true);
    try {
      const data = await changePassword(current, next);
      onSuccess?.(data.user);
    } catch (err) {
      const code = err?.data?.error;
      if (code === 'password_too_weak' && typeof err?.data?.min_length === 'number') {
        setMinLen(err.data.min_length);
        setError(`Use at least ${err.data.min_length} characters for the new password.`);
      } else if (code === 'invalid_current_password') {
        setError('Current password is incorrect.');
      } else if (code === 'same_password') {
        setError('Choose a password different from your current one.');
      } else {
        setError('Could not update password.');
      }
    } finally {
      setBusy(false);
    }
  }

  async function handleSignOut() {
    setBusy(true);
    try {
      await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
      onSignedOut?.();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-ink-950/95 backdrop-blur-sm">
      <div className="card p-6 w-full max-w-md shadow-2xl border border-ink-600">
        <h2 className="text-lg mb-1">Set your password</h2>
        <p className="text-sm text-ink-400 mb-4">
          The initial admin account requires a personal password before you can use administrator tools.
          {user?.username ? (
            <>
              {' '}
              Signed in as <span className="text-ink-200 font-mono">{user.username}</span>.
            </>
          ) : null}
        </p>
        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="label" htmlFor="pwd-gate-current">Current password</label>
            <input
              id="pwd-gate-current"
              className="input"
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              disabled={busy}
              required
            />
          </div>
          <div>
            <label className="label" htmlFor="pwd-gate-new">New password</label>
            <input
              id="pwd-gate-new"
              className="input"
              type="password"
              autoComplete="new-password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              disabled={busy}
              minLength={minLen}
              required
            />
          </div>
          <div>
            <label className="label" htmlFor="pwd-gate-confirm">Confirm new password</label>
            <input
              id="pwd-gate-confirm"
              className="input"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              disabled={busy}
              minLength={minLen}
              required
            />
          </div>
          <p className="text-xs text-ink-500">New password must be at least {minLen} characters.</p>
          {error && <div className="text-sm text-danger">{error}</div>}
          <div className="flex flex-wrap gap-2 justify-between pt-2">
            <button type="button" className="btn-ghost text-ink-400" onClick={handleSignOut} disabled={busy}>
              Sign out
            </button>
            <button type="submit" className="btn-primary" disabled={busy}>
              {busy ? 'Saving…' : 'Save password'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
