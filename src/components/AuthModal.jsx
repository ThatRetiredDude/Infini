import { useEffect, useState } from 'react';
import { login, verifyMfaTotp, forgotPassword } from '../lib/api.js';

export default function AuthModal({ open, onClose, onAuthed }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mfaTicket, setMfaTicket] = useState(null);
  const [mfaUserLabel, setMfaUserLabel] = useState('');
  const [otp, setOtp] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [forgotMode, setForgotMode] = useState(false);
  const [recoveryPath, setRecoveryPath] = useState(null);

  useEffect(() => {
    if (!open) {
      setUsername('');
      setPassword('');
      setMfaTicket(null);
      setMfaUserLabel('');
      setOtp('');
      setError(null);
      setBusy(false);
      setForgotMode(false);
      setRecoveryPath(null);
    }
  }, [open]);

  if (!open) return null;

  const resetMfa = () => {
    setMfaTicket(null);
    setMfaUserLabel('');
    setOtp('');
    setError(null);
  };

  async function handleSubmit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const data = await login(username.trim(), password);
      if (data.mfa_required && data.ticket) {
        setMfaTicket(data.ticket);
        setMfaUserLabel(data.user?.username || username.trim());
        setOtp('');
        return;
      }
      onAuthed?.(data.user);
    } catch (err) {
      setError(err?.data?.error === 'invalid_credentials' ? 'Invalid credentials.' : 'Sign-in failed.');
    } finally {
      setBusy(false);
    }
  }

  async function handleMfa(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const data = await verifyMfaTotp(mfaTicket, otp.replace(/\s/g, ''));
      onAuthed?.(data.user);
      resetMfa();
    } catch (err) {
      const code = err?.data?.error;
      if (code === 'invalid_totp_code') {
        setError('Invalid authenticator code.');
      } else if (code === 'invalid_mfa_ticket') {
        setError('MFA challenge expired. Sign in again.');
        resetMfa();
      } else {
        setError('Verification failed.');
      }
    } finally {
      setBusy(false);
    }
  }

  async function handleForgot(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const data = await forgotPassword(username.trim());
      setRecoveryPath(data.recoveryFile);
    } catch (err) {
      const code = err?.data?.error;
      if (code === 'user_not_found') {
        setError('No account found with that username.');
      } else {
        setError('Could not generate recovery file.');
      }
    } finally {
      setBusy(false);
    }
  }

  if (mfaTicket) {
    return (
      <div
        className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/80 backdrop-blur-sm"
        onClick={onClose}
      >
        <div
          className="card p-6 w-full max-w-sm shadow-2xl"
          onClick={(e) => e.stopPropagation()}
        >
          <h2 className="text-lg mb-1">Authenticator code</h2>
          <p className="text-sm text-ink-400 mb-4">
            Enter the 6-digit code for{' '}
            <span className="text-ink-200 font-mono">{mfaUserLabel}</span>.
          </p>
          <form onSubmit={handleMfa} className="space-y-3">
            <div>
              <label className="label" htmlFor="auth-mfa-otp">
                Code
              </label>
              <input
                id="auth-mfa-otp"
                className="input"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
                autoFocus
                disabled={busy}
                required
              />
            </div>
            {error && <div className="text-sm text-danger">{error}</div>}
            <div className="flex gap-2 justify-end pt-2">
              <button
                type="button"
                className="btn-ghost"
                onClick={() => {
                  resetMfa();
                }}
                disabled={busy}
              >
                Back
              </button>
              <button type="submit" className="btn-primary" disabled={busy}>
                {busy ? 'Verifying…' : 'Verify'}
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  }

  if (forgotMode) {
    return (
      <div
        className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/80 backdrop-blur-sm"
        onClick={onClose}
      >
        <div
          className="card p-6 w-full max-w-sm shadow-2xl"
          onClick={(e) => e.stopPropagation()}
        >
          <h2 className="text-lg mb-1">Forgot password</h2>
          <p className="text-sm text-ink-400 mb-4">
            Enter your username. A recovery file with a new password will be written to a secure location on the server.
          </p>
          {recoveryPath ? (
            <div className="space-y-3">
              <div className="rounded border border-ink-700 bg-ink-950 p-3 text-sm">
                <div className="font-medium mb-1">Recovery file created:</div>
                <code className="block break-all text-xs text-ink-200 font-mono">{recoveryPath}</code>
              </div>
              <p className="text-xs text-ink-400">
                Only the server operator can access this file (0600 permissions under the data volume).
                Use the password inside to sign in — your previous password remains valid.
                Delete the file after use.
              </p>
              <div className="flex justify-end pt-2">
                <button
                  type="button"
                  className="btn-ghost"
                  onClick={() => {
                    setForgotMode(false);
                    setRecoveryPath(null);
                    setError(null);
                  }}
                >
                  Back to sign in
                </button>
              </div>
            </div>
          ) : (
            <form onSubmit={handleForgot} className="space-y-3">
              <div>
                <label className="label" htmlFor="forgot-username">
                  Username
                </label>
                <input
                  id="forgot-username"
                  className="input"
                  autoComplete="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoFocus
                  disabled={busy}
                  required
                />
              </div>
              {error && <div className="text-sm text-danger">{error}</div>}
              <div className="flex gap-2 justify-end pt-2">
                <button
                  type="button"
                  className="btn-ghost"
                  onClick={() => {
                    setForgotMode(false);
                    setError(null);
                  }}
                  disabled={busy}
                >
                  Back
                </button>
                <button type="submit" className="btn-primary" disabled={busy}>
                  {busy ? 'Generating…' : 'Request recovery file'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    );
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/80 backdrop-blur-sm"
      onClick={onClose}
    >
      <div className="card p-6 w-full max-w-sm shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-lg mb-1">Sign in</h2>
        <p className="text-sm text-ink-400 mb-4">Admin access for Infini.</p>
        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="label" htmlFor="auth-username">
              Username
            </label>
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
            <label className="label" htmlFor="auth-password">
              Password
            </label>
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
          <div className="text-right">
            <button
              type="button"
              className="text-sm text-ink-400 hover:text-ink-200 underline"
              onClick={() => {
                setForgotMode(true);
                setError(null);
                setRecoveryPath(null);
              }}
              disabled={busy}
            >
              Forgot password?
            </button>
          </div>
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
