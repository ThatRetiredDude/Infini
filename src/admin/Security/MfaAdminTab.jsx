/**
 * Admin TOTP (authenticator app) enrollment — Security hub.
 */

import { useCallback, useEffect, useState } from 'react';
import { api } from '../../lib/api.js';

export default function MfaAdminTab({ toast }) {
  const [status, setStatus] = useState({ loading: true, totp_enabled: false, enroll_pending: false });
  const [enroll, setEnroll] = useState(null);
  const [verifyCode, setVerifyCode] = useState('');
  const [disPwd, setDisPwd] = useState('');
  const [disCode, setDisCode] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setStatus((s) => ({ ...s, loading: true }));
    try {
      const j = await api.get('/api/admin/auth/mfa/status');
      setStatus({ loading: false, totp_enabled: !!j.totp_enabled, enroll_pending: !!j.enroll_pending });
    } catch {
      setStatus({ loading: false, totp_enabled: false, enroll_pending: false });
      toast('error', 'Could not load MFA status.');
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const startEnroll = async () => {
    setBusy(true);
    try {
      const j = await api.post('/api/admin/auth/mfa/enroll-start', {});
      setEnroll({ otpauth_url: j.otpauth_url, manual_entry_key: j.manual_entry_key });
      await load();
      toast('success', 'Scan the QR or enter the key in your authenticator app.');
    } catch (e) {
      toast('error', e?.data?.error || 'Could not start enrollment.');
    } finally {
      setBusy(false);
    }
  };

  const finishEnroll = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post('/api/admin/auth/mfa/enroll-verify', { code: verifyCode.replace(/\s/g, '') });
      setEnroll(null);
      setVerifyCode('');
      await load();
      toast('success', 'Two-factor authentication is on.');
    } catch (e) {
      toast('error', e?.data?.error === 'invalid_totp_code' ? 'Invalid code.' : 'Verification failed.');
    } finally {
      setBusy(false);
    }
  };

  const cancelEnroll = async () => {
    setBusy(true);
    try {
      await api.post('/api/admin/auth/mfa/enroll-cancel', {});
      setEnroll(null);
      setVerifyCode('');
      await load();
    } catch {
      toast('error', 'Could not cancel.');
    } finally {
      setBusy(false);
    }
  };

  const disable = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post('/api/admin/auth/mfa/disable', {
        password: disPwd,
        code: disCode.replace(/\s/g, ''),
      });
      setDisPwd('');
      setDisCode('');
      await load();
      toast('success', 'Two-factor authentication disabled.');
    } catch (e) {
      const c = e?.data?.error;
      if (c === 'invalid_password') toast('error', 'Wrong password.');
      else if (c === 'invalid_totp_code') toast('error', 'Invalid code.');
      else toast('error', 'Could not disable MFA.');
    } finally {
      setBusy(false);
    }
  };

  if (status.loading) {
    return <div className="text-zinc-500 text-sm italic py-6">Loading…</div>;
  }

  const qrSrc = enroll?.otpauth_url
    ? `https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(enroll.otpauth_url)}`
    : null;

  return (
    <div className="space-y-8 max-w-xl">
      <div>
        <h2 className="text-xl font-semibold text-zinc-100">Two-factor authentication</h2>
        <p className="text-zinc-400 text-sm mt-1">
          Require a time-based code from an authenticator app when signing in. Recommended for admin
          accounts exposed on the public internet.
        </p>
      </div>

      {status.totp_enabled ? (
        <div className="rounded-xl border border-zinc-700 bg-zinc-900/50 p-5 space-y-4">
          <p className="text-emerald-400 text-sm font-medium">Authenticator MFA is enabled.</p>
          <form onSubmit={disable} className="space-y-3">
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Account password</label>
              <input
                type="password"
                className="w-full rounded-lg bg-zinc-950 border border-zinc-700 px-3 py-2 text-sm text-zinc-100"
                value={disPwd}
                onChange={(e) => setDisPwd(e.target.value)}
                autoComplete="current-password"
                disabled={busy}
                required
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Authenticator code</label>
              <input
                className="w-full rounded-lg bg-zinc-950 border border-zinc-700 px-3 py-2 text-sm text-zinc-100"
                inputMode="numeric"
                value={disCode}
                onChange={(e) => setDisCode(e.target.value)}
                autoComplete="one-time-code"
                disabled={busy}
                required
              />
            </div>
            <button
              type="submit"
              disabled={busy}
              className="px-4 py-2 rounded-lg border border-rose-600/40 bg-rose-600/15 text-rose-300 text-sm hover:bg-rose-600/25 disabled:opacity-50"
            >
              Disable MFA
            </button>
          </form>
        </div>
      ) : enroll ? (
        <div className="rounded-xl border border-zinc-700 bg-zinc-900/50 p-5 space-y-4">
          <div className="flex flex-wrap gap-6 items-start">
            {qrSrc && (
              <img src={qrSrc} alt="" className="rounded-lg border border-zinc-700 bg-white p-1" width={180} height={180} />
            )}
            <div className="text-sm text-zinc-400 space-y-2 min-w-0 flex-1">
              <p>Manual entry key:</p>
              <code className="block break-all text-zinc-200 text-xs bg-zinc-950 p-2 rounded border border-zinc-800">
                {enroll.manual_entry_key}
              </code>
            </div>
          </div>
          <form onSubmit={finishEnroll} className="space-y-3">
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Confirm with 6-digit code</label>
              <input
                className="w-full rounded-lg bg-zinc-950 border border-zinc-700 px-3 py-2 text-sm text-zinc-100"
                inputMode="numeric"
                value={verifyCode}
                onChange={(e) => setVerifyCode(e.target.value)}
                disabled={busy}
                required
              />
            </div>
            <div className="flex gap-2">
              <button
                type="submit"
                disabled={busy}
                className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm disabled:opacity-50"
              >
                Verify & enable
              </button>
              <button type="button" onClick={cancelEnroll} disabled={busy} className="px-4 py-2 text-sm text-zinc-400">
                Cancel
              </button>
            </div>
          </form>
        </div>
      ) : (
        <div className="rounded-xl border border-zinc-700 bg-zinc-900/50 p-5">
          <p className="text-zinc-400 text-sm mb-4">
            {status.enroll_pending
              ? 'Enrollment was started earlier. Open your authenticator app or start again.'
              : 'Add a second step to the sign-in flow using Google Authenticator, 1Password, Authy, or similar.'}
          </p>
          <button
            type="button"
            onClick={startEnroll}
            disabled={busy}
            className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium disabled:opacity-50"
          >
            Set up authenticator
          </button>
        </div>
      )}
    </div>
  );
}
