import { useCallback, useState } from 'react';
import MfaSettingsPanel from './MfaSettingsPanel.jsx';

export default function UserSettings({ user, navigate }) {
  const [toast, setToast] = useState(null);

  const showToast = useCallback((type, text) => {
    setToast({ type, text });
    window.setTimeout(() => setToast(null), 5500);
  }, []);

  return (
    <div className="max-w-4xl mx-auto p-6 space-y-6">
      {toast?.text && (
        <div
          className={`fixed bottom-6 right-6 z-50 px-4 py-3 rounded-lg border text-sm shadow-lg max-w-sm ${
            toast.type === 'error'
              ? 'bg-rose-950/95 border-rose-600 text-rose-100'
              : toast.type === 'success'
                ? 'bg-emerald-950/95 border-emerald-600 text-emerald-100'
                : 'bg-ink-900/95 border-ink-600 text-ink-100'
          }`}
        >
          {toast.text}
        </div>
      )}

      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-3xl font-bold text-zinc-100">User Settings</h1>
          <p className="text-zinc-400 mt-1 text-sm">
            Manage account security for <span className="text-zinc-200">{user?.username}</span>.
          </p>
        </div>
        <button
          type="button"
          onClick={() => navigate('/')}
          className="px-5 py-2 rounded-lg border border-zinc-700 hover:border-zinc-500 text-zinc-400 hover:text-zinc-200 text-sm transition-colors"
        >
          Back Home
        </button>
      </div>

      <div className="grid gap-6 md:grid-cols-[220px_1fr]">
        <aside className="rounded-xl border border-zinc-800 bg-zinc-950/40 p-3 h-fit">
          <div className="px-3 py-2 rounded-lg bg-indigo-500/15 border border-indigo-500/40 text-indigo-200 text-sm font-medium">
            Account Security
          </div>
          <div className="px-3 py-2 text-sm text-zinc-500">Profile</div>
          <div className="px-3 py-2 text-sm text-zinc-500">Sessions</div>
        </aside>

        <section className="rounded-xl border border-zinc-800 bg-zinc-950/30 p-5">
          <MfaSettingsPanel toast={showToast} />
        </section>
      </div>
    </div>
  );
}
