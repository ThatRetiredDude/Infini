/**
 * Shared UI primitives for the Security Monitoring hub.
 * Extracted / supersedes the equivalent code in AIFlags.jsx.
 */

const API_BASE = import.meta.env.VITE_API_URL || '/api';
export { API_BASE };

// ─── Country flag + IP display helpers ───────────────────────────────────────

/** Convert ISO 3166-1 alpha-2 country code to flag emoji */
export function countryFlag(code) {
  if (!code || code.length !== 2) return '';
  return code.toUpperCase().replace(/./g, (c) =>
    String.fromCodePoint(c.charCodeAt(0) + 127397)
  );
}

/**
 * IpCell — renders IP address with flag, country, and org inline.
 * enrichment can be the full enrichment JSONB or just the summary sub-object.
 */
export function IpCell({ ip, enrichment, isTor = false, isRepeat = false, onClick }) {
  const raw = enrichment;
  const summary = raw?.summary || (raw?.ipinfo ? raw.summary : null) || raw;
  const country = summary?.country || raw?.ipinfo?.country || null;
  const org = summary?.org || raw?.ipinfo?.org || null;
  const flag = countryFlag(country);

  return (
    <div className={`${onClick ? 'cursor-pointer' : ''}`} onClick={onClick}>
      <div className="flex items-center gap-1.5 font-mono text-xs text-zinc-200">
        {flag && <span className="text-base leading-none">{flag}</span>}
        <span className={onClick ? 'text-indigo-300 underline decoration-dotted' : ''}>{ip || '—'}</span>
        {isTor && (
          <span className="px-1 py-0.5 rounded bg-purple-500/20 border border-purple-500/40 text-purple-300 text-[9px] font-bold">TOR</span>
        )}
        {isRepeat && (
          <span className="px-1 py-0.5 rounded bg-orange-500/20 border border-orange-500/40 text-orange-300 text-[9px] font-bold">REPEAT</span>
        )}
      </div>
      {(country || org) && (
        <div className="text-zinc-500 text-[10px] mt-0.5 truncate max-w-[180px]">
          {country && <span>{country}</span>}
          {country && org && <span> · </span>}
          {org && <span>{org.replace(/^AS\d+\s+/, '').slice(0, 30)}</span>}
        </div>
      )}
    </div>
  );
}

// ─── Severity / action badges ─────────────────────────────────────────────────

const SEVERITY_META = {
  high:   { label: 'HIGH',   bg: 'bg-rose-500/15',   text: 'text-rose-300',   border: 'border-rose-500/40' },
  medium: { label: 'MEDIUM', bg: 'bg-amber-500/15',  text: 'text-amber-300',  border: 'border-amber-500/40' },
  low:    { label: 'LOW',    bg: 'bg-zinc-700/40',   text: 'text-zinc-300',   border: 'border-zinc-600/40' },
};

const ACTION_META = {
  blocked: { label: 'Blocked', bg: 'bg-rose-500/15',  text: 'text-rose-300' },
  warned:  { label: 'Warned',  bg: 'bg-amber-500/15', text: 'text-amber-300' },
  logged:  { label: 'Logged',  bg: 'bg-zinc-700/40',  text: 'text-zinc-400' },
};

export function SeverityBadge({ severity }) {
  const m = SEVERITY_META[severity] || SEVERITY_META.low;
  return (
    <span className={`px-2 py-0.5 rounded-md border text-[10px] font-bold uppercase tracking-wide ${m.bg} ${m.text} ${m.border}`}>
      {m.label}
    </span>
  );
}

export function ActionBadge({ action }) {
  const m = ACTION_META[action] || ACTION_META.logged;
  return (
    <span className={`px-2 py-0.5 rounded-md text-[10px] font-medium ${m.bg} ${m.text}`}>
      {m.label}
    </span>
  );
}

export function ReasonChips({ reasons }) {
  if (!Array.isArray(reasons) || reasons.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1 mt-1">
      {reasons.map((r) => (
        <span key={r} className="px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-[10px] text-zinc-400">
          {r}
        </span>
      ))}
    </div>
  );
}

// ─── Disabled users panel (shared with AIFlagsTab) ───────────────────────────

import { useState, useEffect, useCallback } from 'react';

export function DisabledUsersPanel({ toast, onRestored }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [restoring, setRestoring] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/admin/ai-flags/disabled-users`);
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || 'Failed');
      setUsers(j.users || []);
    } catch (e) {
      toast('error', 'Failed to load disabled users: ' + e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const restore = async (userId, username) => {
    if (!confirm(`Restore AI access for ${username || userId}?`)) return;
    setRestoring(userId);
    try {
      const res = await fetch(`${API_BASE}/admin/ai-flags/users/${userId}/restore`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Manual restore by admin' }),
      });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || 'Failed');
      toast('success', `AI access restored for ${username || userId}`);
      setUsers((u) => u.filter((x) => x.id !== userId));
      if (onRestored) onRestored();
    } catch (e) {
      toast('error', 'Restore failed: ' + e.message);
    } finally {
      setRestoring(null);
    }
  };

  if (loading) return <div className="text-zinc-500 text-sm italic py-4">Loading disabled users…</div>;
  if (users.length === 0) return (
    <div className="text-zinc-500 text-sm italic py-4">No users currently have AI access disabled.</div>
  );

  return (
    <div className="space-y-2">
      {users.map((u) => (
        <div key={u.id} className="flex items-center justify-between gap-4 px-4 py-3 rounded-xl border border-rose-500/25 bg-rose-500/5">
          <div className="min-w-0">
            <div className="text-sm font-medium text-zinc-100">{u.username || u.email || u.id}</div>
            <div className="text-xs text-zinc-400 mt-0.5">
              {u.ai_disabled_at ? `Disabled ${new Date(u.ai_disabled_at).toLocaleString()}` : 'Disabled (date unknown)'}
              {u.ai_disabled_reason && <span className="ml-2 text-zinc-500">— {u.ai_disabled_reason.slice(0, 80)}</span>}
            </div>
          </div>
          <button
            onClick={() => restore(u.id, u.username)}
            disabled={restoring === u.id}
            className="shrink-0 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-medium"
          >
            {restoring === u.id ? 'Restoring…' : 'Restore Access'}
          </button>
        </div>
      ))}
    </div>
  );
}
