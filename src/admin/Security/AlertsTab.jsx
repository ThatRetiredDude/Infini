import { useState, useEffect, useCallback } from 'react';
import { API_BASE } from './shared.jsx';
import { fetchWithCsrf } from '../../lib/api.js';

const SOURCES = ['ai_flags', 'mi_access', 'honeypot', 'maze', 'network_sensor'];
const CHANNELS = ['email', 'discord', 'telegram', 'webhook'];

function RuleForm({ initial, onSave, onCancel, saving }) {
  const [form, setForm] = useState(initial || {
    name: '', source: 'ai_flags', channel: 'email', recipient: '',
    enabled: true, cooldown_min: 30,
    predicate: { count: 1, window_min: 60 },
  });

  const setP = (k, v) => setForm((f) => ({ ...f, predicate: { ...f.predicate, [k]: v } }));
  const isAi = form.source === 'ai_flags';
  const isMi = form.source === 'mi_access';
  const isHp = form.source === 'honeypot';
  const isMz = form.source === 'maze';
  const isNs = form.source === 'network_sensor';

  return (
    <div className="space-y-4 p-5 rounded-xl border border-zinc-700 bg-zinc-900/60">
      <h4 className="text-zinc-100 font-semibold">{initial ? 'Edit Rule' : 'New Alert Rule'}</h4>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Rule name</label>
          <input type="text" value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="e.g. High severity spike"
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none" />
        </div>
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Source</label>
          <select value={form.source} onChange={(e) => setForm((f) => ({ ...f, source: e.target.value }))}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none">
            {SOURCES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Threshold count (&gt;=)</label>
          <input type="number" min={1} value={form.predicate.count || 1} onChange={(e) => setP('count', Number(e.target.value))}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none" />
        </div>
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Window (minutes)</label>
          <input type="number" min={1} value={form.predicate.window_min || 60} onChange={(e) => setP('window_min', Number(e.target.value))}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none" />
        </div>
        {isAi && (
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Severity filter (blank = any)</label>
            <select value={form.predicate.severity || ''} onChange={(e) => setP('severity', e.target.value || undefined)}
              className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none">
              <option value="">Any severity</option>
              <option value="high">HIGH</option>
              <option value="medium">MEDIUM</option>
              <option value="low">LOW</option>
            </select>
          </div>
        )}
        {isHp && (
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Monitored endpoint source filter (blank = any)</label>
            <select value={form.predicate.source_type || ''} onChange={(e) => setP('source_type', e.target.value || undefined)}
              className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none">
              <option value="">Any</option>
              <option value="system_prompt_probe">Research Policy Probe</option>
              <option value="dossier_dump_probe">Data Export Probe</option>
              <option value="eval_probe">Risk Review Probe</option>
            </select>
          </div>
        )}
        {isMi && (
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Tokenless direct hits</label>
            <select value={form.predicate.token_null === true ? 'true' : ''} onChange={(e) => setP('token_null', e.target.value === 'true' ? true : undefined)}
              className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none">
              <option value="">All hits</option>
              <option value="true">Tokenless only</option>
            </select>
          </div>
        )}
        {isMz && (
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Fake data access — specific IP (optional)</label>
            <input
              type="text"
              value={form.predicate.ip || ''}
              onChange={(e) => setP('ip', e.target.value.trim() || undefined)}
              placeholder="Empty = all IPs; threshold is sum of hit_count in window"
              className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none"
            />
          </div>
        )}
        {isNs && (
          <>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Protocol (optional)</label>
              <input
                type="text"
                value={form.predicate.protocol || ''}
                onChange={(e) => setP('protocol', e.target.value.trim() || undefined)}
                placeholder="ssh, telnet, ftp"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Event type contains (optional)</label>
              <input
                type="text"
                value={form.predicate.event_type || ''}
                onChange={(e) => setP('event_type', e.target.value.trim() || undefined)}
                placeholder="e.g. cowrie.login.failed"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Peer IP (optional)</label>
              <input
                type="text"
                value={form.predicate.ip || ''}
                onChange={(e) => setP('ip', e.target.value.trim() || undefined)}
                placeholder="Filter to one attacker IP"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none"
              />
            </div>
          </>
        )}
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Channel</label>
          <select value={form.channel} onChange={(e) => setForm((f) => ({ ...f, channel: e.target.value }))}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none">
            {CHANNELS.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Recipient</label>
          <input type="text" value={form.recipient} onChange={(e) => setForm((f) => ({ ...f, recipient: e.target.value }))}
            placeholder={form.channel === 'email' ? 'analyst@example.com' : form.channel === 'webhook' ? 'https://…' : 'channel ID or leave blank for default'}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none" />
        </div>
        <div>
          <label className="block text-xs text-zinc-400 mb-1">Cooldown (minutes)</label>
          <input type="number" min={1} value={form.cooldown_min} onChange={(e) => setForm((f) => ({ ...f, cooldown_min: Number(e.target.value) }))}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none" />
        </div>
        <div className="flex items-center gap-3">
          <input type="checkbox" id="rule-enabled" checked={form.enabled} onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
            className="rounded border-zinc-600 bg-zinc-800 text-indigo-500" />
          <label htmlFor="rule-enabled" className="text-sm text-zinc-300 cursor-pointer">Enabled</label>
        </div>
      </div>
      <div className="flex gap-3 pt-2">
        <button onClick={() => onSave(form)} disabled={saving}
          className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-medium">
          {saving ? 'Saving…' : (initial ? 'Save Changes' : 'Create Rule')}
        </button>
        <button onClick={onCancel} className="px-4 py-2 rounded-lg border border-zinc-700 text-zinc-400 hover:text-zinc-200 text-sm">
          Cancel
        </button>
      </div>
    </div>
  );
}

export default function AlertsTab({ toast, readOnly = false }) {
  const [rules, setRules] = useState([]);
  const [deliveries, setDeliveries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [editId, setEditId] = useState(null);
  const [saving, setSaving] = useState(false);
  const [testSending, setTestSending] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchWithCsrf(`${API_BASE}/admin/security/alerts`);
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || 'Failed');
      setRules(j.rules || []);
      setDeliveries(j.deliveries || []);
    } catch (e) {
      toast('error', 'Failed to load alert rules: ' + e.message);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  const create = async (form) => {
    setSaving(true);
    try {
      const res = await fetchWithCsrf(`${API_BASE}/admin/security/alerts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || 'Failed');
      toast('success', 'Alert rule created');
      setShowNew(false);
      load();
    } catch (e) {
      toast('error', e.message);
    } finally {
      setSaving(false);
    }
  };

  const update = async (id, form) => {
    setSaving(true);
    try {
      const res = await fetchWithCsrf(`${API_BASE}/admin/security/alerts/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || 'Failed');
      toast('success', 'Rule updated');
      setEditId(null);
      load();
    } catch (e) {
      toast('error', e.message);
    } finally {
      setSaving(false);
    }
  };

  const del = async (id, name) => {
    if (!confirm(`Delete alert rule "${name}"?`)) return;
    try {
      const res = await fetchWithCsrf(`${API_BASE}/admin/security/alerts/${id}`, { method: 'DELETE' });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || 'Failed');
      toast('success', 'Rule deleted');
      load();
    } catch (e) {
      toast('error', e.message);
    }
  };

  const testSend = async (rule) => {
    setTestSending(rule.id);
    try {
      const res = await fetchWithCsrf(`${API_BASE}/admin/security/share`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source: rule.source,
          channel: rule.channel,
          recipient: rule.recipient,
          format: 'summary',
          subject: `[TEST] ${rule.name}`,
        }),
      });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || 'Failed');
      toast('success', `Test sent via ${rule.channel}`);
    } catch (e) {
      toast('error', 'Test failed: ' + e.message);
    } finally {
      setTestSending(null);
    }
  };

  const deliveriesForRule = (id) => deliveries.filter((d) => d.rule_id === id).slice(0, 3);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-xl font-semibold text-zinc-100">Alert Rules</h2>
          <p className="text-zinc-400 text-sm mt-0.5">Evaluated every minute. Dispatches via configured integration channels.</p>
        </div>
        <button
          onClick={() => {
            if (readOnly) return;
            setShowNew(true);
            setEditId(null);
          }}
          disabled={readOnly}
          title={readOnly ? 'Creating rules is disabled in demo mode' : undefined}
          className={
            readOnly
              ? 'px-4 py-2 rounded-lg border border-zinc-700 text-zinc-500 text-sm font-medium cursor-not-allowed'
              : 'px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium transition-colors'
          }
        >
          {readOnly ? 'New Rule disabled in demo' : '+ New Rule'}
        </button>
      </div>

      {readOnly && (
        <div className="rounded-xl border border-zinc-700 bg-zinc-900/50 p-4 text-xs text-zinc-500">
          Alert rules are visible in demo mode, but creating, editing, deleting, and test sends are disabled.
        </div>
      )}

      {showNew && !readOnly && <RuleForm onSave={create} onCancel={() => setShowNew(false)} saving={saving} />}

      {loading && <div className="text-zinc-500 italic text-sm py-4">Loading…</div>}

      {!loading && rules.length === 0 && !showNew && (
        <div className="text-zinc-500 text-sm italic py-8 text-center">
          No alert rules yet. Create one to get notified when thresholds are crossed.
        </div>
      )}

      {rules.map((rule) => {
        const ruleDels = deliveriesForRule(rule.id);
        return (
          <div key={rule.id} className={`rounded-xl border p-5 space-y-3 ${rule.enabled ? 'border-zinc-700 bg-zinc-900/50' : 'border-zinc-800 bg-zinc-900/20 opacity-60'}`}>
            {editId === rule.id && !readOnly ? (
              <RuleForm initial={rule} onSave={(f) => update(rule.id, f)} onCancel={() => setEditId(null)} saving={saving} />
            ) : (
              <>
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-zinc-100 font-semibold">{rule.name}</span>
                      {!rule.enabled && <span className="px-1.5 py-0.5 rounded bg-zinc-700 text-zinc-500 text-[10px]">Disabled</span>}
                    </div>
                    <div className="flex flex-wrap gap-3 text-xs text-zinc-500">
                      <span>Source: <span className="text-zinc-300">{rule.source}</span></span>
                      <span>Channel: <span className="text-zinc-300">{rule.channel}</span></span>
                      <span>Recipient: <span className="text-zinc-300">{rule.recipient}</span></span>
                      <span>Cooldown: {rule.cooldown_min}m</span>
                      {rule.last_fired_at && <span>Last fired: {new Date(rule.last_fired_at).toLocaleString()}</span>}
                    </div>
                    <div className="text-xs text-zinc-500">
                      Predicate: {JSON.stringify(rule.predicate)}
                    </div>
                  </div>
                  {!readOnly && (
                    <div className="flex gap-2 shrink-0">
                      <button onClick={() => testSend(rule)} disabled={testSending === rule.id}
                        className="px-3 py-1.5 rounded-lg border border-indigo-500/40 bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 text-xs font-medium disabled:opacity-50">
                        {testSending === rule.id ? 'Sending…' : 'Test Send'}
                      </button>
                      <button onClick={() => { setEditId(rule.id); setShowNew(false); }}
                        className="px-3 py-1.5 rounded-lg border border-zinc-700 hover:border-zinc-500 text-zinc-400 hover:text-zinc-200 text-xs">
                        Edit
                      </button>
                      <button onClick={() => del(rule.id, rule.name)}
                        className="px-3 py-1.5 rounded-lg border border-rose-600/30 bg-rose-600/10 hover:bg-rose-600/20 text-rose-400 text-xs">
                        Delete
                      </button>
                    </div>
                  )}
                </div>

                {ruleDels.length > 0 && (
                  <div className="border-t border-zinc-800 pt-3">
                    <div className="text-[10px] text-zinc-500 uppercase tracking-wide mb-2">Recent deliveries</div>
                    <div className="space-y-1">
                      {ruleDels.map((d) => (
                        <div key={d.id} className="flex items-center gap-3 text-xs">
                          <span className={`px-1.5 py-0.5 rounded ${d.ok ? 'bg-emerald-500/15 text-emerald-300' : 'bg-rose-500/15 text-rose-300'}`}>
                            {d.ok ? 'OK' : 'FAIL'}
                          </span>
                          <span className="text-zinc-500">{new Date(d.fired_at).toLocaleString()}</span>
                          {d.error && <span className="text-rose-400">{d.error.slice(0, 80)}</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        );
      })}
    </div>
  );
}
