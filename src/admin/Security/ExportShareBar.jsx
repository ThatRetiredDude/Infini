/**
 * ExportShareBar — toolbar used by every data tab.
 *
 * Props:
 *   rows         — current page/all rows for client-side export
 *   filename     — base filename without extension
 *   source       — 'ai_flags' | 'mi_access' | 'honeypot'
 *   filters      — current filter state to pass to server-side share
 *   toast        — (type, text) => void
 *   onExportCsv  — optional override; defaults to client-side CSV from rows
 *   onExportJson — optional override; defaults to client-side JSON from rows
 */

import { useState } from 'react';
import { API_BASE } from './shared.jsx';

function csvEscape(val) {
  const s = String(val ?? '');
  const escaped = s.replace(/"/g, '""');
  return /[",\n\r]/.test(escaped) ? `"${escaped}"` : escaped;
}

function downloadCsv(rows, filename) {
  if (!rows?.length) return;
  const keys = Object.keys(rows[0]);
  const header = keys.map(csvEscape).join(',');
  const lines = rows.map((r) =>
    keys.map((k) => csvEscape(typeof r[k] === 'object' && r[k] !== null ? JSON.stringify(r[k]) : r[k])).join(',')
  );
  const csv = [header, ...lines].join('\r\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `${filename}.csv`;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a); URL.revokeObjectURL(url);
}

function downloadJson(rows, filename) {
  if (!rows?.length) return;
  const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `${filename}.json`;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a); URL.revokeObjectURL(url);
}

export default function ExportShareBar({ rows = [], filename = 'export', source, filters = {}, toast }) {
  const [showSend, setShowSend] = useState(false);
  const [sending, setSending] = useState(false);
  const [sendForm, setSendForm] = useState({ channel: 'email', recipient: '', format: 'summary' });

  const handleSend = async () => {
    if (!sendForm.recipient.trim()) {
      toast('error', 'Recipient is required');
      return;
    }
    setSending(true);
    try {
      const res = await fetch(`${API_BASE}/admin/security/share`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source,
          filters,
          channel: sendForm.channel,
          recipient: sendForm.recipient.trim(),
          format: sendForm.format,
        }),
      });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || 'Send failed');
      toast('success', `Sent ${j.row_count} row(s) via ${sendForm.channel}`);
      setShowSend(false);
    } catch (e) {
      toast('error', e.message);
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <button
        onClick={() => downloadCsv(rows, filename)}
        disabled={!rows.length}
        className="px-3 py-1.5 rounded-lg border border-zinc-700 hover:border-zinc-500 text-zinc-300 hover:text-zinc-100 text-xs font-medium transition-colors disabled:opacity-40"
      >
        Export CSV ({rows.length})
      </button>
      <button
        onClick={() => downloadJson(rows, filename)}
        disabled={!rows.length}
        className="px-3 py-1.5 rounded-lg border border-zinc-700 hover:border-zinc-500 text-zinc-300 hover:text-zinc-100 text-xs font-medium transition-colors disabled:opacity-40"
      >
        Export JSON
      </button>
      <button
        onClick={() => setShowSend(true)}
        className="px-3 py-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/40 border border-indigo-500/40 text-indigo-300 text-xs font-medium transition-colors"
      >
        Send…
      </button>

      {showSend && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={() => setShowSend(false)}>
          <div
            className="bg-zinc-900 border border-zinc-700 rounded-2xl p-6 w-full max-w-md shadow-2xl space-y-4"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-zinc-100 font-semibold text-lg">Send Report</h3>
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-zinc-400 mb-1">Channel</label>
                <select
                  value={sendForm.channel}
                  onChange={(e) => setSendForm((f) => ({ ...f, channel: e.target.value }))}
                  className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none"
                >
                  <option value="email">Email (SMTP)</option>
                  <option value="discord">Discord Webhook</option>
                  <option value="telegram">Telegram</option>
                  <option value="webhook">Generic Webhook</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-zinc-400 mb-1">
                  {sendForm.channel === 'email' ? 'To address' : sendForm.channel === 'telegram' ? 'Chat ID (blank = default)' : 'Webhook URL (blank = configured default)'}
                </label>
                <input
                  type="text"
                  value={sendForm.recipient}
                  onChange={(e) => setSendForm((f) => ({ ...f, recipient: e.target.value }))}
                  placeholder={sendForm.channel === 'email' ? 'analyst@example.com' : sendForm.channel === 'webhook' ? 'https://…' : ''}
                  className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-xs text-zinc-400 mb-1">Format</label>
                <select
                  value={sendForm.format}
                  onChange={(e) => setSendForm((f) => ({ ...f, format: e.target.value }))}
                  className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-indigo-500 focus:outline-none"
                >
                  <option value="summary">Summary (text)</option>
                  <option value="csv">CSV attachment</option>
                  <option value="json">JSON</option>
                </select>
              </div>
            </div>
            <div className="flex gap-3 pt-2">
              <button
                onClick={handleSend}
                disabled={sending}
                className="flex-1 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-medium"
              >
                {sending ? 'Sending…' : 'Send'}
              </button>
              <button
                onClick={() => setShowSend(false)}
                className="px-4 py-2 rounded-lg border border-zinc-700 text-zinc-400 hover:text-zinc-200 text-sm"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
