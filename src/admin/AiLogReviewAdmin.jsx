import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';

const SAMPLE_SELECTION = JSON.stringify(
  {
    honeypot_ids: [],
    access_ids: [],
    ai_flag_ids: [],
    network_ids: [],
    maze_days: {},
    notes: 'Optional pasted JSON row IDs.',
  },
  null,
  2,
);

export default function AiLogReviewAdmin({ onToast }) {
  const toast = useCallback((type, text) => onToast?.({ type, text }), [onToast]);
  const [context, setContext] = useState('');
  const [selectionJson, setSelectionJson] = useState(SAMPLE_SELECTION);
  const [reviewType, setReviewType] = useState('mixed');
  const [running, setRunning] = useState(false);
  const [resultMd, setResultMd] = useState('');
  const [resultActions, setResultActions] = useState([]);
  const [resultGuard, setResultGuard] = useState('');
  const [history, setHistory] = useState([]);
  const [logs, setLogs] = useState([]);
  const [expandedLog, setExpandedLog] = useState(null);

  const refreshHistory = useCallback(async () => {
    try {
      const data = await api.get('/api/admin/ai/reviews');
      setHistory(Array.isArray(data.reviews) ? data.reviews : []);
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }, [toast]);

  const refreshLogs = useCallback(async () => {
    try {
      const data = await api.get('/api/admin/ai/request-logs');
      setLogs(Array.isArray(data.logs) ? data.logs : []);
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }, [toast]);

  useEffect(() => {
    refreshHistory();
    refreshLogs();
  }, [refreshHistory, refreshLogs]);

  async function submit() {
    let selectionObj = {};
    try {
      selectionObj = selectionJson.trim() ? JSON.parse(selectionJson) : {};
      if (!selectionObj || typeof selectionObj !== 'object')
        selectionObj = {};
    } catch {
      toast('error', 'Selection JSON invalid');
      return;
    }

    setRunning(true);
    setResultMd('');
    setResultActions([]);
    setResultGuard('');
    try {
      const out = await api.post('/api/admin/ai/log-review', {
        review_type: reviewType,
        selection: selectionObj,
        context,
      });

      toast('success', `Done (${out?.model})`);
      setResultMd(`${out.summary_md || ''}`);
      setResultActions(out.suggested_actions || []);
      setResultGuard(out.guard || '');
      await refreshHistory();
      await refreshLogs();
    } catch (e) {
      toast('error', e.message || String(e));
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl text-ink-100 font-semibold">AI log review</h2>
        <p className="text-sm text-ink-500 mt-1">
          Sends structured selection + analyst notes through the input guard, then Grok (xAI compat).
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-3">
          <div>
            <label className="text-xs text-ink-500 uppercase tracking-wide mb-1 block">
              Review type
            </label>
            <select
              value={reviewType}
              className="input"
              onChange={(e) => setReviewType(e.target.value)}
            >
              <option value="network">network sensor (Cowrie)</option>
              <option value="mixed">mixed</option>
              <option value="honeypot">monitored endpoints</option>
              <option value="maze">data room</option>
              <option value="access">access</option>
              <option value="ai_flag">ai_flag</option>
              <option value="alert">alert</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-ink-500 uppercase tracking-wide mb-1 block">
              Analyst guidance
            </label>
            <textarea
              value={context}
              onChange={(e) => setContext(e.target.value)}
              className="input min-h-[120px]"
              placeholder="Instructions for Grok..."
            />
          </div>
          <div>
            <label className="text-xs text-ink-500 uppercase tracking-wide mb-1 block">
              Selection JSON
            </label>
            <textarea
              value={selectionJson}
              onChange={(e) => setSelectionJson(e.target.value)}
              className="input font-mono text-xs min-h-[180px]"
            />
          </div>
          <button type="button" className="btn-primary" disabled={running} onClick={submit}>
            {running ? 'Running…' : 'Run Grok'}
          </button>
        </div>

        <div className="space-y-3">
          <h3 className="text-sm text-ink-300">Latest result</h3>
          <div className="card p-4 min-h-[200px] text-sm text-ink-200 whitespace-pre-wrap">
            {resultMd || '(no run yet — response summary_md renders here when successful)'}
          </div>
          {resultGuard && (
            <div className="text-xs text-ink-400">Guard: <span className="text-accent">{resultGuard}</span></div>
          )}
          {resultActions.length > 0 && (
            <div>
              <div className="text-xs text-ink-300 mb-1">Suggested actions</div>
              <ul className="text-xs text-ink-200 list-disc pl-5">
                {resultActions.map((a, i) => <li key={i}>{a}</li>)}
              </ul>
            </div>
          )}

          <h3 className="text-sm text-ink-300 pt-4">Recent reviews</h3>
          <ul className="text-xs font-mono text-ink-400 space-y-2 max-h-48 overflow-auto">
            {history.map((h) => (
              <li key={h.id} className="border-b border-ink-800 pb-2">
                <span className="text-accent">{h.id}</span> · {h.review_type} · {h.model}
                <br />
                <span className="text-ink-500 line-clamp-2">{h.summary_md || ''}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm text-ink-300">Full Request / Response Logs (all LLM I/O)</h3>
          <button type="button" className="text-xs btn" onClick={refreshLogs}>Refresh logs</button>
        </div>
        <div className="card p-2 text-xs max-h-96 overflow-auto">
          {logs.length === 0 && <div className="text-ink-500 p-4">(no logs yet)</div>}
          {logs.map((log) => (
            <div key={log.request_id} className="border-b border-ink-800 py-2">
              <div
                className="flex items-center gap-2 cursor-pointer hover:bg-ink-900 px-2"
                onClick={() => setExpandedLog(expandedLog === log.request_id ? null : log.request_id)}
              >
                <span className="text-accent font-mono">{log.request_id?.slice(0,8)}</span>
                <span>{log.review_type}</span>
                <span className={log.status === 'succeeded' ? 'text-green-400' : log.status === 'failed' ? 'text-red-400' : ''}>{log.status}</span>
                <span className="text-ink-500">{log.model || ''}</span>
                <span className="text-ink-400 ml-auto">{log.created_at}</span>
              </div>
              {expandedLog === log.request_id && (
                <div className="mt-2 p-3 bg-ink-950 text-[10px] font-mono whitespace-pre-wrap overflow-auto">
                  <div><strong>Prompt sent:</strong></div>
                  <div className="text-ink-300 mb-2">{log.request_payload || '(none)'}</div>
                  <div><strong>Response received:</strong></div>
                  <div className="text-ink-300 mb-2">{log.response_payload || '(none)'}</div>
                  <div>Tokens: {log.prompt_tokens || 0} / {log.completion_tokens || 0} / {log.total_tokens || 0}</div>
                  {log.error_message && <div className="text-red-400">Error: {log.error_message}</div>}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
