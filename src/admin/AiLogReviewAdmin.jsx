import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';

const SAMPLE_SELECTION = JSON.stringify(
  {
    honeypot_ids: [],
    access_ids: [],
    ai_flag_ids: [],
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
  const [history, setHistory] = useState([]);

  const refreshHistory = useCallback(async () => {
    try {
      const data = await api.get('/api/admin/ai/reviews');
      setHistory(Array.isArray(data.reviews) ? data.reviews : []);
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }, [toast]);

  useEffect(() => {
    refreshHistory();
  }, [refreshHistory]);

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
    try {
      const out = await api.post('/api/admin/ai/log-review', {
        review_type: reviewType,
        selection: selectionObj,
        context,
      });

      toast('success', `Done (${out?.model})`);
      setResultMd(`${out.summary_md || ''}`);
      await refreshHistory();
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
              <option value="mixed">mixed</option>
              <option value="honeypot">honeypot</option>
              <option value="maze">maze</option>
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
          <h3 className="text-sm text-ink-300">Latest markdown</h3>
          <div className="card p-4 min-h-[260px] text-sm text-ink-200 whitespace-pre-wrap">
            {resultMd || '(no run yet — response summary_md renders here when successful)'}
          </div>

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
    </div>
  );
}
