import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';

export default function BrandingAdmin({ onToast }) {
  const [branding, setBranding] = useState({ brand_name: 'Infini', footer_text: 'Infini · MI', accent_color: '#34d399' });
  const [loading, setLoading] = useState(true);
  const toast = useCallback((type, text) => onToast?.({ type, text }), [onToast]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.get('/api/site/branding');
      setBranding({
        brand_name: data?.brand_name ?? 'Infini',
        footer_text: data?.footer_text ?? 'Infini · MI',
        accent_color: data?.accent_color ?? '#34d399',
      });
    } catch (e) {
      toast('error', e.message || String(e));
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  async function save() {
    try {
      const out = await api.patch('/api/admin/site/branding', {
        brand_name: branding.brand_name,
        footer_text: branding.footer_text,
        accent_color: branding.accent_color,
      });
      toast('success', 'Branding updated — refresh public pages to see changes');
      if (out) {
        setBranding({
          brand_name: out.brand_name,
          footer_text: out.footer_text,
          accent_color: out.accent_color,
        });
      }
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }

  return (
    <div className="space-y-4 max-w-xl">
      <div>
        <h2 className="text-xl text-ink-100 font-semibold">Public branding</h2>
        <p className="text-sm text-ink-500 mt-1">
          Customize the public-facing header name, footer text, and site accent color. Changes apply to the public site only; the admin area and all backend strings remain "Infini".
        </p>
      </div>

      {loading ? (
        <p className="text-ink-400 text-sm">Loading…</p>
      ) : (
        <div className="card p-6 space-y-5">
          <div>
            <label className="label">Header / logo text (top-left)</label>
            <input
              className="input"
              value={branding.brand_name}
              onChange={(e) => setBranding((b) => ({ ...b, brand_name: e.target.value }))}
              placeholder="Infini"
            />
            <p className="text-xs text-ink-500 mt-1">Appears in the sticky header navigation.</p>
          </div>

          <div>
            <label className="label">Accent color</label>
            <div className="flex items-center gap-3">
              <input
                type="color"
                className="h-10 w-16 rounded border border-ink-700 bg-ink-900 p-1"
                value={branding.accent_color}
                onChange={(e) => setBranding((b) => ({ ...b, accent_color: e.target.value }))}
              />
              <input
                className="input font-mono w-32"
                value={branding.accent_color}
                onChange={(e) => setBranding((b) => ({ ...b, accent_color: e.target.value }))}
              />
            </div>
            <p className="text-xs text-ink-500 mt-1">All links, buttons, borders, glows, and focus rings will use this color site-wide.</p>
          </div>

          <div className="pt-2 border-t border-ink-700">
            <div className="text-xs text-ink-400 mb-1">Preview</div>
            <div className="flex items-center gap-4 text-sm">
              <span className="font-mono font-semibold" style={{ color: branding.accent_color }}>{branding.brand_name}</span>
              <span className="text-ink-400">·</span>
              <span className="font-mono text-xs text-ink-400">{branding.footer_text}</span>
            </div>
          </div>

          <button type="button" className="btn-primary mt-2" onClick={save}>
            Save branding
          </button>
        </div>
      )}
    </div>
  );
}
