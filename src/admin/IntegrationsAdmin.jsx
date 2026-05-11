import { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../lib/api.js';

export default function IntegrationsAdmin({ onToast }) {
  const [schemas, setSchemas] = useState({});
  const [servicesMeta, setServicesMeta] = useState([]);
  const [active, setActive] = useState(null);
  const [detail, setDetail] = useState(null);
  const [pending, setPending] = useState({});

  const toast = useCallback((type, text) => onToast?.({ type, text }), [onToast]);

  const groupedServices = useMemo(() => {
    const entries = Object.entries(schemas || {});
    const byCat = new Map();
    for (const [key, schema] of entries) {
      const cat = schema.category || 'other';
      if (!byCat.has(cat)) byCat.set(cat, []);
      byCat.get(cat).push([key, schema]);
    }
    return [...byCat.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [schemas]);

  const loadSchemas = useCallback(async () => {
    const { schemas: s } = await api.get('/api/admin/integrations/schemas');
    setSchemas(s || {});
  }, []);

  const refreshList = useCallback(async () => {
    try {
      const data = await api.get('/api/admin/integrations');
      setServicesMeta(data.services || []);
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }, [toast]);

  const loadService = useCallback(
    async (key) => {
      try {
        const d = await api.get(`/api/admin/integrations/${key}`);
        setDetail(d);
        setPending({ ...(d.fields || {}) });
        setActive(key);
      } catch (e) {
        toast('error', e.message || String(e));
      }
    },
    [toast],
  );

  useEffect(() => {
    loadSchemas().catch(() => {});
  }, [loadSchemas]);

  useEffect(() => {
    refreshList();
  }, [refreshList]);

  async function save() {
    if (!active || !schemas[active]) return;
    try {
      await api.put(`/api/admin/integrations/${active}`, {
        credentials: pending,
      });
      toast('success', 'Saved');
      await refreshList();
      await loadService(active);
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }

  async function toggle(en) {
    if (!detail?.configured) return;
    try {
      await api.put(`/api/admin/integrations/${active}/toggle`, { enabled: en });
      toast('success', en ? 'Enabled' : 'Disabled');
      await refreshList();
      await loadService(active);
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }

  async function remove() {
    if (!confirm('Forget stored credentials for this integration?')) return;
    try {
      await api.delete(`/api/admin/integrations/${active}`);
      toast('success', 'Removed');
      await refreshList();
      setDetail(null);
      setPending({});
      setActive(null);
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }

  async function testService() {
    try {
      const r = await api.post(`/api/admin/integrations/${active}/test`);
      toast(r.ok ? 'success' : 'error', r.message || (r.ok ? 'OK' : 'Failed'));
      await refreshList();
      await loadService(active);
    } catch (e) {
      toast('error', e.message || String(e));
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl text-ink-100 font-semibold">Integrations</h2>
        <p className="text-sm text-ink-500 mt-1">Credentials are encrypted server-side.</p>
      </div>

      <div className="flex flex-col gap-3">
        {groupedServices.map(([cat, list]) => (
          <div key={cat}>
            <p className="text-xs uppercase tracking-wide text-ink-500 mb-2">{cat}</p>
            <div className="flex flex-wrap gap-2">
              {list.map(([key, schema]) => {
                const row = servicesMeta.find((x) => x.service === key);
                return (
                  <button
                    key={key}
                    type="button"
                    onClick={() => loadService(key)}
                    className={
                      active === key
                        ? 'px-3 py-1 rounded-md bg-ink-800 border border-accent/50 text-accent text-xs'
                        : 'px-3 py-1 rounded-md border border-ink-700 text-ink-300 text-xs hover:border-ink-500'
                    }
                  >
                    {schema.label?.slice(0, 48)}
                    {row?.configured ? (row.enabled ? ' · on' : ' · off') : ''}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {active && detail && (
        <div className="card p-6 space-y-5 max-w-2xl">
          <div className="flex flex-wrap justify-between gap-2">
            <div>
              <h3 className="text-lg text-ink-100">{detail.schema.label}</h3>
              <p className="text-xs text-ink-500 mt-1">
                {detail.configured ? `${detail.enabled ? 'Enabled' : 'Disabled'}` : 'Not configured'}
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              {detail.configured && (
                <>
                  <button type="button" className="btn-ghost text-xs py-1" onClick={() => toggle(!detail.enabled)}>
                    Toggle
                  </button>
                  <button type="button" className="btn-ghost text-xs py-1" onClick={remove}>
                    Delete
                  </button>
                  <button type="button" className="btn-primary text-xs py-1" onClick={testService}>
                    Test
                  </button>
                </>
              )}
            </div>
          </div>
          {detail.schema.helpText && (
            <p className="text-sm text-ink-400">{detail.schema.helpText}</p>
          )}

          {(detail.schema.fields || []).map((field) => (
            <div key={field.key}>
              <label className="text-xs font-medium text-ink-400 mb-1 block">{field.label}</label>
              {field.type === 'boolean' ? (
                <label className="flex items-center gap-2 text-sm text-ink-200">
                  <input
                    type="checkbox"
                    checked={Boolean(pending[field.key])}
                    onChange={(e) => setPending((p) => ({ ...p, [field.key]: e.target.checked }))}
                  />
                  Enabled
                </label>
              ) : (
                <input
                  className="input font-mono text-sm"
                  type={field.secret ? 'password' : field.type === 'number' ? 'number' : 'text'}
                  autoComplete={field.secret ? 'off' : undefined}
                  placeholder={field.placeholder}
                  value={pending[field.key] ?? ''}
                  onChange={(e) =>
                    setPending((p) => ({
                      ...p,
                      [field.key]: field.type === 'number' ? Number(e.target.value) : e.target.value,
                    }))
                  }
                />
              )}
            </div>
          ))}

          <button type="button" className="btn-primary" onClick={save}>
            Save credentials
          </button>
        </div>
      )}
    </div>
  );
}
