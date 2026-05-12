import { useCallback, useEffect, useRef, useState } from 'react';
import { API_BASE, IpCell } from './shared.jsx';

const SOURCE_OPTS = [
  { id: 'honeypot', label: 'Monitored endpoints' },
  { id: 'maze', label: 'Data room' },
  { id: 'access', label: 'MI access log' },
  { id: 'ai_flags', label: 'AI safety flags' },
];

const HOUR_PRESETS = [
  { h: 24, label: '24h' },
  { h: 168, label: '7d' },
  { h: 720, label: '30d' },
];

function buildQuery(filters) {
  const p = new URLSearchParams();
  p.set('sources', filters.sources.join(','));
  p.set('limit', String(filters.rowLimit));
  p.set('scan_cap', String(filters.scanCap));
  p.set('min_hits', String(filters.minHits));

  if (filters.useRange && filters.since) p.set('since', filters.since);
  if (filters.useRange && filters.until) p.set('until', filters.until);
  if (!filters.useRange) p.set('hours', String(filters.hours));

  if (filters.ip.trim()) p.set('ip', filters.ip.trim());
  if (filters.country.trim()) p.set('country', filters.country.trim());
  if (filters.pathContains.trim()) p.set('path_contains', filters.pathContains.trim());
  if (filters.honeypotSource.trim()) p.set('source', filters.honeypotSource.trim());
  if (filters.selfIdOnly) p.set('self_id_only', 'true');
  if (filters.route.trim()) p.set('route', filters.route.trim());
  return p.toString();
}

export default function GlobeViewTab({ toast }) {
  const mountRef = useRef(null);
  const globeRef = useRef(null);
  const [globeReady, setGlobeReady] = useState(false);

  const [filters, setFilters] = useState({
    sources: ['honeypot', 'maze'],
    useRange: false,
    hours: 168,
    since: '',
    until: '',
    ip: '',
    country: '',
    pathContains: '',
    honeypotSource: '',
    selfIdOnly: false,
    route: '',
    minHits: 1,
    rowLimit: 300,
    scanCap: 2800,
  });

  const [lures, setLures] = useState([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);
  const [meta, setMeta] = useState(null);
  const [points, setPoints] = useState([]);
  const [rows, setRows] = useState([]);

  useEffect(() => {
    fetch(`${API_BASE}/admin/security/lures`, { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => setLures(Array.isArray(d.rows) ? d.rows : []))
      .catch(() => setLures([]));
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const q = buildQuery(filters);
      const res = await fetch(`${API_BASE}/admin/security/globe-view?${q}`, { credentials: 'include' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `failed_${res.status}`);
      setPoints(Array.isArray(data.points) ? data.points : []);
      setRows(Array.isArray(data.rows) ? data.rows : []);
      setMeta(data.meta || null);
    } catch (e) {
      setErr(e.message || String(e));
      setPoints([]);
      setRows([]);
      setMeta(null);
      if (toast) toast('error', e.message || 'Globe data failed to load');
    } finally {
      setLoading(false);
    }
  }, [filters, toast]);

  useEffect(() => {
    load();
  // eslint-disable-next-line react-hooks/exhaustive-deps -- Apply button applies filter changes; avoid refetch on every keystroke
  }, []);

  useEffect(() => {
    let cancelled = false;
    let offResize = null;
    const rootEl = mountRef.current;
    if (!rootEl) return undefined;

    Promise.all([import('globe.gl'), import('three')])
      .then(([{ default: Globe }, THREE]) => {
        if (cancelled || !mountRef.current) return;
        const { MeshBasicMaterial, Color } = THREE;
        const h = () => Math.max(380, Math.min(560, window.innerHeight * 0.45));
        const globe = Globe(mountRef.current)
          .backgroundColor('#020617')
          .globeMaterial(
            new MeshBasicMaterial({
              wireframe: true,
              color: new Color(0x6366f1),
              transparent: true,
              opacity: 0.2,
            }),
          )
          .showGraticules(true)
          .showAtmosphere(true)
          .atmosphereColor('#312e81')
          .atmosphereAltitude(0.15)
          .pointsData([])
          .pointLat('lat')
          .pointLng('lng')
          .pointAltitude(0.012)
          .pointRadius((d) => Math.min(0.55, 0.12 + Math.sqrt(d.weight) * 0.06))
          .pointColor((d) =>
            d.kinds?.includes('honeypot') && d.kinds?.includes('maze')
              ? '#a78bfa'
              : d.kinds?.includes('honeypot')
                ? '#f472b6'
                : '#38bdf8',
          )
          .pointResolution(18)
          .onPointClick((p) => {
            if (p?.ip && toast) toast('info', `${p.ip} · ${p.weight} weighted hits`);
          });

        try {
          const ctl = globe.controls();
          if (ctl) {
            ctl.autoRotate = true;
            ctl.autoRotateSpeed = 0.35;
          }
        } catch {
          /* ignore */
        }

        const resize = () => {
          if (!mountRef.current || !globe) return;
          globe.width(mountRef.current.clientWidth);
          globe.height(h());
        };
        resize();
        window.addEventListener('resize', resize);
        offResize = () => window.removeEventListener('resize', resize);
        globeRef.current = globe;
        setGlobeReady(true);
      })
      .catch((e) => {
        if (toast) toast('error', `Globe GL: ${e.message || e}`);
      });

    return () => {
      cancelled = true;
      if (offResize) offResize();
      rootEl.innerHTML = '';
      globeRef.current = null;
      setGlobeReady(false);
    };
  }, [toast]);

  useEffect(() => {
    if (!globeReady || !globeRef.current) return;
    globeRef.current.pointsData(points);
  }, [globeReady, points]);

  const toggleSource = (id) => {
    setFilters((f) => {
      const has = f.sources.includes(id);
      let sources = has ? f.sources.filter((s) => s !== id) : [...f.sources, id];
      if (sources.length === 0) sources = ['honeypot'];
      return { ...f, sources };
    });
  };

  return (
    <div className="space-y-6">
      <p className="text-zinc-400 text-sm max-w-3xl">
        Spin the globe to correlate enriched IPs (IPInfo lat/lng). Dots aggregate weight across selected
        sources. The table lists the same filter window — MI access and AI flags have no geo unless enriched
        elsewhere.
      </p>

      <div className="rounded-xl border border-zinc-700/80 bg-zinc-900/40 p-4 space-y-4">
        <div className="flex flex-wrap gap-3 items-center">
          <span className="text-xs text-zinc-500 uppercase tracking-wide">Sources</span>
          {SOURCE_OPTS.map((s) => (
            <label key={s.id} className="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
              <input
                type="checkbox"
                checked={filters.sources.includes(s.id)}
                onChange={() => toggleSource(s.id)}
                className="rounded border-zinc-600"
              />
              {s.label}
            </label>
          ))}
        </div>

        <div className="flex flex-wrap gap-4 items-end">
          <label className="flex flex-col gap-1 text-xs text-zinc-500">
            Time mode
            <select
              className="bg-zinc-800 border border-zinc-600 rounded-md px-2 py-1.5 text-sm text-zinc-200"
              value={filters.useRange ? 'range' : 'rolling'}
              onChange={(e) =>
                setFilters((f) => ({ ...f, useRange: e.target.value === 'range' }))
              }
            >
              <option value="rolling">Rolling window</option>
              <option value="range">Date range</option>
            </select>
          </label>

          {!filters.useRange && (
            <label className="flex flex-col gap-1 text-xs text-zinc-500">
              Window
              <select
                className="bg-zinc-800 border border-zinc-600 rounded-md px-2 py-1.5 text-sm text-zinc-200"
                value={filters.hours}
                onChange={(e) => setFilters((f) => ({ ...f, hours: Number(e.target.value) }))}
              >
                {HOUR_PRESETS.map((p) => (
                  <option key={p.h} value={p.h}>
                    Last {p.label}
                  </option>
                ))}
                <option value={2160}>90d</option>
              </select>
            </label>
          )}

          {filters.useRange && (
            <>
              <label className="flex flex-col gap-1 text-xs text-zinc-500">
                Since
                <input
                  type="date"
                  className="bg-zinc-800 border border-zinc-600 rounded-md px-2 py-1.5 text-sm text-zinc-200"
                  value={filters.since}
                  onChange={(e) => setFilters((f) => ({ ...f, since: e.target.value }))}
                />
              </label>
              <label className="flex flex-col gap-1 text-xs text-zinc-500">
                Until
                <input
                  type="date"
                  className="bg-zinc-800 border border-zinc-600 rounded-md px-2 py-1.5 text-sm text-zinc-200"
                  value={filters.until}
                  onChange={(e) => setFilters((f) => ({ ...f, until: e.target.value }))}
                />
              </label>
            </>
          )}

          <label className="flex flex-col gap-1 text-xs text-zinc-500">
            Country (ISO2)
            <input
              className="bg-zinc-800 border border-zinc-600 rounded-md px-2 py-1.5 text-sm text-zinc-200 w-24"
              placeholder="US"
              value={filters.country}
              onChange={(e) => setFilters((f) => ({ ...f, country: e.target.value }))}
              maxLength={2}
            />
          </label>

          <label className="flex flex-col gap-1 text-xs text-zinc-500">
            IP
            <input
              className="bg-zinc-800 border border-zinc-600 rounded-md px-2 py-1.5 text-sm text-zinc-200 font-mono w-40"
              value={filters.ip}
              onChange={(e) => setFilters((f) => ({ ...f, ip: e.target.value }))}
            />
          </label>

          <label className="flex flex-col gap-1 text-xs text-zinc-500">
            Path / URL contains
            <input
              className="bg-zinc-800 border border-zinc-600 rounded-md px-2 py-1.5 text-sm text-zinc-200 w-48"
              value={filters.pathContains}
              onChange={(e) => setFilters((f) => ({ ...f, pathContains: e.target.value }))}
            />
          </label>
        </div>

        <div className="flex flex-wrap gap-4 items-end">
          <label className="flex flex-col gap-1 text-xs text-zinc-500">
            Monitored lure
            <select
              className="bg-zinc-800 border border-zinc-600 rounded-md px-2 py-1.5 text-sm text-zinc-200 min-w-[200px]"
              value={filters.honeypotSource}
              onChange={(e) => setFilters((f) => ({ ...f, honeypotSource: e.target.value }))}
            >
              <option value="">(any)</option>
              {lures.map((l) => (
                <option key={l.source} value={l.source}>
                  {l.source}
                </option>
              ))}
            </select>
          </label>

          <label className="flex items-center gap-2 text-sm text-zinc-400 cursor-pointer">
            <input
              type="checkbox"
              checked={filters.selfIdOnly}
              onChange={(e) => setFilters((f) => ({ ...f, selfIdOnly: e.target.checked }))}
              className="rounded border-zinc-600"
            />
            Data room: self-ID only
          </label>

          <label className="flex flex-col gap-1 text-xs text-zinc-500">
            AI flag route equals
            <input
              className="bg-zinc-800 border border-zinc-600 rounded-md px-2 py-1.5 text-sm text-zinc-200 w-44"
              value={filters.route}
              onChange={(e) => setFilters((f) => ({ ...f, route: e.target.value }))}
            />
          </label>

          <label className="flex flex-col gap-1 text-xs text-zinc-500">
            Min weight (globe)
            <input
              type="number"
              min={1}
              className="bg-zinc-800 border border-zinc-600 rounded-md px-2 py-1.5 text-sm text-zinc-200 w-24"
              value={filters.minHits}
              onChange={(e) =>
                setFilters((f) => ({ ...f, minHits: Math.max(1, Number(e.target.value) || 1) }))
              }
            />
          </label>

          <label className="flex flex-col gap-1 text-xs text-zinc-500">
            Table rows cap
            <input
              type="number"
              min={50}
              max={500}
              className="bg-zinc-800 border border-zinc-600 rounded-md px-2 py-1.5 text-sm text-zinc-200 w-24"
              value={filters.rowLimit}
              onChange={(e) =>
                setFilters((f) => ({
                  ...f,
                  rowLimit: Math.min(500, Math.max(50, Number(e.target.value) || 300)),
                }))
              }
            />
          </label>
        </div>

        <button
          type="button"
          disabled={loading}
          onClick={() => load()}
          className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-medium"
        >
          {loading ? 'Loading…' : 'Apply filters'}
        </button>
        {err && <div className="text-rose-400 text-sm">{err}</div>}
        {meta && (
          <div className="text-zinc-500 text-xs font-mono space-y-1">
            <div>
              Points: {meta.points_count} · table rows: {rows.length} (scanned {meta.table_total_before_limit}{' '}
              before cap) · scan_cap {meta.scan_cap}
            </div>
            <div>{meta.note}</div>
          </div>
        )}
      </div>

      <div className="rounded-xl border border-zinc-700 overflow-hidden bg-zinc-950 relative">
        <div ref={mountRef} className="w-full" style={{ minHeight: 400 }} />
        {!globeReady && (
          <div className="absolute inset-0 flex items-center justify-center text-zinc-500 text-sm pointer-events-none bg-zinc-950/80">
            Initializing WebGL globe…
          </div>
        )}
        <p className="px-3 py-2 text-[11px] text-zinc-500 border-t border-zinc-800">
          Drag to rotate · scroll to zoom · click a pillar for IP summary
        </p>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-zinc-200 mb-3">Filtered events</h2>
        <div className="overflow-x-auto rounded-lg border border-zinc-700">
          <table className="min-w-full text-xs text-left">
            <thead className="bg-zinc-800/80 text-zinc-400 uppercase tracking-wide">
              <tr>
                <th className="px-3 py-2">Kind</th>
                <th className="px-3 py-2">Time</th>
                <th className="px-3 py-2">IP / geo</th>
                <th className="px-3 py-2">Endpoint</th>
                <th className="px-3 py-2">Source</th>
                <th className="px-3 py-2">Weight</th>
                <th className="px-3 py-2">Lat/Lng</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {rows.map((r, i) => (
                <tr key={`${r.kind}-${r.id}-${i}`} className="hover:bg-zinc-800/40">
                  <td className="px-3 py-2 text-zinc-300 font-mono">{r.kind}</td>
                  <td className="px-3 py-2 text-zinc-400 whitespace-nowrap font-mono">
                    {r.time?.slice?.(0, 19) || '—'}
                  </td>
                  <td className="px-3 py-2">
                    <IpCell
                      ip={r.ip}
                      enrichment={
                        r.country
                          ? { summary: { country: r.country, org: null }, ipinfo: { country: r.country, city: r.city } }
                          : null
                      }
                    />
                  </td>
                  <td className="px-3 py-2 text-zinc-400 max-w-[220px] truncate font-mono" title={r.endpoint || ''}>
                    {r.endpoint || r.path || '—'}
                  </td>
                  <td className="px-3 py-2 text-zinc-400 max-w-[180px] truncate" title={r.source || ''}>
                    {r.source || '—'}
                  </td>
                  <td className="px-3 py-2 text-zinc-300">{r.weight}</td>
                  <td className="px-3 py-2 text-zinc-500 font-mono">
                    {r.lat != null && r.lng != null ? (
                      <span>
                        {r.lat.toFixed(2)}, {r.lng.toFixed(2)}
                      </span>
                    ) : (
                      '—'
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && !loading && (
            <div className="p-8 text-center text-zinc-500 text-sm">No rows match the current filters.</div>
          )}
        </div>
      </div>
    </div>
  );
}
