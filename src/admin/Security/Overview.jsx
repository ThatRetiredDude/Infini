import { useState, useEffect } from 'react';
import { API_BASE, countryFlag } from './shared.jsx';

function KpiCard({ label, value, sub, accent, mono }) {
  const color =
    accent === 'red'    ? 'text-rose-400'   :
    accent === 'amber'  ? 'text-amber-400'  :
    accent === 'green'  ? 'text-emerald-400':
    accent === 'violet' ? 'text-violet-400' :
    'text-indigo-400';
  return (
    <div className="rounded-xl border border-zinc-700 bg-zinc-900/60 p-4 space-y-1">
      <div className="text-xs text-zinc-500 uppercase tracking-wide">{label}</div>
      <div className={`text-2xl font-bold ${color} ${mono ? 'font-mono' : ''}`}>{value ?? '—'}</div>
      {sub && <div className="text-xs text-zinc-500">{sub}</div>}
    </div>
  );
}

function Sparkline({ data, color = '#818cf8', label }) {
  if (!data || data.length < 2) {
    return (
      <div className="flex flex-col gap-2">
        {label && <div className="text-xs text-zinc-500 uppercase tracking-wide">{label}</div>}
        <div className="text-zinc-600 text-xs italic">No data yet</div>
      </div>
    );
  }
  const max = Math.max(...data.map((d) => d.n), 1);
  const W = 220; const H = 44;
  const pts = data.map((d, i) => {
    const x = (i / (data.length - 1)) * W;
    const y = H - (d.n / max) * (H - 6) - 3;
    return `${x},${y}`;
  });
  // Area fill path
  const areaPath = `M${pts[0]} L${pts.join(' L')} L${W},${H} L0,${H} Z`;
  return (
    <div className="flex flex-col gap-2">
      {label && <div className="text-xs text-zinc-500 uppercase tracking-wide">{label}</div>}
      <svg width={W} height={H} aria-hidden="true">
        <path d={areaPath} fill={color} fillOpacity="0.08" />
        <polyline points={pts.join(' ')} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <div className="flex justify-between text-[10px] text-zinc-600">
        <span>{data[0]?.day ? new Date(data[0].day).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : ''}</span>
        <span className="text-zinc-400">peak: {max.toLocaleString()}</span>
        <span>{data[data.length - 1]?.day ? new Date(data[data.length - 1].day).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : ''}</span>
      </div>
    </div>
  );
}

function fmtTokens(n) {
  if (!n) return '0';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return String(n);
}

function fmtTime(ms) {
  if (!ms) return '0s';
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min`;
  const h = (m / 60).toFixed(1);
  return `${h} hr`;
}

export default function Overview({ toast }) {
  const [data, setData] = useState(null);
  const [mazeStats, setMazeStats] = useState(null);
  const [geoData, setGeoData] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [ovRes, msRes, geoRes] = await Promise.all([
        fetch(`${API_BASE}/admin/security/overview`),
        fetch(`${API_BASE}/admin/security/maze/stats`),
        fetch(`${API_BASE}/admin/security/overview/geo`),
      ]);
      const ov = await ovRes.json();
      const ms = await msRes.json();
      const geo = await geoRes.json();
      if (!ovRes.ok) throw new Error(ov.error || 'Failed');
      setData(ov);
      if (msRes.ok) setMazeStats(ms);
      if (geoRes.ok) setGeoData(geo);
    } catch (e) {
      toast('error', 'Failed to load overview: ' + e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  if (loading) return <div className="py-8 text-zinc-500 italic text-sm text-center">Loading overview…</div>;
  if (!data) return null;

  const { ai_flags, mi_access, honeypot, maze, top_ips, sparklines } = data;
  const mt = mazeStats?.totals || {};
  const countries = geoData?.countries || [];
  const asns = geoData?.asns || [];

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-zinc-100">Overview — last 7 days</h2>
        <button onClick={load} className="px-4 py-1.5 rounded-lg border border-zinc-700 hover:border-zinc-500 text-zinc-400 hover:text-zinc-200 text-xs transition-colors">
          Refresh
        </button>
      </div>

      {/* ── AI flags + honeypot ── */}
      <section>
        <div className="text-[10px] text-zinc-600 uppercase tracking-widest mb-3">AI Abuse Detection</div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <KpiCard label="AI Flags (24h)"    value={ai_flags?.flags_24h?.toLocaleString()}  sub={`${ai_flags?.flags_7d?.toLocaleString()} last 7d`} accent="indigo" />
          <KpiCard label="HIGH severity"     value={ai_flags?.high_24h?.toLocaleString()}   sub={`${ai_flags?.medium_24h} medium · ${ai_flags?.low_24h} low`} accent="red" />
          <KpiCard label="MI Access (24h)"   value={mi_access?.hits_24h?.toLocaleString()}  sub={`${mi_access?.honeypot_24h} honeypot hits`} accent="amber" />
          <KpiCard label="Decoy Endpoints"   value={honeypot?.hits_24h?.toLocaleString()}   sub={`${honeypot?.hits_7d?.toLocaleString()} last 7d`} accent="red" />
        </div>
      </section>

      {/* ── Spider trap ── */}
      <section>
        <div className="text-[10px] text-zinc-600 uppercase tracking-widest mb-3">Spider Trap / Maze</div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <KpiCard label="Maze hits today"   value={maze?.hits_today?.toLocaleString()}     sub={`${maze?.hits_7d?.toLocaleString()} last 7d`} accent="violet" />
          <KpiCard label="Unique IPs (7d)"   value={maze?.unique_ips_7d?.toLocaleString()}  sub={`${maze?.unique_ips_all?.toLocaleString()} all time`} accent="violet" />
          <KpiCard label="Self-IDs captured" value={maze?.self_ids_all?.toLocaleString()}   sub="operators that identified themselves" accent="green" />
          <KpiCard label="Est. tokens burned" value={fmtTokens(mt.tokens_pipeline_est)}     sub="LLM pipeline estimate (all time)" accent="amber" />
        </div>

        {/* Token/cost/time detail strip */}
        {mt.total_hits > 0 && (
          <div className="mt-3 rounded-xl border border-zinc-700/60 bg-zinc-900/40 px-5 py-3 flex flex-wrap gap-6 text-xs">
            <div>
              <span className="text-zinc-500">Total maze requests</span>
              <span className="ml-2 text-zinc-200 font-semibold">{Number(mt.total_hits).toLocaleString()}</span>
            </div>
            <div>
              <span className="text-zinc-500">Tokens generated (~1K/page)</span>
              <span className="ml-2 text-zinc-200 font-semibold">{fmtTokens(mt.tokens_generated)}</span>
            </div>
            <div>
              <span className="text-zinc-500">LLM pipeline tokens (×2)</span>
              <span className="ml-2 text-violet-300 font-semibold">{fmtTokens(mt.tokens_pipeline_est)}</span>
            </div>
            <div>
              <span className="text-zinc-500">Est. API cost burned</span>
              <span className="ml-2 text-emerald-300 font-bold">${mt.cost_usd_est?.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</span>
              <span className="ml-1 text-zinc-600">(GPT-4o rate)</span>
            </div>
            <div>
              <span className="text-zinc-500">Est. scraper time wasted</span>
              <span className="ml-2 text-amber-300 font-semibold">{fmtTime(mt.time_ms_est)}</span>
            </div>
          </div>
        )}
      </section>

      {/* ── Sparklines ── */}
      <section>
        <div className="text-[10px] text-zinc-600 uppercase tracking-widest mb-3">7-Day Trends</div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="rounded-xl border border-zinc-700 bg-zinc-900/60 p-4">
            <Sparkline data={sparklines?.flags || []} color="#f87171" label="AI flags" />
          </div>
          <div className="rounded-xl border border-zinc-700 bg-zinc-900/60 p-4">
            <Sparkline data={sparklines?.mi_access || []} color="#fb923c" label="MI access hits" />
          </div>
          <div className="rounded-xl border border-zinc-700 bg-zinc-900/60 p-4">
            <Sparkline data={sparklines?.maze || []} color="#a78bfa" label="Maze page hits" />
          </div>
        </div>
      </section>

      {/* ── Top IPs ── */}
      {top_ips?.length > 0 && (
        <section>
          <div className="text-[10px] text-zinc-600 uppercase tracking-widest mb-3">Top IPs — last 24h (all sources)</div>
          <div className="rounded-xl border border-zinc-700 bg-zinc-900/60 p-4 space-y-2">
            {top_ips.map((row) => (
              <div key={row.ip} className="flex items-center gap-3">
                <span className="font-mono text-xs text-zinc-200 w-40 shrink-0 truncate">{row.ip}</span>
                <div className="flex-1 bg-zinc-800 rounded h-2 overflow-hidden">
                  <div className="h-full bg-indigo-500/60 rounded" style={{ width: `${Math.min(100, (row.n / (top_ips[0]?.n || 1)) * 100)}%` }} />
                </div>
                <span className="text-xs text-zinc-400 w-10 text-right">{row.n}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── UA summary from maze stats ── */}
      {mazeStats?.ua_summary?.length > 0 && (
        <section>
          <div className="text-[10px] text-zinc-600 uppercase tracking-widest mb-3">Scraper Fingerprints (Maze UA Summary)</div>
          <div className="rounded-xl border border-zinc-700 bg-zinc-900/60 p-4 space-y-2">
            {mazeStats.ua_summary.map((row) => (
              <div key={row.family} className="flex items-center gap-3">
                <span className="text-xs text-zinc-300 w-48 shrink-0 truncate">{row.family}</span>
                <div className="flex-1 bg-zinc-800 rounded h-2 overflow-hidden">
                  <div className="h-full bg-violet-500/50 rounded"
                    style={{ width: `${Math.min(100, (row.hits / (mazeStats.ua_summary[0]?.hits || 1)) * 100)}%` }} />
                </div>
                <span className="text-[10px] text-zinc-500 w-20 text-right">{row.hits?.toLocaleString()} hits · {row.ips} IP{row.ips !== 1 ? 's' : ''}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── Top countries ── */}
      {countries.length > 0 && (
        <section>
          <div className="text-[10px] text-zinc-600 uppercase tracking-widest mb-3">Top Countries (all scraper sources)</div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Bar chart */}
            <div className="rounded-xl border border-zinc-700 bg-zinc-900/60 p-4 space-y-2">
              {countries.slice(0, 15).map((row) => (
                <div key={row.country} className="flex items-center gap-2">
                  <span className="text-base leading-none w-7 shrink-0">{countryFlag(row.country)}</span>
                  <span className="text-xs text-zinc-300 w-8 shrink-0">{row.country}</span>
                  <div className="flex-1 bg-zinc-800 rounded h-2.5 overflow-hidden">
                    <div className="h-full bg-sky-500/60 rounded"
                      style={{ width: `${Math.min(100, (row.hits / (countries[0]?.hits || 1)) * 100)}%` }} />
                  </div>
                  <span className="text-[10px] text-zinc-500 w-28 text-right shrink-0">{row.hits?.toLocaleString()} hits · {row.ips} IP{row.ips !== 1 ? 's' : ''}</span>
                </div>
              ))}
            </div>

            {/* Flag grid */}
            <div className="rounded-xl border border-zinc-700 bg-zinc-900/60 p-4">
              <div className="text-[10px] text-zinc-500 uppercase tracking-wide mb-3">Heat map (by hit volume)</div>
              <div className="flex flex-wrap gap-2">
                {countries.slice(0, 30).map((row) => {
                  const pct = Math.min(100, (row.hits / (countries[0]?.hits || 1)) * 100);
                  const opacity = Math.max(0.2, pct / 100);
                  return (
                    <div key={row.country} title={`${row.country}: ${row.hits} hits`}
                      className="flex flex-col items-center gap-0.5 p-1.5 rounded-lg border border-zinc-700/60"
                      style={{ background: `rgba(99,102,241,${opacity * 0.3})`, borderColor: `rgba(99,102,241,${opacity * 0.5})` }}>
                      <span className="text-xl leading-none">{countryFlag(row.country)}</span>
                      <span className="text-[9px] text-zinc-400">{row.country}</span>
                      <span className="text-[9px] text-zinc-500">{row.hits >= 1000 ? `${(row.hits/1000).toFixed(0)}K` : row.hits}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </section>
      )}

      {/* ── Top ASNs ── */}
      {asns.length > 0 && (
        <section>
          <div className="text-[10px] text-zinc-600 uppercase tracking-widest mb-3">Top ASNs / Hosting Providers</div>
          <div className="rounded-xl border border-zinc-700 bg-zinc-900/60 p-4 space-y-2">
            {asns.slice(0, 12).map((row) => (
              <div key={row.org} className="flex items-center gap-3">
                <span className="text-xs text-zinc-300 w-56 shrink-0 truncate" title={row.org}>
                  {row.org?.replace(/^AS\d+\s+/, '').slice(0, 40) || '—'}
                </span>
                <div className="flex-1 bg-zinc-800 rounded h-2.5 overflow-hidden">
                  <div className="h-full bg-amber-500/50 rounded"
                    style={{ width: `${Math.min(100, (row.hits / (asns[0]?.hits || 1)) * 100)}%` }} />
                </div>
                <span className="text-[10px] text-zinc-500 w-28 text-right shrink-0">{row.hits?.toLocaleString()} hits · {row.ips} IP{row.ips !== 1 ? 's' : ''}</span>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
