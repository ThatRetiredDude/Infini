/**
 * FlaggedIpsTab — IPs flagged as Tor exits, repeat offenders, or high abuse score.
 *
 * Three sections:
 *   1. Repeat Offenders — IPs seen on 5+ distinct days
 *   2. High Abuse Score — AbuseIPDB >= 50%
 *   3. Tor Exits — any Tor exit node that has hit the site
 *
 * Blocklist export: download flagged IPs as nginx / iptables / Cloudflare / CIDR
 * for manual review. No automatic blocking.
 */

import { useState, useEffect, useCallback } from 'react';
import { API_BASE, IpCell, countryFlag } from './shared.jsx';

// ─── Flag badges ──────────────────────────────────────────────────────────────

function FlagBadge({ flag }) {
  const MAP = {
    'tor':          'bg-purple-500/20 border-purple-500/40 text-purple-300',
    'repeat':       'bg-orange-500/20 border-orange-500/40 text-orange-300',
    'high-abuse':   'bg-rose-500/20 border-rose-500/40 text-rose-300',
    'hosting':      'bg-amber-500/20 border-amber-500/40 text-amber-300',
  };
  const c = MAP[flag] || 'bg-zinc-700/40 border-zinc-600/40 text-zinc-400';
  return (
    <span className={`px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase ${c}`}>
      {flag}
    </span>
  );
}

// ─── Blocklist export ─────────────────────────────────────────────────────────

function buildBlocklist(ips, format) {
  const clean = [...new Set(ips.filter(Boolean))];
  switch (format) {
    case 'nginx':
      return clean.map((ip) => `deny ${ip};`).join('\n') + '\n';
    case 'iptables':
      return clean.map((ip) => `iptables -A INPUT -s ${ip} -j DROP`).join('\n') + '\n';
    case 'cloudflare':
      return JSON.stringify(clean.map((ip) => ({ ip, notes: 'Flagged by security monitor', mode: 'block' })), null, 2);
    case 'cidr':
    default:
      return clean.join('\n') + '\n';
  }
}

function downloadText(text, filename) {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a); URL.revokeObjectURL(url);
}

function BlocklistExport({ ips }) {
  const [format, setFormat] = useState('cidr');
  const count = [...new Set(ips.filter(Boolean))].length;
  if (count === 0) return null;
  return (
    <div className="flex items-center gap-2 flex-wrap">
      <span className="text-xs text-zinc-500">{count} IPs</span>
      <select value={format} onChange={(e) => setFormat(e.target.value)}
        className="rounded border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-300 focus:border-indigo-500 focus:outline-none">
        <option value="cidr">Plain CIDR / IP list</option>
        <option value="nginx">nginx deny rules</option>
        <option value="iptables">iptables DROP rules</option>
        <option value="cloudflare">Cloudflare bulk block (JSON)</option>
      </select>
      <button
        onClick={() => downloadText(buildBlocklist(ips, format), `flagged-ips.${format === 'cloudflare' ? 'json' : 'txt'}`)}
        className="px-3 py-1 rounded-lg border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs transition-colors">
        ↓ Export for manual review
      </button>
      <span className="text-[10px] text-zinc-600 italic">No automatic blocking — for manual action only</span>
    </div>
  );
}

// ─── IP row ───────────────────────────────────────────────────────────────────

function IpRow({ row, source }) {
  const [expanded, setExpanded] = useState(false);
  const enrich = row.enrichment
    ? (typeof row.enrichment === 'string' ? JSON.parse(row.enrichment) : row.enrichment)
    : null;
  const isTor = row.is_tor || (row.flags || []).includes('tor');
  const isRepeat = (row.flags || []).includes('repeat');

  return (
    <>
      <tr className="hover:bg-zinc-800/40 cursor-pointer" onClick={() => setExpanded((e) => !e)}>
        <td className="px-3 py-2.5">
          <IpCell ip={row.ip} enrichment={enrich} isTor={isTor} isRepeat={isRepeat} />
        </td>
        <td className="px-3 py-2.5">
          <div className="flex flex-wrap gap-1">
            {(row.flags || []).filter(Boolean).map((f) => <FlagBadge key={f} flag={f} />)}
          </div>
        </td>
        <td className="px-3 py-2.5 text-zinc-300 text-xs">{source}</td>
        <td className="px-3 py-2.5 text-zinc-100 font-semibold text-sm">
          {row.total_hits != null ? Number(row.total_hits).toLocaleString() : (row.hit_count ?? '—')}
        </td>
        <td className="px-3 py-2.5 text-zinc-400 text-xs">
          {row.days != null ? `${row.days} days` : '—'}
        </td>
        <td className="px-3 py-2.5 text-zinc-500 text-xs whitespace-nowrap">
          {row.last_seen ? new Date(row.last_seen).toLocaleDateString() : '—'}
        </td>
        <td className="px-3 py-2.5 text-zinc-600 text-[10px]">▾</td>
      </tr>
      {expanded && enrich && (
        <tr className="bg-zinc-900/60">
          <td colSpan={7} className="px-5 py-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              {enrich.ipinfo && (
                <div className="rounded-lg bg-zinc-800/60 border border-zinc-700/60 p-3 space-y-1">
                  <div className="text-zinc-400 font-semibold text-[10px] uppercase tracking-wide">IPInfo</div>
                  {enrich.ipinfo.country && <div className="text-zinc-300">{countryFlag(enrich.ipinfo.country)} {enrich.ipinfo.country}{enrich.ipinfo.city ? ` / ${enrich.ipinfo.city}` : ''}</div>}
                  {enrich.ipinfo.org && <div className="text-zinc-300 break-all">{enrich.ipinfo.org}</div>}
                  {enrich.ipinfo.hostname && <div className="font-mono text-zinc-400 break-all">{enrich.ipinfo.hostname}</div>}
                  {enrich.ipinfo.is_hosting && <div className="text-amber-300">⚠ Hosting / Cloud provider</div>}
                </div>
              )}
              {enrich.abuseipdb && (
                <div className="rounded-lg bg-zinc-800/60 border border-zinc-700/60 p-3 space-y-1">
                  <div className="text-zinc-400 font-semibold text-[10px] uppercase tracking-wide">AbuseIPDB</div>
                  <div className="text-zinc-300">Abuse score: <span className={`font-bold ${(enrich.abuseipdb.abuse_confidence ?? 0) >= 50 ? 'text-rose-300' : 'text-emerald-300'}`}>{enrich.abuseipdb.abuse_confidence ?? '—'}%</span></div>
                  {enrich.abuseipdb.total_reports != null && <div className="text-zinc-400">{enrich.abuseipdb.total_reports} reports</div>}
                  {enrich.abuseipdb.is_tor && <div className="text-rose-300">TOR exit node</div>}
                  {enrich.abuseipdb.usage_type && <div className="text-zinc-400">{enrich.abuseipdb.usage_type}</div>}
                </div>
              )}
              {enrich.greynoise && (
                <div className="rounded-lg bg-zinc-800/60 border border-zinc-700/60 p-3 space-y-1">
                  <div className="text-zinc-400 font-semibold text-[10px] uppercase tracking-wide">GreyNoise</div>
                  <div className="text-zinc-300">Class: <span className={`font-bold ${enrich.greynoise.classification === 'malicious' ? 'text-rose-300' : enrich.greynoise.classification === 'benign' ? 'text-emerald-300' : 'text-zinc-300'}`}>{enrich.greynoise.classification}</span></div>
                  {enrich.greynoise.noise && <div className="text-amber-300">Known internet scanner</div>}
                  {enrich.greynoise.name && <div className="text-zinc-300">{enrich.greynoise.name}</div>}
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function IpTable({ rows, source, emptyMsg }) {
  if (!rows?.length) return <div className="text-zinc-600 text-xs italic py-4 text-center">{emptyMsg}</div>;
  return (
    <div className="rounded-xl border border-zinc-700 overflow-hidden overflow-x-auto">
      <table className="w-full text-sm text-left min-w-[700px]">
        <thead className="bg-zinc-900/80 border-b border-zinc-700">
          <tr>
            {['IP / Intel', 'Flags', 'Source', 'Total Hits', 'Active Days', 'Last Seen', ''].map((h) => (
              <th key={h} className="px-3 py-2.5 text-[10px] font-semibold text-zinc-400 uppercase tracking-wide">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800">
          {rows.map((r) => <IpRow key={r.ip + (r.date || '')} row={r} source={source} />)}
        </tbody>
      </table>
    </div>
  );
}

// ─── Main tab ─────────────────────────────────────────────────────────────────

export default function FlaggedIpsTab({ toast }) {
  const [data, setData] = useState(null);
  const [torStats, setTorStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeSection, setActiveSection] = useState('repeat');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [flagRes, torRes] = await Promise.all([
        fetch(`${API_BASE}/admin/security/flagged`),
        fetch(`${API_BASE}/admin/security/tor-feed`),
      ]);
      const flagData = await flagRes.json();
      const torData = await torRes.json();
      if (!flagRes.ok) throw new Error(flagData.error || 'Failed');
      setData(flagData);
      if (torRes.ok) setTorStats(torData);
    } catch (e) {
      toast('error', 'Failed to load flagged IPs: ' + e.message);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  const repeatRows = data?.repeat_offenders || [];
  const abuseRows = data?.high_abuse || [];
  const torRows = data?.tor_hits || [];

  const allFlaggedIps = [...new Set([
    ...repeatRows.map((r) => r.ip),
    ...abuseRows.map((r) => r.ip),
    ...torRows.map((r) => r.ip),
  ])];

  const sections = [
    { id: 'repeat', label: `Repeat Offenders (${repeatRows.length})` },
    { id: 'abuse',  label: `High Abuse Score (${abuseRows.length})` },
    { id: 'tor',    label: `Tor Exit Nodes (${torRows.length})` },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-xl font-semibold text-zinc-100">Flagged IPs</h2>
          <p className="text-zinc-400 text-sm mt-0.5">
            {allFlaggedIps.length} unique IPs flagged across all sources. Observe-only — no automatic action.
          </p>
        </div>
        <button onClick={load} disabled={loading}
          className="px-4 py-2 rounded-lg bg-indigo-500 hover:bg-indigo-600 disabled:opacity-50 text-white text-sm font-medium transition-colors">
          {loading ? 'Loading…' : 'Refresh'}
        </button>
      </div>

      {/* Tor feed status */}
      {torStats && (
        <div className="rounded-xl border border-purple-500/30 bg-purple-500/5 px-4 py-3 flex items-center gap-4 text-xs flex-wrap">
          <span className="w-2 h-2 rounded-full bg-purple-400" />
          <span className="text-purple-300 font-semibold">Tor Exit Feed</span>
          <span className="text-zinc-400">{torStats.count?.toLocaleString()} known exit nodes cached</span>
          {torStats.last_fetch && <span className="text-zinc-500">Last refresh: {new Date(torStats.last_fetch).toLocaleTimeString()}</span>}
          <span className="text-zinc-600">Source: {torStats.source}</span>
        </div>
      )}

      {/* Blocklist export */}
      <div className="rounded-xl border border-zinc-700 bg-zinc-900/50 p-4 space-y-2">
        <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">Blocklist Export</div>
        <BlocklistExport ips={allFlaggedIps} />
      </div>

      {/* Section tabs */}
      <div className="flex gap-1 border-b border-zinc-700">
        {sections.map((s) => (
          <button key={s.id} onClick={() => setActiveSection(s.id)}
            className={`px-4 py-2 text-sm font-medium whitespace-nowrap transition-colors border-b-2 -mb-px ${
              activeSection === s.id
                ? 'border-indigo-500 text-indigo-300'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}>
            {s.label}
          </button>
        ))}
      </div>

      {loading && <div className="py-8 text-zinc-500 italic text-center text-sm">Loading…</div>}

      {!loading && activeSection === 'repeat' && (
        <div className="space-y-3">
          <p className="text-xs text-zinc-500">IPs seen on 5 or more distinct calendar days across monitored endpoint and data-room activity.</p>
          <IpTable rows={repeatRows} source="data room + monitored endpoints" emptyMsg="No repeat offenders yet." />
        </div>
      )}

      {!loading && activeSection === 'abuse' && (
        <div className="space-y-3">
          <p className="text-xs text-zinc-500">IPs with AbuseIPDB confidence score ≥ 50% from stored enrichment data.</p>
          <IpTable rows={abuseRows} source="monitored endpoints / data room" emptyMsg="No high-abuse IPs found. Configure AbuseIPDB API key in Integrations to enable scoring." />
        </div>
      )}

      {!loading && activeSection === 'tor' && (
        <div className="space-y-3">
          <p className="text-xs text-zinc-500">
            Known Tor exit nodes that have hit this site. Tor users may be legitimate privacy-conscious visitors —
            these are flagged for visibility only, not blocked.
          </p>
          <IpTable rows={torRows} source="all sources" emptyMsg="No Tor exit nodes detected yet." />
        </div>
      )}
    </div>
  );
}
