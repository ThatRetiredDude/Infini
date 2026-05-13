/**
 * Security Monitoring Hub
 *
 * Unified tabbed admin screen covering:
 *   - Overview (KPIs + sparklines)
 *   - Globe (3D traffic view + filtered spreadsheet)
 *   - Access Trail (traffic + tokenless link follows)
 *   - HTTP Decoys (internal-looking endpoint hits + IP enrichment)
 *   - Fake Data Access (procedural archive access + enrichment + self-ID)
 *   - Alert Rules
 */

import { useState, useCallback, useEffect } from 'react';
import Overview from './Overview.jsx';
import AIFlagsTab from './AIFlagsTab.jsx';
import MIAccessTab from './MIAccessTab.jsx';
import MonitoredEndpointsTab from './MonitoredEndpointsTab.jsx';
import MazeTab from './MazeTab.jsx';
import FlaggedIpsTab from './FlaggedIpsTab.jsx';
import AlertsTab from './AlertsTab.jsx';
import EventLogTable from './EventLogTable.jsx';

import GlobeViewTab from './GlobeViewTab.jsx';

import NetworkSensorsTab from './NetworkSensorsTab.jsx';

const TABS = [
  { id: 'overview', label: 'Overview', group: 'Overview' },
  { id: 'honeypot', label: 'HTTP Decoys', group: 'Decoys' },
  { id: 'maze', label: 'Fake Data Access', group: 'Decoys' },
  { id: 'network', label: 'SSH / Telnet Decoys', group: 'Decoys' },
  { id: 'mi-access', label: 'Access Trail', group: 'Investigation' },
  { id: 'requests', label: 'All Requests', group: 'Investigation' },
  { id: 'globe', label: 'Globe', group: 'Investigation' },
  { id: 'flagged', label: 'Flagged IPs', group: 'Investigation' },
  { id: 'ai-flags', label: 'Abuse Logs', group: 'Investigation' },
  { id: 'alerts', label: 'Alert Rules', group: 'Response' },
];

const GROUPS = ['Overview', 'Decoys', 'Investigation', 'Response'];

export default function SecurityHub({ onNavigate, onToast, initialTab, readOnly = false }) {
  const validInitial =
    initialTab && TABS.some((t) => t.id === initialTab) ? initialTab : 'overview';
  const [activeTab, setActiveTab] = useState(validInitial);

  useEffect(() => {
    if (!initialTab) {
      setActiveTab('overview');
      return;
    }
    if (TABS.some((t) => t.id === initialTab)) setActiveTab(initialTab);
  }, [initialTab]);

  const selectTab = useCallback(
    (id) => {
      setActiveTab(id);
      if (id === 'overview') onNavigate('/admin/security');
      else onNavigate(`/admin/security/${id}`);
    },
    [onNavigate],
  );

  const toast = useCallback((type, text) => {
    if (typeof onToast === 'function') onToast({ type, text });
  }, [onToast]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-3xl font-bold text-zinc-100">Security Monitoring</h1>
          <p className="text-zinc-400 mt-1 text-sm">
            Decoy activity, suspicious requests, attacker infrastructure, and response rules.
          </p>
        </div>
        {!readOnly && (
          <button
            onClick={() => onNavigate('/admin')}
            className="px-5 py-2 rounded-lg border border-zinc-700 hover:border-zinc-500 text-zinc-400 hover:text-zinc-200 text-sm transition-colors"
          >
            Back to Dashboard
          </button>
        )}
      </div>

      {/* Tab nav */}
      <div className="space-y-3 rounded-xl border border-zinc-800 bg-zinc-950/30 p-3">
        {GROUPS.map((group) => (
          <div key={group} className="flex flex-wrap items-center gap-2">
            <div className="w-28 shrink-0 text-[10px] uppercase tracking-widest text-zinc-600">
              {group}
            </div>
            <div className="flex flex-wrap gap-1">
              {TABS.filter((t) => t.group === group).map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => selectTab(t.id)}
                  className={`px-3 py-1.5 text-sm font-medium rounded-lg border transition-colors ${
                    activeTab === t.id
                      ? 'border-indigo-500/60 bg-indigo-500/15 text-indigo-200'
                      : 'border-zinc-800 text-zinc-400 hover:border-zinc-600 hover:text-zinc-200'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Tab content */}
      <div>
        {activeTab === 'overview' && <Overview toast={toast} />}
        {activeTab === 'globe' && <GlobeViewTab toast={toast} />}
        {activeTab === 'ai-flags' && <AIFlagsTab toast={toast} readOnly={readOnly} />}
        {activeTab === 'mi-access' && <MIAccessTab toast={toast} readOnly={readOnly} />}
        {activeTab === 'requests' && <EventLogTable toast={toast} mode="requests" />}
        {activeTab === 'honeypot'  && <MonitoredEndpointsTab toast={toast} readOnly={readOnly} />}
        {activeTab === 'network'   && <NetworkSensorsTab toast={toast} readOnly={readOnly} />}
        {activeTab === 'maze'      && <MazeTab toast={toast} readOnly={readOnly} />}
        {activeTab === 'flagged'   && <FlaggedIpsTab toast={toast} readOnly={readOnly} />}
        {activeTab === 'alerts'    && <AlertsTab toast={toast} readOnly={readOnly} />}
      </div>
    </div>
  );
}
