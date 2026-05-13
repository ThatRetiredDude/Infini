/**
 * Security Monitoring Hub
 *
 * Unified tabbed admin screen covering:
 *   - Overview (KPIs + sparklines)
 *   - Globe (3D traffic view + filtered spreadsheet)
 *   - MI Access Log (traffic + tokenless link follows)
 *   - Monitored Endpoints (internal-looking endpoint hits + IP enrichment)
 *   - Data Room Activity (procedural archive access + enrichment + self-ID)
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

import GlobeViewTab from './GlobeViewTab.jsx';
import MfaAdminTab from './MfaAdminTab.jsx';

import NetworkSensorsTab from './NetworkSensorsTab.jsx';

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'globe', label: 'Globe' },
  { id: 'ai-flags', label: 'AI Flags' },
  { id: 'mi-access', label: 'MI Access' },
  { id: 'honeypot',  label: 'Monitored Endpoints' },
  { id: 'network',   label: 'Network sensor' },
  { id: 'maze',      label: 'Data Room Activity' },
  { id: 'flagged',   label: 'Flagged IPs' },
  { id: 'alerts',    label: 'Alert Rules' },
  { id: 'mfa',       label: '2FA' },
];

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
            AI abuse detection, MI access, monitored endpoint activity, and alert rules.
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
      <div className="flex gap-1 border-b border-zinc-700 overflow-x-auto">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => selectTab(t.id)}
            className={`px-4 py-2.5 text-sm font-medium whitespace-nowrap transition-colors border-b-2 -mb-px ${
              activeTab === t.id
                ? 'border-indigo-500 text-indigo-300'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div>
        {activeTab === 'overview' && <Overview toast={toast} />}
        {activeTab === 'globe' && <GlobeViewTab toast={toast} />}
        {activeTab === 'ai-flags' && <AIFlagsTab toast={toast} readOnly={readOnly} />}
        {activeTab === 'mi-access' && <MIAccessTab toast={toast} readOnly={readOnly} />}
        {activeTab === 'honeypot'  && <MonitoredEndpointsTab toast={toast} readOnly={readOnly} />}
        {activeTab === 'network'   && <NetworkSensorsTab toast={toast} readOnly={readOnly} />}
        {activeTab === 'maze'      && <MazeTab toast={toast} readOnly={readOnly} />}
        {activeTab === 'flagged'   && <FlaggedIpsTab toast={toast} readOnly={readOnly} />}
        {activeTab === 'alerts'    && <AlertsTab toast={toast} />}
        {activeTab === 'mfa'       && <MfaAdminTab toast={toast} />}
      </div>
    </div>
  );
}
