import { useState, useMemo, Fragment } from 'react';
import type { FC } from 'react';
import { Bell, AlertOctagon, Search, RefreshCw, ChevronDown, ChevronUp, Check, Copy, Sparkles } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { explainSecurityAlert, getSecurityAlerts } from '../api/alerts';
import { ScannedRegionBadge } from '../components/ScannedRegionBadge';
import { LastScannedBadge } from '../components/LastScannedBadge';
import { useScanDataRefresh } from '../hooks/useScanDataRefresh';
import type { SecurityAlert } from '../types';
import type { CopilotMessage } from '../api/copilot';

const parseEventDetails = (details: string): Record<string, any> => {
  try {
    const value = JSON.parse(details);
    return value && typeof value === 'object' ? value : {};
  } catch {
    return {};
  }
};

export const Alerts: FC = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);
  // Client-side dismiss set — cleared on each new scan (component remounts via queryKey invalidation)
  const [dismissedIds, setDismissedIds] = useState<Set<string>>(new Set());
  const [copyAlertId, setCopyAlertId] = useState<string | null>(null);
  const [aiLoadingAlertId, setAiLoadingAlertId] = useState<string | null>(null);
  const [aiResults, setAiResults] = useState<Record<string, CopilotMessage>>({});
  const [aiErrors, setAiErrors] = useState<Record<string, string>>({});

  const { isScanning, hasCompletedSnapshot } = useScanDataRefresh();

  const { data } = useQuery({
    queryKey: ['securityAlerts'],
    queryFn: getSecurityAlerts,
    refetchInterval: 10000
  });

  const alerts = useMemo(() => data || [], [data]);

  const getSeverityBadge = (severity: SecurityAlert['severity']) => {
    switch (severity) {
      case 'critical':
        return 'bg-enterprise-critical/20 text-enterprise-critical border-enterprise-critical/30';
      case 'high':
        return 'bg-enterprise-warning/20 text-enterprise-warning border-enterprise-warning/30';
      case 'medium':
        return 'bg-enterprise-accent/20 text-enterprise-accent border-enterprise-accent/30';
      case 'low':
        return 'bg-gray-800 text-enterprise-subtext border-gray-700';
      default:
        return 'bg-gray-800 text-enterprise-subtext border-gray-700';
    }
  };

  const getStatusBadge = (status: SecurityAlert['status']) => {
    switch (status) {
      case 'open':
        return 'bg-enterprise-critical/10 text-enterprise-critical border-enterprise-critical/20';
      case 'resolved':
        return 'bg-enterprise-success/15 text-enterprise-success border-enterprise-success/20';
      case 'suppressed':
        return 'bg-gray-800 text-enterprise-subtext border-gray-700';
      default:
        return 'bg-gray-800 text-enterprise-subtext border-gray-700';
    }
  };

  // Count of currently-resolved alerts that can be dismissed
  const resolvedCount = useMemo(
    () => alerts.filter(a => a.status === 'resolved' && !dismissedIds.has(a.id)).length,
    [alerts, dismissedIds]
  );

  const handleClearResolved = () => {
    const resolvedIds = alerts
      .filter(a => a.status === 'resolved')
      .map(a => a.id);
    setDismissedIds(prev => new Set([...prev, ...resolvedIds]));
  };

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      if (dismissedIds.has(alert.id)) return false;

      const matchesSearch =
        alert.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        alert.resource.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesSeverity = severityFilter === 'ALL' || alert.severity === severityFilter;

      return matchesSearch && matchesSeverity;
    });
  }, [alerts, searchQuery, severityFilter, dismissedIds]);

  const toggleExpand = (id: string) => {
    setExpandedAlertId((prev) => (prev === id ? null : id));
  };

  const handleCopyDetails = (alert: SecurityAlert) => {
    navigator.clipboard.writeText(alert.details);
    setCopyAlertId(alert.id);
    setTimeout(() => setCopyAlertId(null), 2000);
  };

  const handleExplainAlert = async (alert: SecurityAlert) => {
    setAiLoadingAlertId(alert.id);
    setAiErrors((current) => ({ ...current, [alert.id]: '' }));
    try {
      const explanation = await explainSecurityAlert(alert.id);
      setAiResults((current) => ({ ...current, [alert.id]: explanation }));
    } catch (error: any) {
      setAiErrors((current) => ({
        ...current,
        [alert.id]: error?.response?.data?.detail || 'AI could not explain this alert. Check that the AI provider is configured and that your account has analyst access.',
      }));
    } finally {
      setAiLoadingAlertId(null);
    }
  };

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto bg-enterprise-bg select-none">
      {/* Header */}
      <div className="flex justify-between items-center flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Bell className="w-6 h-6 text-enterprise-warning" />
            <span>Recent CloudTrail Security Alerts</span>
          </h1>
          <div className="flex flex-wrap items-center gap-2 mt-1">
            <p className="text-xs text-enterprise-subtext">
              Security sensitive activity observed in the last 7 days. Routine read-only AWS service role checks are hidden; possible attack paths are listed separately under Attack Paths.
            </p>
            {isScanning && (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/25 text-blue-400 text-[11px] animate-pulse">
                <RefreshCw className="w-3 h-3 animate-spin text-blue-400" />
                Updating from latest AWS scan...
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 flex-wrap justify-end">
          <ScannedRegionBadge />
          <LastScannedBadge />
          <button
            onClick={handleClearResolved}
            disabled={resolvedCount === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-enterprise-card hover:bg-gray-800 disabled:opacity-40 disabled:cursor-not-allowed text-white font-semibold rounded-lg text-xs transition-colors border border-enterprise-border"
            title={resolvedCount === 0 ? 'No resolved alerts to clear' : `Hide ${resolvedCount} resolved alert${resolvedCount > 1 ? 's' : ''} from view`}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Clear Resolved{resolvedCount > 0 ? ` (${resolvedCount})` : ''}</span>
          </button>
        </div>
      </div>

      {/* Filter and Search controls */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-enterprise-card border border-enterprise-border p-4 rounded-xl">
        {/* Search */}
        <div className="relative">
          <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <Search className="h-4 w-4 text-enterprise-subtext" />
          </span>
          <input
            type="text"
            placeholder="Search alerts by name, target resource..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-enterprise-bg/60 border border-enterprise-border rounded-lg pl-10 pr-4 py-2 text-xs text-white placeholder-enterprise-subtext focus:outline-none focus:border-enterprise-accent transition-colors"
          />
        </div>

        {/* Severity Filter */}
        <div className="flex items-center gap-2">
          <span className="text-xs font-bold text-enterprise-subtext whitespace-nowrap">Filter Severity:</span>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full bg-enterprise-bg/60 border border-enterprise-border rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-enterprise-accent"
          >
            <option value="ALL" className="bg-enterprise-card">All Severities</option>
            <option value="critical" className="bg-enterprise-card text-enterprise-critical">Critical Findings Only</option>
            <option value="high" className="bg-enterprise-card text-enterprise-warning">High Severity Only</option>
            <option value="medium" className="bg-enterprise-card text-enterprise-accent">Medium Severity Only</option>
            <option value="low" className="bg-enterprise-card text-enterprise-success">Low Severity Only</option>
          </select>
        </div>
      </div>

      {/* Alerts Timeline Table */}
      <div className="bg-enterprise-card border border-enterprise-border rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-enterprise-bg/40 border-b border-enterprise-border text-xs font-bold text-enterprise-subtext">
                <th className="p-4">Timestamp</th>
                <th className="p-4">Target Resource</th>
                <th className="p-4">Finding Description</th>
                <th className="p-4">Severity</th>
                <th className="p-4">Status</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-enterprise-border text-xs text-gray-200">
              {filteredAlerts.length > 0 ? (
                filteredAlerts.map((alert) => {
                  const isExpanded = expandedAlertId === alert.id;
                  const event = parseEventDetails(alert.details);
                  const alertAi = aiResults[alert.id];
                  return (
                    <Fragment key={alert.id}>
                      <tr className="hover:bg-gray-800/10 transition-colors">
                        <td className="p-4 font-mono text-[10px] text-gray-400">
                          {alert.timestamp.replace('Z', '').split('T').join(' ')}
                        </td>
                        <td className="p-4 font-bold text-white max-w-[130px] truncate">{alert.resource}</td>
                        <td className="p-4 text-gray-300 font-medium max-w-[300px] whitespace-normal">
                          {alert.description}
                        </td>
                        <td className="p-4">
                          <span className={`px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${getSeverityBadge(alert.severity)}`}>
                            {alert.severity}
                          </span>
                        </td>
                        <td className="p-4">
                          <span className={`px-2 py-0.5 rounded-full border text-[10px] font-semibold ${getStatusBadge(alert.status)}`}>
                            {alert.status}
                          </span>
                        </td>
                        <td className="p-4 text-right">
                          <button
                            onClick={() => toggleExpand(alert.id)}
                            className="flex items-center gap-1 ml-auto px-2.5 py-1.5 hover:bg-gray-800 text-enterprise-accent font-semibold rounded transition-colors text-[10px]"
                          >
                            <span>{isExpanded ? 'Hide Details' : 'Details & AI'}</span>
                            {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                          </button>
                        </td>
                      </tr>
                      {/* Expanded detail box */}
                      {isExpanded && (
                        <tr>
                          <td colSpan={6} className="bg-enterprise-bg/60 p-4 border-b border-enterprise-border">
                            <div className="space-y-4">
                              <section className="rounded-xl border border-enterprise-border bg-enterprise-card p-4 space-y-3">
                                <div className="flex flex-wrap items-center justify-between gap-3">
                                  <div>
                                    <h5 className="text-sm font-bold text-white">Event impact overview</h5>
                                    <p className="mt-1 text-[11px] text-enterprise-subtext">CloudTrail records the request and outcome. The previous configuration is shown only when historical evidence is available.</p>
                                  </div>
                                  <button
                                    onClick={() => void handleExplainAlert(alert)}
                                    disabled={aiLoadingAlertId === alert.id}
                                    className="inline-flex items-center gap-2 rounded-lg bg-enterprise-accent px-3 py-2 text-xs font-semibold text-white disabled:cursor-wait disabled:opacity-60"
                                  >
                                    <Sparkles className="h-4 w-4" />
                                    {aiLoadingAlertId === alert.id ? 'Analyzing evidence…' : alertAi ? 'Explain again with AI' : 'Explain with AI'}
                                  </button>
                                </div>
                                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 text-xs">
                                  <div className="rounded-lg bg-enterprise-bg p-3"><span className="text-enterprise-subtext">AWS action</span><p className="mt-1 font-semibold text-white">{event.eventName || 'Unavailable'}</p></div>
                                  <div className="rounded-lg bg-enterprise-bg p-3"><span className="text-enterprise-subtext">Actor</span><p className="mt-1 break-all font-semibold text-white">{event.userIdentity?.arn || event.userIdentity?.principalId || event.userIdentity?.userName || 'Not identified in event'}</p></div>
                                  <div className="rounded-lg bg-enterprise-bg p-3"><span className="text-enterprise-subtext">Region / source</span><p className="mt-1 font-semibold text-white">{event.awsRegion || 'Unknown'} · {event.sourceIPAddress || 'Source IP unavailable'}</p></div>
                                  <div className="rounded-lg bg-enterprise-bg p-3"><span className="text-enterprise-subtext">Recorded result</span><p className={`mt-1 font-semibold ${event.errorCode ? 'text-enterprise-critical' : 'text-enterprise-success'}`}>{event.errorCode ? `Failed: ${event.errorCode}` : 'No API error recorded'}</p></div>
                                </div>
                                <div className="grid gap-3 lg:grid-cols-2 text-xs">
                                  <div className="rounded-lg border border-enterprise-border p-3"><h6 className="font-semibold text-white">Requested change</h6><pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all text-[10px] text-enterprise-subtext">{JSON.stringify(event.requestParameters ?? 'Not included in the event', null, 2)}</pre></div>
                                  <div className="rounded-lg border border-enterprise-border p-3"><h6 className="font-semibold text-white">AWS response</h6><pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all text-[10px] text-enterprise-subtext">{JSON.stringify(event.responseElements ?? 'No response details included; this does not by itself prove what downstream access occurred.', null, 2)}</pre></div>
                                </div>
                                <div className="text-[11px] text-enterprise-subtext">Prior state: CloudTrail event history does not normally contain a before-image. Compare with the prior CloudScope snapshot or AWS Config history to confirm what changed.</div>
                              </section>

                              {aiErrors[alert.id] && <div role="alert" className="rounded-lg border border-enterprise-critical/30 bg-enterprise-critical/10 p-3 text-xs text-enterprise-critical">{aiErrors[alert.id]}</div>}
                              {alertAi && (
                                <section className="rounded-xl border border-enterprise-accent/30 bg-enterprise-accent/5 p-4 space-y-3">
                                  <div className="flex items-center gap-2"><Sparkles className="h-4 w-4 text-enterprise-accent" /><h5 className="text-sm font-bold text-white">AI administrator briefing</h5></div>
                                  <p className="text-xs font-semibold text-white">{alertAi.summary || 'Alert analysis'}</p>
                                  <p className="whitespace-pre-wrap text-xs leading-relaxed text-gray-200">{alertAi.analysis || alertAi.text}</p>
                                  {alertAi.affectedEntities?.length ? <div><h6 className="mb-1 text-[11px] font-semibold text-white">Potentially affected resources</h6><ul className="list-disc space-y-1 pl-5 text-xs text-gray-300">{alertAi.affectedEntities.map((entity, index) => <li key={`${entity}-${index}`}>{entity}</li>)}</ul></div> : null}
                                  {alertAi.evidence?.length ? <div><h6 className="mb-1 text-[11px] font-semibold text-white">Evidence considered</h6><ul className="list-disc space-y-1 pl-5 text-xs text-gray-300">{alertAi.evidence.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul></div> : null}
                                  {alertAi.recommendations?.length ? <div><h6 className="mb-1 text-[11px] font-semibold text-white">Recommended next steps</h6><ol className="list-decimal space-y-1 pl-5 text-xs text-gray-300">{alertAi.recommendations.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ol></div> : null}
                                  {alertAi.limitations?.length ? <div className="rounded-lg bg-enterprise-bg p-3 text-[11px] text-enterprise-subtext"><strong className="text-white">Evidence limits: </strong>{alertAi.limitations.join(' ')}</div> : null}
                                  <p className="text-[10px] text-enterprise-subtext">AI analysis is advisory. Verify resource state and event history in AWS before taking action.{alertAi.model ? ` Model: ${alertAi.model}.` : ''}</p>
                                </section>
                              )}

                              <div className="flex items-center justify-between">
                                <h5 className="font-bold text-[10px] text-enterprise-accent flex items-center gap-1 uppercase">
                                  <AlertOctagon className="w-4 h-4 text-enterprise-accent shrink-0" />
                                  <span>Sanitized CloudTrail event payload</span>
                                </h5>
                                <button
                                  onClick={() => handleCopyDetails(alert)}
                                  className="flex items-center gap-1 px-2 py-1 hover:bg-gray-800 text-enterprise-subtext hover:text-white rounded text-[10px] transition-colors"
                                >
                                  {copyAlertId === alert.id
                                    ? <Check className="w-3.5 h-3.5 text-enterprise-success" />
                                    : <Copy className="w-3.5 h-3.5" />}
                                  <span>{copyAlertId === alert.id ? 'Copied' : 'Copy'}</span>
                                </button>
                              </div>
                              <pre className="p-4 bg-gray-900 border border-enterprise-border rounded-lg text-[9px] font-mono text-gray-300 overflow-x-auto whitespace-pre-wrap leading-relaxed select-text">
                                {alert.details}
                              </pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={6} className="text-center p-8 text-enterprise-subtext font-medium text-xs">
                    {isScanning && !hasCompletedSnapshot ? (
                      <div className="flex flex-col items-center justify-center gap-2">
                        <RefreshCw className="w-6 h-6 text-enterprise-accent animate-spin" />
                        <span className="text-white font-medium">Initial AWS scan is running...</span>
                        <span>Correlating CloudTrail threat events. This will populate automatically.</span>
                      </div>
                    ) : isScanning && hasCompletedSnapshot ? (
                      <div className="flex flex-col items-center justify-center gap-2">
                        <RefreshCw className="w-6 h-6 text-blue-400 animate-spin" />
                        <span className="text-white font-medium">Updating from latest AWS scan...</span>
                        <span>Preserving current alert logs until scan completes.</span>
                      </div>
                    ) : (
                      'No active threat logs detected matching criteria.'
                    )}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
