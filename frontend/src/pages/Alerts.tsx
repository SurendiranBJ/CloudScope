import { useState, useMemo, Fragment } from 'react';
import type { FC } from 'react';
import { Bell, AlertOctagon, Search, RefreshCw, ChevronDown, ChevronUp } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getSecurityAlerts } from '../api/alerts';
import { mockAlerts } from '../data/alerts';
import type { SecurityAlert } from '../types';

export const Alerts: FC = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);

  const { data } = useQuery({
    queryKey: ['securityAlerts'],
    queryFn: getSecurityAlerts,
    refetchInterval: 10000
  });

  const alerts = data || mockAlerts;

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

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      const matchesSearch =
        alert.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        alert.resource.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesSeverity = severityFilter === 'ALL' || alert.severity === severityFilter;

      return matchesSearch && matchesSeverity;
    });
  }, [alerts, searchQuery, severityFilter]);

  const toggleExpand = (id: string) => {
    setExpandedAlertId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto bg-enterprise-bg select-none">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Bell className="w-6 h-6 text-enterprise-warning" />
            <span>CloudTrail Threat Alerts</span>
          </h1>
          <p className="text-xs text-enterprise-subtext mt-1">
            Real-time security log alerts listing permission drifts and credential assumption events.
          </p>
        </div>
        <button className="flex items-center gap-1.5 px-3 py-1.5 bg-enterprise-card hover:bg-gray-800 text-white font-semibold rounded-lg text-xs transition-colors border border-enterprise-border">
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Clear Resolved</span>
        </button>
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
                            <span>{isExpanded ? 'Hide Payload' : 'Inspect JSON'}</span>
                            {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                          </button>
                        </td>
                      </tr>
                      {/* Expanded detail box */}
                      {isExpanded && (
                        <tr>
                          <td colSpan={6} className="bg-enterprise-bg/60 p-4 border-b border-enterprise-border">
                            <div className="space-y-2">
                              <h5 className="font-bold text-[10px] text-enterprise-accent flex items-center gap-1 uppercase">
                                <AlertOctagon className="w-4 h-4 text-enterprise-accent shrink-0" />
                                <span>CloudTrail Log Payload Parameters</span>
                              </h5>
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
                    No active threat logs detected matching criteria.
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
