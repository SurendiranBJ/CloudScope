import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Activity,
  Lock,
  Unlock,
  Database,
  Server,
  Clock,
  RotateCw,
  Play,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Filter,
  Eye,
} from 'lucide-react';
import {
  getOperationsOverview,
  getAuditLogs,
  triggerScan,
  type AuditQueryFilters,
  type ScanRunItem,
  type AuditEventItem,
} from '../api/operations';

export const Operations: React.FC = () => {
  const queryClient = useQueryClient();
  const [auditFilters, setAuditFilters] = useState<AuditQueryFilters>({ limit: 25 });
  const [selectedAuditMetadata, setSelectedAuditMetadata] = useState<Record<string, any> | null>(null);
  const [triggerError, setTriggerError] = useState<string | null>(null);

  const {
    data: overview,
    refetch: refetchOverview,
  } = useQuery({
    queryKey: ['operations-overview'],
    queryFn: getOperationsOverview,
    refetchInterval: 10000,
  });

  const {
    data: auditData,
    isLoading: auditLoading,
    refetch: refetchAudit,
  } = useQuery({
    queryKey: ['operations-audit', auditFilters],
    queryFn: () => getAuditLogs(auditFilters),
    refetchInterval: 15000,
  });

  const scanMutation = useMutation({
    mutationFn: () => triggerScan({ mode: 'global' }),
    onSuccess: () => {
      setTriggerError(null);
      queryClient.invalidateQueries({ queryKey: ['operations-overview'] });
      queryClient.invalidateQueries({ queryKey: ['operations-audit'] });
    },
    onError: (err: any) => {
      const msg = err.response?.data?.error?.message || err.response?.data?.detail || err.message;
      setTriggerError(msg);
    },
  });

  const formatUptime = (totalSeconds: number) => {
    if (!totalSeconds && totalSeconds !== 0) return '0s';
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = Math.floor(totalSeconds % 60);
    return `${hours}h ${minutes}m ${seconds}s`;
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'SUCCESS':
      case 'COMPLETED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3" />
            SUCCESS
          </span>
        );
      case 'PARTIAL':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3" />
            PARTIAL
          </span>
        );
      case 'RUNNING':
      case 'SCANNING':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-blue-500/15 text-blue-400 border border-blue-500/30">
            <RotateCw className="w-3 h-3 animate-spin" />
            SCANNING
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-500/15 text-rose-400 border border-rose-500/30">
            <XCircle className="w-3 h-3" />
            {status}
          </span>
        );
    }
  };

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-enterprise-bg text-gray-200">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-enterprise-border pb-4">
        <div>
          <div className="flex items-center gap-3">
            <Activity className="w-7 h-7 text-enterprise-accent" />
            <h1 className="text-2xl font-bold text-white">Operations & Reliability Center</h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
              ADMINISTRATOR ONLY
            </span>
          </div>
          <p className="text-xs text-enterprise-subtext mt-1">
            Real-time scanner locking, multi-instance health, durable execution history, and audit log inspection.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              refetchOverview();
              refetchAudit();
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-enterprise-card hover:bg-gray-800 border border-enterprise-border rounded-lg text-xs text-gray-300 hover:text-white transition-colors"
          >
            <RotateCw className="w-3.5 h-3.5" />
            Refresh
          </button>
          <button
            onClick={() => scanMutation.mutate()}
            disabled={scanMutation.isPending || overview?.scanner?.is_scanning}
            className="flex items-center gap-1.5 px-4 py-1.5 bg-enterprise-accent hover:bg-blue-600 disabled:opacity-50 text-white rounded-lg text-xs font-semibold shadow-md transition-colors"
          >
            <Play className="w-3.5 h-3.5" />
            {scanMutation.isPending ? 'Starting...' : 'Trigger Scan'}
          </button>
        </div>
      </div>

      {triggerError && (
        <div className="p-3 bg-rose-950/80 border border-rose-600/50 rounded-xl text-rose-200 text-xs flex justify-between items-center">
          <span>Failed to trigger scan: {triggerError}</span>
          <button onClick={() => setTriggerError(null)} className="text-rose-400 hover:text-white">
            Dismiss
          </button>
        </div>
      )}

      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Distributed Scan Lock */}
        <div className="bg-enterprise-card border border-enterprise-border rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs text-enterprise-subtext mb-2">
            <span>Distributed Lock</span>
            {overview?.distributed_lock?.locked ? (
              <Lock className="w-4 h-4 text-amber-400" />
            ) : (
              <Unlock className="w-4 h-4 text-emerald-400" />
            )}
          </div>
          <div className="text-xl font-bold text-white flex items-center gap-2">
            {overview?.distributed_lock?.locked ? (
              <span className="text-amber-400">LOCKED</span>
            ) : (
              <span className="text-emerald-400">AVAILABLE</span>
            )}
          </div>
          <div className="text-[11px] text-enterprise-subtext mt-2 space-y-0.5 font-mono">
            <div className="truncate">Owner: {overview?.distributed_lock?.owner_instance_id || 'None'}</div>
            <div>TTL: {overview?.distributed_lock?.ttl_seconds ?? 0}s remaining</div>
          </div>
        </div>

        {/* System & Scanner Phase */}
        <div className="bg-enterprise-card border border-enterprise-border rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs text-enterprise-subtext mb-2">
            <span>Scanner Engine</span>
            <Activity className="w-4 h-4 text-enterprise-accent" />
          </div>
          <div className="text-xl font-bold text-white">
            {overview?.scanner?.is_scanning ? (
              <span className="text-blue-400">SCANNING</span>
            ) : (
              <span className="text-gray-300">IDLE</span>
            )}
          </div>
          <div className="text-[11px] text-enterprise-subtext mt-2 font-mono">
            <div>Phase: {overview?.scanner?.active_phase || 'READY'}</div>
            <div>Mode: {overview?.scanner?.mode || 'single'}</div>
          </div>
        </div>

        {/* Core Dependencies */}
        <div className="bg-enterprise-card border border-enterprise-border rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs text-enterprise-subtext mb-2">
            <span>Service Dependencies</span>
            <Database className="w-4 h-4 text-purple-400" />
          </div>
          <div className="space-y-1 mt-1 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Neo4j Graph:</span>
              {overview?.dependencies?.neo4j ? (
                <span className="text-emerald-400 font-semibold">UP</span>
              ) : (
                <span className="text-rose-400 font-semibold">DOWN</span>
              )}
            </div>
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Redis Cache/Lock:</span>
              {overview?.dependencies?.redis ? (
                <span className="text-emerald-400 font-semibold">UP</span>
              ) : (
                <span className="text-amber-400 font-semibold">MEMORY FALLBACK</span>
              )}
            </div>
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Durable Relational DB:</span>
              {overview?.dependencies?.database ? (
                <span className="text-emerald-400 font-semibold">UP</span>
              ) : (
                <span className="text-rose-400 font-semibold">DOWN</span>
              )}
            </div>
          </div>
        </div>

        {/* Build & Version Marker */}
        <div className="bg-enterprise-card border border-enterprise-border rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs text-enterprise-subtext mb-2">
            <span>Process & Version</span>
            <Server className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-sm font-mono font-semibold text-white">
            Commit: <span className="text-enterprise-accent">{overview?.commit_hash?.slice(0, 8) || 'unknown'}</span>
          </div>
          <div className="text-[11px] text-enterprise-subtext mt-2 font-mono">
            <div>Uptime: {formatUptime(overview?.uptime_seconds ?? 0)}</div>
            <div>Version: {overview?.app_version || '2.0.0'}</div>
          </div>
        </div>
      </div>

      {/* Durable Scan Runs Table */}
      <div className="bg-enterprise-card border border-enterprise-border rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-5 h-5 text-enterprise-accent" />
            <h2 className="text-base font-bold text-white">Durable Scan History (Last 10 Runs)</h2>
          </div>
          <span className="text-xs text-enterprise-subtext">Persisted in relational store across restarts</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-enterprise-border text-enterprise-subtext uppercase text-[10px] tracking-wider">
                <th className="py-2.5 px-3">Scan ID</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Mode</th>
                <th className="py-2.5 px-3">Duration</th>
                <th className="py-2.5 px-3">Regions</th>
                <th className="py-2.5 px-3">Triggered By</th>
                <th className="py-2.5 px-3">Snapshot ID</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-enterprise-border/50">
              {overview?.recent_scans && overview.recent_scans.length > 0 ? (
                overview.recent_scans.map((scan: ScanRunItem) => (
                  <tr key={scan.scan_id} className="hover:bg-gray-800/20 font-mono">
                    <td className="py-2.5 px-3 text-white truncate max-w-[140px]" title={scan.scan_id}>
                      {scan.scan_id}
                    </td>
                    <td className="py-2.5 px-3">{getStatusBadge(scan.status)}</td>
                    <td className="py-2.5 px-3 uppercase text-gray-300">{scan.scan_mode}</td>
                    <td className="py-2.5 px-3 text-gray-300">
                      {scan.duration_seconds ? `${scan.duration_seconds.toFixed(1)}s` : '—'}
                    </td>
                    <td className="py-2.5 px-3 text-gray-300">
                      {scan.successful_regions?.length || 0} ok
                      {scan.failed_regions?.length ? ` (${scan.failed_regions.length} fail)` : ''}
                    </td>
                    <td className="py-2.5 px-3 text-gray-400">{scan.created_by || 'system'}</td>
                    <td className="py-2.5 px-3 text-blue-400 truncate max-w-[120px]" title={scan.snapshot_id || ''}>
                      {scan.snapshot_id ? scan.snapshot_id.slice(0, 10) + '...' : '—'}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-4 text-center text-enterprise-subtext">
                    No scan runs recorded yet in durable repository.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Administrative Audit Trail */}
      <div className="bg-enterprise-card border border-enterprise-border rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <h2 className="text-base font-bold text-white">Administrative Audit Trail</h2>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <Filter className="w-3.5 h-3.5 text-enterprise-subtext" />
            <input
              type="text"
              placeholder="Filter by Actor..."
              className="bg-enterprise-bg/60 border border-enterprise-border rounded px-2.5 py-1 text-xs text-white placeholder-enterprise-subtext focus:outline-none focus:border-enterprise-accent"
              value={auditFilters.actor_id || ''}
              onChange={(e) => setAuditFilters((prev) => ({ ...prev, actor_id: e.target.value || undefined }))}
            />
            <input
              type="text"
              placeholder="Filter by Action..."
              className="bg-enterprise-bg/60 border border-enterprise-border rounded px-2.5 py-1 text-xs text-white placeholder-enterprise-subtext focus:outline-none focus:border-enterprise-accent"
              value={auditFilters.action || ''}
              onChange={(e) => setAuditFilters((prev) => ({ ...prev, action: e.target.value || undefined }))}
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-enterprise-border text-enterprise-subtext uppercase text-[10px] tracking-wider">
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Actor</th>
                <th className="py-2.5 px-3">Role</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Resource</th>
                <th className="py-2.5 px-3">Result</th>
                <th className="py-2.5 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-enterprise-border/50">
              {auditData?.events && auditData.events.length > 0 ? (
                auditData.events.map((evt: AuditEventItem) => (
                  <tr key={evt.id} className="hover:bg-gray-800/20 font-mono">
                    <td className="py-2.5 px-3 text-enterprise-subtext whitespace-nowrap">
                      {new Date(evt.event_time).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3 text-white font-medium">{evt.actor_id}</td>
                    <td className="py-2.5 px-3 text-purple-400">{evt.actor_role}</td>
                    <td className="py-2.5 px-3 text-blue-300 font-semibold">{evt.action}</td>
                    <td className="py-2.5 px-3 text-gray-400">
                      {evt.resource_type ? `${evt.resource_type}: ${evt.resource_id || ''}` : '—'}
                    </td>
                    <td className="py-2.5 px-3">
                      {evt.result === 'SUCCESS' ? (
                        <span className="text-emerald-400 font-semibold">SUCCESS</span>
                      ) : (
                        <span className="text-rose-400 font-semibold">{evt.result}</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => setSelectedAuditMetadata(evt.metadata)}
                        className="p-1 hover:bg-gray-700/50 rounded text-enterprise-accent hover:text-white inline-flex items-center gap-1"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span className="text-[11px]">Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-4 text-center text-enterprise-subtext">
                    {auditLoading ? 'Loading audit trail...' : 'No audit events found.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Metadata Inspector Modal */}
      {selectedAuditMetadata && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-enterprise-card border border-enterprise-border rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-enterprise-border pb-3">
              <h3 className="text-sm font-bold text-white">Sanitized Event Metadata</h3>
              <button
                onClick={() => setSelectedAuditMetadata(null)}
                className="text-enterprise-subtext hover:text-white text-xs px-2 py-1 rounded bg-gray-800"
              >
                Close
              </button>
            </div>
            <pre className="bg-enterprise-bg/80 border border-enterprise-border rounded-lg p-3 text-xs font-mono text-emerald-400 overflow-x-auto max-h-60">
              {JSON.stringify(selectedAuditMetadata, null, 2)}
            </pre>
            <p className="text-[11px] text-enterprise-subtext">
              * AWS credentials, session tokens, and API keys are automatically sanitized prior to durable persistence.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
