import { apiClient, type APIResponse } from './client';

export interface LockInfo {
  locked: boolean;
  owner_instance_id: string | null;
  acquired_at: string | null;
  ttl_seconds: number;
  stale: boolean;
}

export interface ScannerInfo {
  is_scanning: boolean;
  active_phase: string;
  mode: string;
  current_scan_id: string | null;
  current_snapshot_id: string | null;
  progress: number;
  resolved_regions: string[];
}

export interface DependencyStatus {
  neo4j: boolean;
  redis: boolean;
  database: boolean;
}

export interface MetricsSummary {
  last_scan_duration_seconds: number | null;
  last_scan_status: string | null;
  historical_failed_regions: string[];
  recent_collector_failure_count: number;
}

export interface ScanRunItem {
  scan_id: string;
  snapshot_id: string | null;
  status: string;
  started_at: string;
  completed_at: string | null;
  duration_seconds: number | null;
  scan_mode: string;
  resolved_regions: string[];
  successful_regions: string[];
  failed_regions: string[];
  active_phase: string;
  total_collectors: number;
  completed_collectors: number;
  error_summary: string | null;
  created_by: string;
  trigger_type: string;
}

export interface AuditEventItem {
  id: string;
  event_time: string;
  actor_id: string;
  actor_role: string;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  scan_id: string | null;
  snapshot_id: string | null;
  result: string;
  error_code: string | null;
  ip_address: string | null;
  metadata: Record<string, any>;
}

export interface OperationsOverview {
  timestamp: string;
  commit_hash: string;
  build_version: string;
  app_version: string;
  uptime_seconds: number;
  scanner: ScannerInfo;
  distributed_lock: LockInfo;
  dependencies: DependencyStatus;
  metrics_summary: MetricsSummary;
  recent_scans: ScanRunItem[];
  latest_snapshot: any;
  recent_audit_events: AuditEventItem[];
  system_status: 'HEALTHY' | 'DEGRADED';
  database_status: 'HEALTHY' | 'ERROR';
  database_error: string | null;
}

export interface AuditQueryFilters {
  actor_id?: string;
  action?: string;
  resource_type?: string;
  resource_id?: string;
  scan_id?: string;
  limit?: number;
  offset?: number;
}

export interface AuditQueryResult {
  events: AuditEventItem[];
  count: number;
  limit: number;
  offset: number;
}

export const getOperationsOverview = async (): Promise<OperationsOverview> => {
  const response = await apiClient.get<APIResponse<OperationsOverview>>('/operations/overview');
  const data = response.data.data;
  if (!data || typeof data !== 'object') {
    throw new Error('Operations API returned an empty or invalid payload');
  }
  if (!data.scanner || typeof data.scanner.is_scanning !== 'boolean') {
    throw new Error('Malformed Operations response: missing valid scanner state');
  }
  if (!data.distributed_lock || typeof data.distributed_lock.locked !== 'boolean') {
    throw new Error('Malformed Operations response: missing valid distributed lock state');
  }
  if (!data.dependencies || typeof data.dependencies.database !== 'boolean') {
    throw new Error('Malformed Operations response: missing valid dependencies status');
  }
  if (!Array.isArray(data.recent_scans)) {
    throw new Error('Malformed Operations response: recent_scans must be an array');
  }
  return data;
};

export const getAuditLogs = async (filters: AuditQueryFilters = {}): Promise<AuditQueryResult> => {
  const params = new URLSearchParams();
  if (filters.actor_id) params.set('actor_id', filters.actor_id);
  if (filters.action) params.set('action', filters.action);
  if (filters.resource_type) params.set('resource_type', filters.resource_type);
  if (filters.resource_id) params.set('resource_id', filters.resource_id);
  if (filters.scan_id) params.set('scan_id', filters.scan_id);
  if (filters.limit) params.set('limit', filters.limit.toString());
  if (filters.offset) params.set('offset', filters.offset.toString());

  const response = await apiClient.get<APIResponse<any>>(`/audit?${params.toString()}`);
  const resData = response.data?.data || {};
  const rawEvents = Array.isArray(resData.events) ? resData.events : [];

  const normalizedEvents: AuditEventItem[] = rawEvents.map((ev: any, idx: number) => ({
    id: ev.id || ev.event_id || `audit-event-${idx}`,
    event_time: ev.event_time || ev.timestamp || new Date().toISOString(),
    actor_id: ev.actor_id || 'system',
    actor_role: ev.actor_role || 'SYSTEM',
    action: ev.action || 'UNKNOWN',
    resource_type: ev.resource_type || null,
    resource_id: ev.resource_id || null,
    scan_id: ev.scan_id || null,
    snapshot_id: ev.snapshot_id || null,
    result: ev.result || 'SUCCESS',
    error_code: ev.error_code || null,
    ip_address: ev.ip_address || null,
    metadata: ev.metadata || {},
  }));

  return {
    events: normalizedEvents,
    count: typeof resData.count === 'number' ? resData.count : normalizedEvents.length,
    limit: typeof resData.limit === 'number' ? resData.limit : (filters.limit || 50),
    offset: typeof resData.offset === 'number' ? resData.offset : (filters.offset || 0),
  };
};

export const triggerScan = async (params: { mode?: string; region?: string } = {}) => {
  const response = await apiClient.post<APIResponse<any>>('/scan', params);
  return response.data.data;
};
