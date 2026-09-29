import { apiClient, type APIResponse } from './client';

export interface LockInfo {
  locked: boolean;
  owner_instance_id: string | null;
  acquired_at: string | null;
  ttl_seconds: number | null;
  stale: boolean;
}

export interface ScannerInfo {
  is_scanning: boolean;
  active_phase: string;
  mode: string;
  current_scan_id: string | null;
  progress: number;
}

export interface DependencyStatus {
  neo4j: boolean;
  redis: boolean;
  database: boolean;
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
  recent_scans: ScanRunItem[];
  latest_snapshot: any;
  recent_audit_events: AuditEventItem[];
  system_status: 'HEALTHY' | 'DEGRADED';
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
  return response.data.data;
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

  const response = await apiClient.get<APIResponse<AuditQueryResult>>(`/audit?${params.toString()}`);
  return response.data.data;
};

export const triggerScan = async (params: { mode?: string; region?: string } = {}) => {
  const response = await apiClient.post<APIResponse<any>>('/scan', params);
  return response.data.data;
};
