import { apiClient } from './client';
import type { APIResponse } from './client';

export interface CytoscapeElement {
  data: {
    id: string;
    label?: string;
    type?: string;
    source?: string;
    target?: string;
    riskScore?: number;
    arn?: string;
    description?: string;
    policyType?: string;
    edge_type?: string;
    access_category?: string;
    action?: string;
    actions?: string[];
    policy_name?: string;
    policy_names?: string[];
    policy_arn?: string;
    statement_sid?: string;
    effect?: string;
    decision?: string;
    region?: string;
    why?: string;
    evidence?: any;
    isActivity?: boolean;
    trustPolicy?: string;
    policies?: string[];
    diffStatus?: 'added' | 'removed';
  };
  classes?: string;
}

export interface EffectiveAccessRecord {
  identity_id: string;
  identity_name: string;
  identity_type: 'User' | 'Role' | 'Group';
  target_resource_id: string;
  target_resource_name: string;
  target_resource_type: string;
  access_path: string[];
  through_relationship: string[];
  policy_names: string[];
  policy_arns: string[];
  evidence?: {
    principal?: string;
    principal_type?: string;
    policy_arn?: string;
    policy_name?: string;
    statement_sid?: string;
    effect?: string;
    action?: string | string[];
    resource?: string | string[];
    matched_action?: string;
    matched_resource?: string;
    condition_status?: string;
    decision?: string;
    region?: string;
    resource_arn?: string;
    reason?: string;
  };
}

export interface ScanStatus {
  is_scanning: boolean;
  scan_id?: string | null;
  scan_status?: 'IDLE' | 'SCANNING' | 'SUCCESS' | 'FAILED' | 'PARTIAL';
  started_at: string | null;
  last_successful_scan_at?: string | null;
  last_successful_scan_id?: string | null;
  last_error?: string | null;
  last_result: {
    status: string;
    scan_id?: string;
    scan_status?: string;
    timestamp?: string;
    last_successful_scan_at?: string;
    duration_seconds?: number;
    resources?: number;
    risks?: number;
    error?: string;
  } | null;
  service_status?: Record<string, string>;
  failed_regions?: string[];
}

export const getGraphElements = async (): Promise<CytoscapeElement[]> => {
  const res = await apiClient.get<APIResponse<CytoscapeElement[]>>('/graph');
  return res.data.data;
};

export const rebuildGraph = async (): Promise<any> => {
  const res = await apiClient.post<APIResponse<any>>('/graph/rebuild');
  return res.data.data;
};

export const getScanStatus = async (): Promise<ScanStatus> => {
  const res = await apiClient.get<APIResponse<ScanStatus>>('/scan/status');
  return res.data.data;
};

export const getEffectiveAccess = async (): Promise<EffectiveAccessRecord[]> => {
  const res = await apiClient.get<APIResponse<EffectiveAccessRecord[]>>('/graph/effective-access');
  return res.data.data;
};

