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
