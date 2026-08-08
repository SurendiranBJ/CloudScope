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
  started_at: string | null;
  last_result: {
    status: string;
    timestamp?: string;
    duration?: number;
    resources?: number;
    risks?: number;
  } | null;
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
