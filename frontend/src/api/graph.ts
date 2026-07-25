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

export const getGraphElements = async (): Promise<CytoscapeElement[]> => {
  const res = await apiClient.get<APIResponse<CytoscapeElement[]>>('/graph');
  return res.data.data;
};

export const rebuildGraph = async (): Promise<any> => {
  const res = await apiClient.post<APIResponse<any>>('/graph/rebuild');
  return res.data.data;
};
