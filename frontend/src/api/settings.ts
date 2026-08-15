import { apiClient } from './client';
import type { APIResponse } from './client';

export interface ScanIntervalResponse {
  minutes: number;
  message: string;
}

export const postScanInterval = async (minutes: number): Promise<ScanIntervalResponse> => {
  const res = await apiClient.post<APIResponse<ScanIntervalResponse>>('/settings/scan-interval', { minutes });
  return res.data.data;
};
