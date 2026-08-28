import { apiClient } from './client';
import type { APIResponse } from './client';

export interface ScanIntervalResponse {
  minutes: number;
  message: string;
}

export interface RegionOption {
  code: string;
  friendly_name: string;
}

export interface ScanRegionResponse {
  mode: string;
  region: string | null;
  scan_regions: string[];
  message: string;
}

export const postScanInterval = async (minutes: number): Promise<ScanIntervalResponse> => {
  const res = await apiClient.post<APIResponse<ScanIntervalResponse>>('/settings/scan-interval', { minutes });
  return res.data.data;
};

export const getAvailableRegions = async (): Promise<RegionOption[]> => {
  const res = await apiClient.get<APIResponse<RegionOption[]>>('/settings/available-regions');
  return res.data.data;
};

export const postScanRegion = async (
  mode: 'single' | 'global',
  region?: string
): Promise<ScanRegionResponse> => {
  const res = await apiClient.post<APIResponse<ScanRegionResponse>>('/settings/scan-region', {
    mode,
    region: region ?? null,
  });
  return res.data.data;
};
