import { apiClient } from './client';
import type { APIResponse } from './client';
import type { SecurityAlert } from '../types';

export const getSecurityAlerts = async (): Promise<SecurityAlert[]> => {
  const res = await apiClient.get<APIResponse<SecurityAlert[]>>('/alerts');
  return res.data.data;
};
