import { apiClient } from './client';
import type { APIResponse } from './client';
import type { DashboardData } from '../types';

export const getDashboardSummary = async (): Promise<DashboardData> => {
  const res = await apiClient.get<APIResponse<DashboardData>>('/dashboard');
  return res.data.data;
};
