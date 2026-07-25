import { apiClient } from './client';
import type { APIResponse } from './client';
import type { AttackPath } from '../types';

export const getAttackPaths = async (): Promise<AttackPath[]> => {
  const res = await apiClient.get<APIResponse<AttackPath[]>>('/attack-paths');
  return res.data.data;
};

export const getAttackPathById = async (id: string): Promise<AttackPath> => {
  const res = await apiClient.get<APIResponse<AttackPath>>(`/attack-paths/${id}`);
  return res.data.data;
};

export const triggerManualScan = async (): Promise<any> => {
  const res = await apiClient.post<APIResponse<any>>('/scan');
  return res.data.data;
};
