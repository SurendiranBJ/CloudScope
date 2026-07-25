import { apiClient } from './client';
import type { APIResponse } from './client';
import type { IAMRole } from '../types';

export const getIAMRoles = async (): Promise<IAMRole[]> => {
  const res = await apiClient.get<APIResponse<IAMRole[]>>('/roles');
  return res.data.data;
};
