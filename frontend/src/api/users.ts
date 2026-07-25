import { apiClient } from './client';
import type { APIResponse } from './client';
import type { IAMUser } from '../types';

export const getIAMUsers = async (): Promise<IAMUser[]> => {
  const res = await apiClient.get<APIResponse<IAMUser[]>>('/users');
  return res.data.data;
};
