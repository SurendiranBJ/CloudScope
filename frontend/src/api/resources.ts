import { apiClient } from './client';
import type { APIResponse } from './client';
import type { CloudResource } from '../types';

export const getCloudResources = async (): Promise<CloudResource[]> => {
  const res = await apiClient.get<APIResponse<CloudResource[]>>('/resources');
  return res.data.data;
};
