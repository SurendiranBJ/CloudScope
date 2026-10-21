import { apiClient } from './client';
import type { APIResponse } from './client';
import type { SecurityAlert } from '../types';
import type { CopilotMessage } from './copilot';

export const getSecurityAlerts = async (): Promise<SecurityAlert[]> => {
  const res = await apiClient.get<APIResponse<SecurityAlert[]>>('/alerts');
  return res.data.data;
};

export const explainSecurityAlert = async (alert_id: string): Promise<CopilotMessage> => {
  const res = await apiClient.post<APIResponse<CopilotMessage>>('/copilot/explain-alert', { alert_id });
  return res.data.data;
};
