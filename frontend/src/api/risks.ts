import { apiClient } from './client';
import type { APIResponse } from './client';
import type { RiskFinding, SecurityFinding } from '../types';

export const getRiskAssessmentFindings = async (): Promise<RiskFinding[]> => {
  const res = await apiClient.get<APIResponse<RiskFinding[]>>('/risk-assessment');
  return res.data.data;
};

export const getSecurityFindings = async (params?: Record<string, string>): Promise<SecurityFinding[]> => {
  const res = await apiClient.get<APIResponse<SecurityFinding[]>>('/findings', { params });
  return res.data.data;
};

export const acknowledgeFinding = async (id: string): Promise<SecurityFinding> => {
  const res = await apiClient.post<APIResponse<SecurityFinding>>(`/findings/${id}/acknowledge`);
  return res.data.data;
};

export const resolveFinding = async (id: string): Promise<SecurityFinding> => {
  const res = await apiClient.post<APIResponse<SecurityFinding>>(`/findings/${id}/resolve`);
  return res.data.data;
};

export const suppressFinding = async (id: string): Promise<SecurityFinding> => {
  const res = await apiClient.post<APIResponse<SecurityFinding>>(`/findings/${id}/suppress`);
  return res.data.data;
};
