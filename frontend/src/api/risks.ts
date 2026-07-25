import { apiClient } from './client';
import type { APIResponse } from './client';
import type { RiskFinding } from '../types';

export const getRiskAssessmentFindings = async (): Promise<RiskFinding[]> => {
  const res = await apiClient.get<APIResponse<RiskFinding[]>>('/risk-assessment');
  return res.data.data;
};
