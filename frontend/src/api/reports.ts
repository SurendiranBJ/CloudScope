import { apiClient } from './client';
import type { APIResponse } from './client';

export interface ComplianceStandard {
  name: string;
  score: number;
  details: string;
}

export interface ReportsSummary {
  compliance: ComplianceStandard[];
  summary: {
    score: string;
    grade: string;
    findings_count: number;
  };
}

export const getReportsSummary = async (): Promise<ReportsSummary> => {
  const res = await apiClient.get<APIResponse<ReportsSummary>>('/reports');
  return res.data.data;
};
