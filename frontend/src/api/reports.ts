import { apiClient } from './client';
import type { APIResponse } from './client';

export interface ComplianceStandard {
  name: string;
  score: number;
  details: string;
}

export interface ReportsSummary {
  has_data?: boolean;
  compliance: ComplianceStandard[];
  summary: {
    score: number | string | null;
    grade: string;
    findings_count: number;
    status?: string;
  };
  findings_by_severity?: Record<string, number>;
  findings_by_category?: Record<string, number>;
  findings?: any[];
}

export const getReportsSummary = async (): Promise<ReportsSummary> => {
  const res = await apiClient.get<APIResponse<ReportsSummary>>('/reports');
  return res.data.data;
};
