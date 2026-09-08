import { apiClient, APIResponse } from './client';
import type { PolicyCatalogEntry } from '../types';

export interface PolicyListParams {
  type_filter?: 'aws-managed' | 'customer-managed' | 'inline';
  search?: string;
  limit?: number;
}

export const getPolicyCatalog = async (params?: PolicyListParams): Promise<PolicyCatalogEntry[]> => {
  const res = await apiClient.get<APIResponse<PolicyCatalogEntry[]>>('/policies', { params });
  return res.data.data;
};

export const getPolicyById = async (policyId: string): Promise<PolicyCatalogEntry> => {
  const encoded = encodeURIComponent(policyId);
  const res = await apiClient.get<APIResponse<PolicyCatalogEntry>>(`/policies/${encoded}`);
  return res.data.data;
};
