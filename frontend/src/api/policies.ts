import { apiClient, type APIResponse } from './client';
import type { PolicyCatalogEntry, PaginatedPolicyCatalog } from '../types';

export interface PolicyListParams {
  page?: number;
  page_size?: number;
  type_filter?: 'aws-managed' | 'customer-managed' | 'inline';
  search?: string;
  limit?: number;
}

export const getPolicyCatalog = async (params?: PolicyListParams): Promise<PaginatedPolicyCatalog> => {
  const res = await apiClient.get<APIResponse<PaginatedPolicyCatalog | PolicyCatalogEntry[]>>('/policies', { params });
  const data = res.data.data;
  if (Array.isArray(data)) {
    return {
      items: data,
      page: params?.page ?? 1,
      page_size: params?.page_size ?? data.length,
      total: data.length,
      total_pages: 1,
    };
  }
  return data;
};

export const getPolicyById = async (policyId: string): Promise<PolicyCatalogEntry> => {
  const encoded = encodeURIComponent(policyId);
  const res = await apiClient.get<APIResponse<PolicyCatalogEntry>>(`/policies/${encoded}`);
  return res.data.data;
};
