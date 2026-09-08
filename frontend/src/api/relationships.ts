import { apiClient, APIResponse } from './client';
import type { RelationshipsResponse, RelationshipEntry } from '../types';

export interface RelationshipParams {
  entity_type?: string;
  search?: string;
  limit?: number;
}

export const getRelationships = async (params?: RelationshipParams): Promise<RelationshipsResponse> => {
  const res = await apiClient.get<APIResponse<RelationshipsResponse>>('/relationships', { params });
  return res.data.data;
};

export const getEntityRelationships = async (
  entityId: string,
  direction?: 'incoming' | 'outgoing' | 'both'
): Promise<{
  entity_id: string;
  entity_name: string;
  entity_type: string;
  relationships: RelationshipEntry[];
  outgoing_count: number;
  incoming_count: number;
  provenance: { chain: string[]; relationships: string[] }[];
}> => {
  const encoded = encodeURIComponent(entityId);
  const res = await apiClient.get<APIResponse<{
    entity_id: string;
    entity_name: string;
    entity_type: string;
    relationships: RelationshipEntry[];
    outgoing_count: number;
    incoming_count: number;
    provenance: { chain: string[]; relationships: string[] }[];
  }>>(`/relationships/${encoded}`, { params: direction ? { direction } : undefined });
  return res.data.data;
};
