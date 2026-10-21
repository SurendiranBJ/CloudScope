import { apiClient, type APIResponse } from './client';

export interface SnapshotHistoryItem {
  snapshot_id: string;
  scan_id: string;
  published_at: string;
  status: string;
  duration_seconds?: number;
  regions: Record<string, unknown>;
  resource_counts: Record<string, number>;
  finding_counts: Record<string, number>;
  metadata: Record<string, unknown>;
  is_current: boolean;
}

export const getSnapshotHistory = async (): Promise<SnapshotHistoryItem[]> => {
  const response = await apiClient.get<APIResponse<{ snapshots: SnapshotHistoryItem[] }>>('/snapshots/history');
  return response.data.data.snapshots || [];
};
