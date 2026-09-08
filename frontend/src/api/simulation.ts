import { apiClient, APIResponse } from './client';
import type {
  SimulationState,
  SimulationChange,
  SimulationAnalysis,
  GraphDiff,
  RiskComparison,
  AttackPathComparison,
  BlastRadiusComparison,
} from '../types';

export interface SimulationChangePayload {
  action: 'ATTACH_POLICY' | 'DETACH_POLICY';
  principal_type: 'USER' | 'GROUP' | 'ROLE';
  principal_id: string;
  policy_arn: string;
}

// ── State ────────────────────────────────────────────────────────────────────

export const getSimulationState = async (): Promise<SimulationState> => {
  const res = await apiClient.get<APIResponse<SimulationState>>('/simulation/state');
  return res.data.data;
};

// ── Mutate ───────────────────────────────────────────────────────────────────

export const addSimulationChange = async (change: SimulationChangePayload): Promise<SimulationChange> => {
  const res = await apiClient.post<APIResponse<SimulationChange>>('/simulation/changes', change);
  return res.data.data;
};

export const removeSimulationChange = async (changeId: string): Promise<void> => {
  await apiClient.delete(`/simulation/changes/${changeId}`);
};

export const resetSimulation = async (): Promise<void> => {
  await apiClient.post('/simulation/reset');
};

// ── Preview (POST, does NOT persist) ─────────────────────────────────────────

export const previewSimulationChange = async (
  change: SimulationChangePayload
): Promise<SimulationAnalysis> => {
  const res = await apiClient.post<APIResponse<SimulationAnalysis>>(
    '/simulation/preview',
    change
  );
  return res.data.data;
};

// ── Analysis ─────────────────────────────────────────────────────────────────

export const getSimulationDiff = async (): Promise<{
  simulation_active: boolean;
  pending_changes: number;
  graph_diff: GraphDiff | null;
}> => {
  const res = await apiClient.get<APIResponse<{
    simulation_active: boolean;
    pending_changes: number;
    graph_diff: GraphDiff | null;
  }>>('/simulation/diff');
  return res.data.data;
};

export const getSimulationRisk = async (): Promise<RiskComparison & { simulation_active: boolean; pending_changes?: number }> => {
  const res = await apiClient.get<APIResponse<RiskComparison & { simulation_active: boolean; pending_changes?: number }>>('/simulation/risk');
  return res.data.data;
};

export const getSimulationAttackPaths = async (): Promise<{
  simulation_active: boolean;
  pending_changes?: number;
  current_paths: unknown[];
} & AttackPathComparison> => {
  const res = await apiClient.get<APIResponse<{
    simulation_active: boolean;
    pending_changes?: number;
    current_paths: unknown[];
  } & AttackPathComparison>>('/simulation/attack-paths');
  return res.data.data;
};

export const getSimulationBlastRadius = async (): Promise<BlastRadiusComparison & { simulation_active: boolean }> => {
  const res = await apiClient.get<APIResponse<BlastRadiusComparison & { simulation_active: boolean }>>('/simulation/blast-radius');
  return res.data.data;
};
