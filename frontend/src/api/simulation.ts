import { apiClient, type APIResponse } from './client';
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

export interface SimulationChangeBatchPayload {
  changes: SimulationChangePayload[];
}

export const getSimulationGroups = async (): Promise<{ name: string; attachedPolicies?: string[]; attachedPolicyArns?: Record<string, string> }[]> => {
  const res = await apiClient.get<APIResponse<{ groups: { name: string; attachedPolicies?: string[]; attachedPolicyArns?: Record<string, string> }[] }>>('/simulation/groups');
  return res.data.data.groups || [];
};

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

export const addSimulationChanges = async (changes: SimulationChangePayload[]): Promise<SimulationChange[]> => {
  const res = await apiClient.post<APIResponse<{ changes: SimulationChange[] }>>('/simulation/changes/batch', { changes });
  return res.data.data.changes || [];
};

export const removeSimulationChange = async (changeId: string): Promise<void> => {
  await apiClient.delete(`/simulation/changes/${changeId}`);
};

export const updateSimulationChange = async (changeId: string, change: SimulationChangePayload): Promise<SimulationChange> => {
  const res = await apiClient.put<APIResponse<SimulationChange>>(`/simulation/changes/${changeId}`, change);
  return res.data.data;
};

export const resetSimulation = async (): Promise<void> => {
  await apiClient.post('/simulation/reset');
};

// ── Preview (POST, does NOT persist) ─────────────────────────────────────────

export const previewSimulationChange = async (
  change: SimulationChangePayload | SimulationChangeBatchPayload
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
  desired_elements?: any[];
}> => {
  const res = await apiClient.get<APIResponse<{
    simulation_active: boolean;
    pending_changes: number;
    graph_diff: GraphDiff | null;
    desired_elements?: any[];
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
