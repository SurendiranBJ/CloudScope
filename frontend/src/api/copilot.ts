import { apiClient } from './client';
import type { APIResponse } from './client';

export interface CopilotRequestPayload {
  prompt: string;
  context_type?: string;
  entity_id?: string;
  entity_type?: string;
  attack_path_id?: string;
  finding_id?: string;
  simulation_context?: Record<string, any>;
}

export interface CopilotMessage {
  sender: 'user' | 'ai';
  text: string;
  type?: 'text' | 'remediation' | 'analysis';
  codeBlock?: string;
  summary?: string;
  analysis?: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN';
  riskScore?: number | null;
  affectedEntities?: string[];
  evidence?: string[];
  recommendations?: string[];
  suggestions?: string[];
  limitations?: string[];
  provider?: string;
  model?: string;
}

export const postCopilotMessage = async (
  payloadOrPrompt: string | CopilotRequestPayload
): Promise<CopilotMessage> => {
  const payload = typeof payloadOrPrompt === 'string'
    ? { prompt: payloadOrPrompt }
    : payloadOrPrompt;
  const res = await apiClient.post<APIResponse<CopilotMessage>>('/copilot', payload);
  return res.data.data;
};

export const explainFinding = async (finding_id: string): Promise<CopilotMessage> => {
  const res = await apiClient.post<APIResponse<CopilotMessage>>('/copilot/explain-finding', {
    finding_id,
  });
  return res.data.data;
};

export const explainAttackPath = async (
  attack_path_id: string,
  supplementary_metadata?: Record<string, any>
): Promise<CopilotMessage> => {
  const res = await apiClient.post<APIResponse<CopilotMessage>>('/copilot/explain-attack-path', {
    attack_path_id,
    supplementary_metadata,
  });
  return res.data.data;
};
