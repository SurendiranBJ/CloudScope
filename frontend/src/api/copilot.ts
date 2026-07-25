import { apiClient } from './client';
import type { APIResponse } from './client';

export interface CopilotMessage {
  sender: 'user' | 'ai';
  text: string;
  type?: 'text' | 'remediation' | 'analysis';
  codeBlock?: string;
}

export const postCopilotMessage = async (prompt: string): Promise<CopilotMessage> => {
  const res = await apiClient.post<APIResponse<CopilotMessage>>('/copilot', { prompt });
  return res.data.data;
};
