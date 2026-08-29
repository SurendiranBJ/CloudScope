import axios from 'axios';

const apiBase = import.meta.env.VITE_API_BASE_URL 
  ? `${import.meta.env.VITE_API_BASE_URL.replace(/\/+$/, '')}/api/v1`
  : 'http://localhost:8000/api/v1';

export const apiClient = axios.create({
  baseURL: apiBase,
  headers: {
    'Content-Type': 'application/json',
  },
});

export interface APIResponse<T> {
  success: boolean;
  message: string;
  timestamp: string;
  data: T;
}
