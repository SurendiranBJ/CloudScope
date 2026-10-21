import axios, { AxiosError } from 'axios';

const apiBase = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_BASE_URL)
  ? `${import.meta.env.VITE_API_BASE_URL.replace(/\/+$/, '')}/api/v1`
  : 'http://localhost:8000/api/v1';

export const apiClient = axios.create({
  baseURL: apiBase,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor: attach bearer token or dev role headers
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('cloudscope_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  } else if (typeof import.meta !== 'undefined' && import.meta.env?.DEV) {
    // Development-only role headers are ignored by production builds.
    const devRole = localStorage.getItem('cloudscope_dev_role') || 'ADMINISTRATOR';
    const devUser = localStorage.getItem('cloudscope_dev_user') || 'admin-user';
    config.headers['X-Dev-Role'] = devRole;
    config.headers['X-Dev-User'] = devUser;
    config.headers['X-Dev-Subject'] = devUser;
  }
  return config;
});

export interface ErrorEventDetail {
  status: number;
  message: string;
  requestId?: string;
  retryAfter?: number;
  code?: string;
}

// Response interceptor: handle security and error responses
apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError<any>) => {
    if (error.response) {
      const status = error.response.status;
      const data = error.response.data || {};
      const requestId =
        error.response.headers['x-request-id'] ||
        data.request_id ||
        (data.error && data.error.request_id);

      const message =
        (data.error && data.error.message) ||
        data.detail ||
        error.message ||
        'An unexpected error occurred';

      const code = (data.error && data.error.code) || 'UNKNOWN_ERROR';

      if (status === 401) {
        // Evict stale or invalid token to unblock session recovery
        localStorage.removeItem('cloudscope_token');
        const authMessage =
          (data.error && data.error.message) ||
          data.detail ||
          'Session expired or unauthenticated.';
        window.dispatchEvent(
          new CustomEvent<ErrorEventDetail>('cloudscope:auth_error', {
            detail: { status: 401, message: authMessage, requestId, code },
          })
        );
      } else if (status === 403) {
        window.dispatchEvent(
          new CustomEvent<ErrorEventDetail>('cloudscope:forbidden', {
            detail: { status: 403, message, requestId, code },
          })
        );
      } else if (status === 429) {
        const retryAfterHeader = error.response.headers['retry-after'];
        const retryAfter = retryAfterHeader ? parseInt(retryAfterHeader, 10) : 30;
        window.dispatchEvent(
          new CustomEvent<ErrorEventDetail>('cloudscope:rate_limited', {
            detail: { status: 429, message, requestId, retryAfter, code },
          })
        );
      } else if (status >= 500) {
        window.dispatchEvent(
          new CustomEvent<ErrorEventDetail>('cloudscope:server_error', {
            detail: { status, message, requestId, code },
          })
        );
      }
    }
    return Promise.reject(error);
  }
);

export interface APIResponse<T> {
  success: boolean;
  message: string;
  timestamp: string;
  data: T;
}

