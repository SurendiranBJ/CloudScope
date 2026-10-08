import React, { createContext, useContext, useState, useEffect, useCallback, useMemo, type ReactNode } from 'react';
import type { ErrorEventDetail } from '../api/client';

export type Role = 'VIEWER' | 'ANALYST' | 'SECURITY_OFFICER' | 'ADMINISTRATOR';

export const ROLE_HIERARCHY: Record<Role, number> = {
  VIEWER: 1,
  ANALYST: 2,
  SECURITY_OFFICER: 3,
  ADMINISTRATOR: 4,
};

export const ROLE_PERMISSIONS: Record<Role, string[]> = {
  VIEWER: ['view:read'],
  ANALYST: ['view:read', 'simulation:execute', 'copilot:query'],
  SECURITY_OFFICER: ['view:read', 'simulation:execute', 'copilot:query', 'finding:mutate', 'audit:view'],
  ADMINISTRATOR: [
    'view:read',
    'simulation:execute',
    'copilot:query',
    'finding:mutate',
    'audit:view',
    'scan:trigger',
    'settings:modify',
    'operations:manage',
  ],
};

export interface UserProfile {
  id: string;
  email?: string;
  roles: Role[];
  permissions: string[];
}

export interface SecurityNotice {
  type: 'RATE_LIMIT' | 'SERVER_ERROR' | 'FORBIDDEN' | 'AUTH_ERROR';
  message: string;
  requestId?: string;
  retryAfter?: number;
  code?: string;
  timestamp: number;
}

interface AuthContextType {
  currentUser: UserProfile;
  roles: Role[];
  permissions: string[];
  isAuthenticated: boolean;
  isLoading: boolean;
  isDevMode: boolean;
  activeDevRole: Role;
  setDevRole: (role: Role) => void;
  login: (token: string) => void;
  logout: () => void;
  hasRole: (role: Role) => boolean;
  hasMinRole: (minRole: Role) => boolean;
  hasPermission: (permission: string) => boolean;
  activeNotice: SecurityNotice | null;
  clearNotice: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('cloudscope_token'));
  const [activeDevRole, setActiveDevRoleState] = useState<Role>(() => {
    return (localStorage.getItem('cloudscope_dev_role') as Role) || 'VIEWER';
  });
  const [activeNotice, setActiveNotice] = useState<SecurityNotice | null>(null);
  const [isLoading] = useState<boolean>(false);

  const isDevMode = import.meta.env.DEV && !token;

  // Compute effective roles and permissions
  const roles: Role[] = useMemo(() => {
    return isDevMode ? [activeDevRole] : [];
  }, [activeDevRole, isDevMode]);

  const highestRoleLevel = Math.max(...roles.map((r) => ROLE_HIERARCHY[r] || 1));
  const permissions: string[] = useMemo(() => {
    return isDevMode ? ROLE_PERMISSIONS[activeDevRole] || ROLE_PERMISSIONS.VIEWER : [];
  }, [activeDevRole, isDevMode]);

  const currentUser: UserProfile = useMemo(() => ({
    id: isDevMode
      ? localStorage.getItem('cloudscope_dev_user') || 'dev-user'
      : token ? 'Authenticated user' : 'Not authenticated',
    email: undefined,
    roles,
    permissions,
  }), [isDevMode, token, roles, permissions]);

  const setDevRole = useCallback((role: Role) => {
    if (!import.meta.env.DEV || token) return;
    localStorage.setItem('cloudscope_dev_role', role);
    setActiveDevRoleState(role);
    // Reload or notify consumers if needed
  }, [token]);

  const login = useCallback((jwtToken: string) => {
    localStorage.setItem('cloudscope_token', jwtToken);
    setToken(jwtToken);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('cloudscope_token');
    setToken(null);
  }, []);

  const hasRole = useCallback(
    (role: Role) => roles.includes(role),
    [roles]
  );

  const hasMinRole = useCallback(
    (minRole: Role) => {
      const minLevel = ROLE_HIERARCHY[minRole] || 1;
      return highestRoleLevel >= minLevel;
    },
    [highestRoleLevel]
  );

  const hasPermission = useCallback(
    (perm: string) => permissions.includes(perm),
    [permissions]
  );

  const clearNotice = useCallback(() => {
    setActiveNotice(null);
  }, []);

  // Listen to global interceptor error events
  useEffect(() => {
    const handleRateLimit = (e: Event) => {
      const detail = (e as CustomEvent<ErrorEventDetail>).detail;
      setActiveNotice({
        type: 'RATE_LIMIT',
        message: detail.message || 'API rate limit reached. Please wait before retrying.',
        requestId: detail.requestId,
        retryAfter: detail.retryAfter,
        code: detail.code,
        timestamp: Date.now(),
      });
    };

    const handleServerError = (e: Event) => {
      const detail = (e as CustomEvent<ErrorEventDetail>).detail;
      setActiveNotice({
        type: 'SERVER_ERROR',
        message: detail.message || 'Server encountered an unexpected error.',
        requestId: detail.requestId,
        code: detail.code,
        timestamp: Date.now(),
      });
    };

    const handleForbidden = (e: Event) => {
      const detail = (e as CustomEvent<ErrorEventDetail>).detail;
      setActiveNotice({
        type: 'FORBIDDEN',
        message: detail.message || 'Access denied: your assigned role does not have permission.',
        requestId: detail.requestId,
        code: detail.code,
        timestamp: Date.now(),
      });
    };

    const handleAuthError = (e: Event) => {
      const detail = (e as CustomEvent<ErrorEventDetail>).detail;
      setActiveNotice({
        type: 'AUTH_ERROR',
        message: detail.message || 'Authentication failed or expired.',
        requestId: detail.requestId,
        code: detail.code,
        timestamp: Date.now(),
      });
    };

    window.addEventListener('cloudscope:rate_limited', handleRateLimit);
    window.addEventListener('cloudscope:server_error', handleServerError);
    window.addEventListener('cloudscope:forbidden', handleForbidden);
    window.addEventListener('cloudscope:auth_error', handleAuthError);

    return () => {
      window.removeEventListener('cloudscope:rate_limited', handleRateLimit);
      window.removeEventListener('cloudscope:server_error', handleServerError);
      window.removeEventListener('cloudscope:forbidden', handleForbidden);
      window.removeEventListener('cloudscope:auth_error', handleAuthError);
    };
  }, []);

  return (
    <AuthContext.Provider
      value={{
        currentUser,
        roles,
        permissions,
        isAuthenticated: Boolean(token) || isDevMode,
        isLoading,
        isDevMode,
        activeDevRole,
        setDevRole,
        login,
        logout,
        hasRole,
        hasMinRole,
        hasPermission,
        activeNotice,
        clearNotice,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
