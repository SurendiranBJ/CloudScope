import React, { lazy } from 'react';
import { useAuth, type Role } from '../context/AuthContext';

const Forbidden = lazy(async () => ({ default: (await import('../pages/Forbidden')).Forbidden }));

interface ProtectedRouteProps {
  children: React.ReactNode;
  minRole?: Role;
  requiredRole?: Role;
  requiredPermission?: string;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  minRole,
  requiredRole,
  requiredPermission,
}) => {
  const { hasMinRole, hasRole, hasPermission, isDevMode } = useAuth();

  // Role checks here are only a development convenience. The API owns the
  // authorization decision for deployed sessions.
  if (!isDevMode) return <>{children}</>;

  if (requiredRole && !hasRole(requiredRole)) {
    return <Forbidden requiredRole={requiredRole} />;
  }

  if (minRole && !hasMinRole(minRole)) {
    return <Forbidden requiredRole={minRole} />;
  }

  if (requiredPermission && !hasPermission(requiredPermission)) {
    return <Forbidden requiredPermission={requiredPermission} />;
  }

  return <>{children}</>;
};
