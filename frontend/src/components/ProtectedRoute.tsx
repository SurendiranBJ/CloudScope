import React from 'react';
import { useAuth, type Role } from '../context/AuthContext';
import { Forbidden } from '../pages/Forbidden';

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
  const { hasMinRole, hasRole, hasPermission } = useAuth();

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
