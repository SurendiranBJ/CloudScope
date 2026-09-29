import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldX, ArrowLeft, KeyRound } from 'lucide-react';
import { useAuth, type Role } from '../context/AuthContext';

interface ForbiddenProps {
  requiredRole?: Role;
  requiredPermission?: string;
}

export const Forbidden: React.FC<ForbiddenProps> = ({ requiredRole = 'ADMINISTRATOR', requiredPermission }) => {
  const navigate = useNavigate();
  const { currentUser, activeDevRole, setDevRole, isDevMode } = useAuth();

  return (
    <div className="flex-1 flex flex-col items-center justify-center p-8 bg-enterprise-bg text-center">
      <div className="max-w-md w-full bg-enterprise-card border border-rose-800/40 rounded-2xl p-8 shadow-2xl relative overflow-hidden">
        {/* Glow effect */}
        <div className="absolute -top-16 -left-16 w-32 h-32 bg-rose-600/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-16 -right-16 w-32 h-32 bg-rose-600/10 rounded-full blur-3xl pointer-events-none" />

        <div className="w-16 h-16 mx-auto mb-5 rounded-2xl bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-400">
          <ShieldX className="w-8 h-8" />
        </div>

        <h1 className="text-2xl font-bold text-white mb-2">403 — Access Denied</h1>
        <p className="text-sm text-enterprise-subtext mb-6">
          You do not have sufficient privileges to access this operational resource.
        </p>

        <div className="bg-enterprise-bg/60 border border-enterprise-border rounded-xl p-4 mb-6 text-left space-y-2 text-xs">
          <div className="flex justify-between">
            <span className="text-enterprise-subtext">Current User:</span>
            <span className="font-mono text-gray-200">{currentUser.id}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-enterprise-subtext">Active Role:</span>
            <span className="font-semibold text-rose-400">{activeDevRole}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-enterprise-subtext">Required Minimum Role:</span>
            <span className="font-semibold text-emerald-400">{requiredRole}</span>
          </div>
          {requiredPermission && (
            <div className="flex justify-between">
              <span className="text-enterprise-subtext">Required Permission:</span>
              <span className="font-mono text-blue-400">{requiredPermission}</span>
            </div>
          )}
        </div>

        {isDevMode && (
          <div className="bg-blue-950/30 border border-blue-800/40 rounded-xl p-3 mb-6 text-xs text-left">
            <div className="flex items-center gap-2 text-blue-300 font-semibold mb-2">
              <KeyRound className="w-4 h-4 text-blue-400" />
              <span>Dev Auth Quick Switch:</span>
            </div>
            <div className="flex gap-2 flex-wrap">
              {(['VIEWER', 'ANALYST', 'SECURITY_OFFICER', 'ADMINISTRATOR'] as Role[]).map((r) => (
                <button
                  key={r}
                  onClick={() => setDevRole(r)}
                  className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                    activeDevRole === r
                      ? 'bg-enterprise-accent text-white font-bold'
                      : 'bg-enterprise-card hover:bg-gray-800 text-enterprise-subtext hover:text-white border border-enterprise-border'
                  }`}
                >
                  {r}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="flex gap-3 justify-center">
          <button
            onClick={() => navigate('/')}
            className="flex items-center gap-2 px-4 py-2 bg-enterprise-card hover:bg-gray-800 border border-enterprise-border rounded-lg text-sm text-white font-medium transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Return to Dashboard</span>
          </button>
        </div>
      </div>
    </div>
  );
};
