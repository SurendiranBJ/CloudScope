import React, { useState } from 'react';
import { Search, ChevronDown, User, Shield } from 'lucide-react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useScanLifecycle } from '../hooks/useScanLifecycle.ts';
import { useAuth } from '../context/AuthContext';
import { ThemeToggle } from './ThemeToggle';

interface NavbarProps {
  onSearchChange?: (val: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ onSearchChange }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const isDashboard = location.pathname === '/' || location.pathname === '/dashboard';
  const [showProfile, setShowProfile] = useState(false);
  const { currentUser, isAuthenticated } = useAuth();
  const roleLabel = isAuthenticated ? 'Signed in' : 'Not authenticated';

  const { isScanning, scanJustCompleted, hasCompletedSnapshot, currentSnapshotId } = useScanLifecycle();

  const showSearch = location.pathname === '/resources' || location.pathname === '/risks';

  return (
    <header className="h-16 border-b border-enterprise-border bg-enterprise-card px-6 flex items-center justify-between relative z-40 select-none">
      {/* Search Input */}
      <div className={`relative ${showSearch ? 'w-96' : 'w-0'}`}>
        {showSearch && <>
        <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <Search className="h-4 w-4 text-enterprise-subtext" />
        </span>
        <input
          type="text"
          placeholder={location.pathname === '/resources' ? 'Filter cloud resources…' : 'Filter findings…'}
          className="w-full bg-enterprise-bg/60 border border-enterprise-border rounded-lg pl-10 pr-4 py-2 text-sm text-white placeholder-enterprise-subtext focus:outline-none focus:border-enterprise-accent transition-colors"
          onChange={(e) => onSearchChange && onSearchChange(e.target.value)}
        />
        </>}
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-4">
        {/* Global Scan Status Indicator: shown on subpages only to prevent duplicate on Dashboard */}
        {!isDashboard && isScanning ? (
          <button
            type="button"
            onClick={() => navigate('/')}
            title="Scan in progress — click to view on Dashboard"
            className="flex items-center gap-2 bg-blue-500/10 border border-blue-500/25 px-2.5 py-1 rounded-full text-xs font-medium text-blue-400 hover:bg-blue-500/20 transition-colors cursor-pointer"
          >
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500" />
            </span>
            <span>Scanning</span>
          </button>
        ) : !isDashboard && (hasCompletedSnapshot || scanJustCompleted) ? (
          <button
            type="button"
            onClick={() => navigate('/')}
            title={`Snapshot: ${currentSnapshotId ? currentSnapshotId.slice(0, 8) : 'active'} — click to view on Dashboard`}
            className="flex items-center gap-1.5 bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 rounded-full text-xs font-medium text-emerald-400 hover:bg-emerald-500/20 transition-colors cursor-pointer"
          >
            <span className="inline-flex rounded-full h-1.5 w-1.5 bg-emerald-400" />
            <span>Updated</span>
          </button>
        ) : null}

        {/* Theme Toggle Button */}
        <ThemeToggle className="hidden sm:inline-flex" />

        {/* Profile Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowProfile(!showProfile)}
            className="flex items-center gap-2 p-1.5 hover:bg-gray-800/40 rounded-lg transition-colors border border-transparent hover:border-enterprise-border"
          >
            <div className="w-8 h-8 rounded-full bg-enterprise-accent/20 flex items-center justify-center border border-enterprise-accent/30 text-enterprise-accent">
              <User className="w-4 h-4" />
            </div>
            <div className="text-left hidden md:block">
              <p className="text-xs font-semibold text-white">{currentUser.id}</p>
              <p className="text-[10px] text-enterprise-accent font-semibold">{roleLabel}</p>
            </div>
            <ChevronDown className="w-4 h-4 text-enterprise-subtext" />
          </button>

          {showProfile && (
            <div className="absolute right-0 mt-2 w-56 bg-enterprise-card border border-enterprise-border rounded-xl shadow-2xl overflow-hidden z-50 divide-y divide-enterprise-border">
              <div className="p-3">
                <p className="text-xs font-bold text-white truncate">{currentUser.id}</p>
                <div className="flex items-center gap-1.5 mt-1">
                  <Shield className="w-3 h-3 text-enterprise-accent" />
                  <span className="text-[10px] text-enterprise-subtext uppercase font-semibold">{roleLabel}</span>
                </div>
              </div>

              <div className="p-2 space-y-0.5">
                <button
                  onClick={() => { setShowProfile(false); navigate('/settings'); }}
                  className="w-full text-left px-3 py-1.5 rounded hover:bg-gray-800 text-xs text-gray-200"
                >
                  Settings
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
