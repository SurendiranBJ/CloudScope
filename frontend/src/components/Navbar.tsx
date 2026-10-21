import React, { useState } from 'react';
import { Search, ChevronDown, User, Shield } from 'lucide-react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useScanLifecycle } from '../hooks/useScanLifecycle.ts';
import { useAuth } from '../context/AuthContext';
import { ThemeToggle } from './ThemeToggle';
import { useQuery } from '@tanstack/react-query';
import { Clock3, Check, X } from 'lucide-react';
import { getSnapshotHistory } from '../api/snapshots';
import { useSnapshotView } from '../context/SnapshotViewContext';
import { formatRegion } from '../utils/regionNames';

const getSnapshotRegionSummary = (regions: Record<string, unknown>) => {
  const rawRegions = regions.scanned_regions ?? regions.resolved_regions ?? regions.successful_regions;
  if (!Array.isArray(rawRegions) || rawRegions.length === 0) return 'Region details unavailable';
  const labels = rawRegions.filter((region): region is string => typeof region === 'string').map(formatRegion);
  const shown = labels.slice(0, 3).join(', ');
  const remaining = labels.length > 3 ? `, +${labels.length - 3} more` : '';
  const scope = regions.scan_mode === 'global' ? `All regions · ${labels.length}` : `${labels.length} region${labels.length === 1 ? '' : 's'}`;
  return `${scope}: ${shown}${remaining}`;
};

interface NavbarProps {
  onSearchChange?: (val: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ onSearchChange }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const isDashboard = location.pathname === '/' || location.pathname === '/dashboard';
  const [showProfile, setShowProfile] = useState(false);
  const [showSnapshots, setShowSnapshots] = useState(false);
  const { snapshotId, selectSnapshot, exitSnapshot } = useSnapshotView();
  const { data: snapshots = [], isLoading: snapshotsLoading, isError: snapshotsError } = useQuery({ queryKey: ['snapshot-history'], queryFn: getSnapshotHistory, staleTime: 60_000 });
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
        <div className="relative">
          <button type="button" onClick={() => setShowSnapshots((value) => !value)} className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-semibold transition-colors ${snapshotId ? 'border-amber-400/40 bg-amber-400/10 text-amber-200' : 'border-enterprise-border text-enterprise-subtext hover:bg-enterprise-bg hover:text-white'}`}><Clock3 className="h-3.5 w-3.5" />Snapshots <span className="rounded bg-black/15 px-1.5 py-0.5">{snapshots.length}/10</span></button>
          {showSnapshots && <div className="absolute right-0 top-full z-50 mt-2 w-[min(24rem,90vw)] overflow-hidden rounded-xl border border-enterprise-border bg-enterprise-card shadow-2xl"><div className="flex items-center justify-between border-b border-enterprise-border px-3 py-2.5"><div><p className="text-sm font-semibold text-white">Snapshot history</p><p className="text-[10px] text-enterprise-subtext">Choose a saved scan to browse the app as it was then.</p></div><button type="button" aria-label="Close snapshot history" onClick={() => setShowSnapshots(false)} className="rounded p-1 text-enterprise-subtext hover:text-white"><X className="h-4 w-4" /></button></div><div className="max-h-[65vh] overflow-y-auto p-1.5">{snapshotsLoading ? <p className="p-4 text-xs text-enterprise-subtext">Loading snapshots…</p> : snapshotsError ? <p className="p-4 text-xs text-rose-300">Snapshot history could not be loaded.</p> : snapshots.length ? snapshots.map((snapshot) => <button key={snapshot.snapshot_id} type="button" onClick={() => { if (snapshot.is_current) exitSnapshot(); else selectSnapshot(snapshot.snapshot_id); setShowSnapshots(false); }} className={`block w-full rounded-lg px-3 py-2.5 text-left hover:bg-enterprise-bg ${snapshotId === snapshot.snapshot_id ? 'bg-amber-400/10' : ''}`}><span className="flex items-center justify-between gap-2"><code className="font-mono text-xs font-bold text-white">{snapshot.snapshot_id}</code><span className="flex items-center gap-1 text-[10px] text-emerald-300">{snapshot.is_current ? 'Current · live' : snapshot.status}{snapshotId === snapshot.snapshot_id && <Check className="h-3 w-3" />}</span></span><span className="mt-1 block text-[10px] text-enterprise-subtext">{new Date(snapshot.published_at).toLocaleString()} · {Object.values(snapshot.resource_counts || {}).reduce((a, b) => a + (Number(b) || 0), 0)} resources</span><span className="mt-1 block text-[10px] leading-relaxed text-enterprise-subtext">{getSnapshotRegionSummary(snapshot.regions || {})}</span></button>) : <p className="p-4 text-xs text-enterprise-subtext">No retained snapshots are available yet.</p>}</div>{snapshotId && <button type="button" onClick={() => { exitSnapshot(); setShowSnapshots(false); }} className="w-full border-t border-enterprise-border px-3 py-2.5 text-left text-xs font-semibold text-amber-200 hover:bg-amber-400/10">Exit historical view and return to live data</button>}</div>}
        </div>
        {!snapshotId && !isDashboard && isScanning ? (
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
        ) : !snapshotId && !isDashboard && (hasCompletedSnapshot || scanJustCompleted) ? (
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
