import React, { useState } from 'react';
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { useScanLifecycle } from '../hooks/useScanLifecycle.ts';

export const GlobalScanStatus: React.FC = () => {
  const {
    isScanning,
    scanJustCompleted,
    scanError,
    activePhase,
    phaseDescription,
    elapsedFormatted,
    completedCollectors,
    totalCollectors,
    collectorStatus,
    publicationState,
    hasProgressWarning,
    progressWarningText,
    currentSnapshotId,
    newScanId,
    isPartial,
    isFailed,
    failedRegions,
    manualTriggerLoading,
  } = useScanLifecycle();

  const [showCollectors, setShowCollectors] = useState(false);

  const currentShort = currentSnapshotId ? currentSnapshotId.slice(0, 8) : null;
  const newShort = newScanId ? newScanId.slice(0, 8) : null;
  const isInitializing = (activePhase || '').toUpperCase() === 'INITIALIZING';

  const safeTotal = totalCollectors > 0 ? totalCollectors : 12;
  const safeCompleted = Math.min(safeTotal, Math.max(0, completedCollectors));
  const progressPct = Math.round((safeCompleted / safeTotal) * 100);

  // 0. CONNECTING STATE BEFORE BACKEND ARRIVES
  if (manualTriggerLoading && !isScanning) {
    return (
      <div className="bg-enterprise-card/95 border border-blue-500/30 rounded-xl px-4 py-3 shadow-lg text-xs w-full transition-all flex items-center gap-3">
        <svg
          className="animate-spin w-4 h-4 shrink-0 text-blue-400"
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
        <span className="text-gray-200 font-medium">Connecting to CloudScope AWS Scan Coordinator...</span>
      </div>
    );
  }

  // 1. ACTIVE SCANNING STATE (Full-width executive status banner)
  if (isScanning) {
    const collectorKeys = Object.keys(collectorStatus || {});

    return (
      <div className="bg-enterprise-card/95 border border-blue-500/40 rounded-2xl p-4 shadow-xl text-xs w-full transition-all space-y-3">
        {/* Top row: Status, Phase & Live Timer */}
        <div className="flex flex-wrap items-center justify-between gap-3 pb-2 border-b border-enterprise-border/60">
          <div className="flex items-center gap-2.5 min-w-0">
            <span className="relative flex h-3 w-3 shrink-0">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-3 w-3 bg-blue-500" />
            </span>
            <div>
              <span className="font-bold text-white text-sm">Scanning AWS Cloud Infrastructure</span>
              <span className="text-enterprise-subtext text-xs ml-2">
                — {phaseDescription}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {newShort && (
              <span className="font-mono text-gray-400 text-xs bg-gray-800/80 px-2 py-0.5 rounded border border-gray-700/60">
                Scan ID: <strong className="text-blue-300">{newShort}</strong>
              </span>
            )}
            <span className="font-mono text-blue-400 font-bold bg-blue-950/60 border border-blue-500/30 px-3 py-1 rounded-lg text-sm">
              {elapsedFormatted}
            </span>
          </div>
        </div>

        {/* Progress Bar & Collector Metrics */}
        <div className="space-y-1.5">
          <div className="flex justify-between items-center text-[11px] text-gray-300">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-enterprise-subtext">Collector Pipeline:</span>
              {isInitializing ? (
                <span className="text-blue-300 font-medium">AWS Authentication & Regional Discovery</span>
              ) : (
                <span className="text-white font-mono font-medium">{safeCompleted} / {safeTotal} collectors ({progressPct}%)</span>
              )}
            </div>

            <div className="flex items-center gap-3">
              {currentShort && (
                <span className="text-[10px] text-gray-400">
                  Current: <strong className="text-gray-300 font-mono">{currentShort}</strong>
                </span>
              )}
              <span className="text-[10px] text-gray-400">
                Status: <strong className="text-blue-300 font-mono">{publicationState}</strong>
              </span>
              <button
                type="button"
                onClick={() => setShowCollectors(!showCollectors)}
                className="text-[11px] text-blue-400 hover:text-blue-300 inline-flex items-center gap-1 font-semibold transition-colors cursor-pointer"
              >
                <span>{showCollectors ? 'Hide Details' : 'View Collectors'}</span>
                {showCollectors ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          {/* Visual Progress Bar */}
          <div className="w-full bg-gray-800/80 rounded-full h-2 overflow-hidden border border-gray-700/40">
            <div
              className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 rounded-full transition-all duration-300"
              style={{ width: `${Math.max(5, progressPct)}%` }}
            />
          </div>
        </div>

        {/* Heartbeat warning if any */}
        {hasProgressWarning && (
          <div className="flex items-center gap-1.5 text-amber-400 text-xs bg-amber-500/10 border border-amber-500/20 px-3 py-1.5 rounded-lg">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            <span>{progressWarningText}</span>
          </div>
        )}

        {/* Collapsible Collector Status Grid */}
        {showCollectors && collectorKeys.length > 0 && (
          <div className="pt-2 border-t border-enterprise-border/60">
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2 pt-1">
              {Object.entries(collectorStatus).map(([name, status]) => {
                const isSuccess = status.includes('SUCCESS');
                const isFail = status.includes('FAILED');
                const isRunning = status === 'RUNNING';
                return (
                  <div
                    key={name}
                    className="p-2 rounded-lg bg-enterprise-bg/60 border border-enterprise-border/60 text-[10px] flex justify-between items-center"
                  >
                    <span className="text-gray-300 font-medium truncate" title={name}>{name}</span>
                    <span className={`px-1.5 py-0.2 rounded font-mono font-bold text-[9px] ${
                      isSuccess ? 'text-emerald-400 bg-emerald-500/10' :
                      isFail ? 'text-rose-400 bg-rose-500/10' :
                      isRunning ? 'text-blue-400 bg-blue-500/10 animate-pulse' :
                      'text-gray-400 bg-gray-800'
                    }`}>
                      {status}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    );
  }

  // 2. JUST COMPLETED STATE
  if (scanJustCompleted) {
    return (
      <div className={`border rounded-2xl p-3.5 shadow-lg text-xs w-full transition-all ${
        isPartial
          ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
          : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
      }`}>
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            {isPartial ? (
              <AlertTriangle className="w-5 h-5 shrink-0 text-amber-400" />
            ) : (
              <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-400" />
            )}
            <div>
              <p className="font-bold text-white text-xs">
                {isPartial ? 'Scan completed with regional warnings' : 'Scan published successfully'}
              </p>
              <p className="text-[11px] text-gray-300 mt-0.5">
                Authoritative snapshot <span className="font-mono text-white font-semibold">{currentShort || 'updated'}</span> is active.
                {failedRegions.length > 0 ? ` (failed regions: ${failedRegions.join(', ')})` : ''}
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // 3. ERROR / FAILED STATE
  if (scanError || isFailed) {
    return (
      <div className="bg-rose-500/10 border border-rose-500/30 rounded-2xl p-3.5 shadow-lg text-xs w-full">
        <div className="flex items-center gap-2.5">
          <AlertCircle className="w-5 h-5 shrink-0 text-rose-400" />
          <div className="min-w-0 flex-1">
            <p className="font-bold text-rose-300">Scan execution failed</p>
            <p className="text-[11px] text-gray-300 mt-0.5" title={scanError || undefined}>
              {scanError || 'Prior published snapshot ' + (currentShort || 'none') + ' remains active.'}
            </p>
          </div>
        </div>
      </div>
    );
  }

  return null;
};
