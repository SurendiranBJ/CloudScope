import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { useScanLifecycle } from '../hooks/useScanLifecycle';

export const GlobalScanStatus: React.FC = () => {
  const {
    isScanning,
    scanJustCompleted,
    scanError,
    phaseDescription,
    elapsedFormatted,
    completedCollectors,
    totalCollectors,
    collectorStatus,
    progressSecondsAgo,
    hasProgressWarning,
    progressWarningText,
    currentSnapshotId,
    newScanId,
    lastPublishedAt,
    isPartial,
    isFailed,
    failedRegions,
    manualTriggerLoading,
  } = useScanLifecycle();

  const [showCollectors, setShowCollectors] = useState(false);

  const currentShort = currentSnapshotId ? currentSnapshotId.slice(0, 8) : null;
  const newShort = newScanId ? newScanId.slice(0, 8) : null;

  // 0. CONNECTING STATE BEFORE BACKEND ARRIVES (Requirement 10)
  if (manualTriggerLoading && !isScanning) {
    return (
      <div className="bg-enterprise-card/95 border border-blue-500/30 rounded-xl px-3.5 py-2.5 shadow-lg text-xs w-full sm:max-w-xs min-w-0 transition-all flex items-center gap-2">
        <svg
          className="animate-spin w-3.5 h-3.5 shrink-0 text-blue-400"
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
        <span className="text-gray-300 font-medium">Connecting to scan service...</span>
      </div>
    );
  }

  // 1. ACTIVE SCANNING STATE (Compact, responsive card)
  if (isScanning) {
    return (
      <div className="bg-enterprise-card/95 border border-blue-500/30 rounded-xl px-3.5 py-2.5 shadow-lg text-xs w-full sm:max-w-md min-w-0 transition-all">
        {/* Top row: Title + Elapsed Timer */}
        <div className="flex items-center justify-between gap-2 pb-1.5 border-b border-enterprise-border/50">
          <div className="flex items-center gap-2 min-w-0">
            <span className="relative flex h-2.5 w-2.5 shrink-0">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-blue-500" />
            </span>
            <span className="font-semibold text-white truncate">Scanning AWS</span>
          </div>
          <span className="font-mono text-blue-400 font-bold shrink-0 text-[13px]">
            {elapsedFormatted}
          </span>
        </div>

        {/* Middle details: Phase + Collector counter */}
        <div className="mt-1.5 space-y-1">
          <div className="flex items-center justify-between gap-2 text-[11px]">
            <span className="text-enterprise-subtext shrink-0">Phase:</span>
            <span className="font-medium text-blue-200 truncate text-right">
              {phaseDescription}
            </span>
          </div>

          <div className="flex items-center justify-between gap-2 text-[11px]">
            <div className="flex items-center gap-1.5 text-enterprise-subtext shrink-0">
              <span>Progress:</span>
              <button
                type="button"
                onClick={() => setShowCollectors(!showCollectors)}
                className="text-[10px] text-gray-400 hover:text-white inline-flex items-center gap-0.5 underline transition-colors"
                title="Toggle collector details"
              >
                <span>{completedCollectors} / {totalCollectors} collectors</span>
                {showCollectors ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </button>
            </div>
            {newShort && (
              <span className="font-mono text-gray-400 text-[10px] shrink-0">
                Scan: {newShort}
              </span>
            )}
          </div>

          {/* Current snapshot & active scan ID (Requirement 12) */}
          <div className="flex items-center justify-between text-[10px] text-gray-400 pt-0.5 gap-2">
            {currentShort && (
              <span className="truncate">
                Current snapshot: <span className="font-mono text-gray-300">{currentShort}</span>
              </span>
            )}
            {newShort && (
              <span className="truncate text-blue-300 text-right">
                Updating: <span className="font-mono font-medium">{newShort}</span>
              </span>
            )}
          </div>

          {/* Heartbeat / Progress check */}
          <div className="text-[10px] pt-0.5">
            {hasProgressWarning ? (
              <div className="flex items-start gap-1 text-amber-400">
                <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />
                <span className="truncate">{progressWarningText}</span>
              </div>
            ) : progressSecondsAgo !== null ? (
              <span className="text-gray-400">
                Last progress {progressSecondsAgo}s ago
              </span>
            ) : null}
          </div>

          {/* Optional expandable collectors drawer */}
          {showCollectors && collectorStatus && (
            <div className="mt-2 pt-2 border-t border-enterprise-border/50 max-h-32 overflow-y-auto space-y-1">
              <div className="grid grid-cols-2 gap-1 text-[10px]">
                {Object.entries(collectorStatus).map(([name, status]) => (
                  <div
                    key={name}
                    className="flex items-center justify-between bg-enterprise-bg/60 px-1.5 py-0.5 rounded border border-enterprise-border/40"
                  >
                    <span className="text-gray-300 truncate max-w-[85px]">{name}</span>
                    <span
                      className={`font-mono text-[9px] ${
                        status.startsWith('SUCCESS')
                          ? 'text-green-400'
                          : status === 'RUNNING'
                            ? 'text-blue-400 animate-pulse'
                            : status === 'FAILED'
                              ? 'text-red-400'
                              : 'text-gray-400'
                      }`}
                    >
                      {status === 'SUCCESS_WITH_DATA' ? 'DATA' : status === 'SUCCESS_EMPTY' ? 'EMPTY' : status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  // 2. JUST COMPLETED STATE
  if (scanJustCompleted) {
    return (
      <div className={`border rounded-xl px-3 py-2 shadow-md text-xs w-full sm:max-w-xs min-w-0 transition-all ${
        isPartial
          ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
          : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
      }`}>
        <div className="flex items-center gap-2">
          {isPartial ? (
            <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400" />
          ) : (
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
          )}
          <div className="min-w-0 flex-1">
            <p className="font-semibold text-white truncate">
              {isPartial ? 'Scan completed with regional failures' : 'Scan completed'}
            </p>
            <p className="text-[10px] text-gray-300 truncate">
              Snapshot: <span className="font-mono">{currentShort || 'published'}</span>
              {failedRegions.length > 0 ? ` (failed: ${failedRegions.join(', ')})` : ''}
            </p>
          </div>
        </div>
      </div>
    );
  }

  // 3. ERROR / FAILED STATE
  if (scanError || isFailed) {
    return (
      <div className="bg-red-500/10 border border-red-500/30 rounded-xl px-3 py-2 shadow-md text-xs w-full sm:max-w-xs min-w-0">
        <div className="flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
          <div className="min-w-0 flex-1">
            <p className="font-semibold text-red-300 truncate">Scan failed</p>
            <p className="text-[10px] text-gray-300 truncate">
              Showing last snapshot: <span className="font-mono">{currentShort || 'none'}</span>
            </p>
          </div>
        </div>
      </div>
    );
  }

  // 4. IDLE STATE WITH SNAPSHOT (Compact status chip)
  if (currentShort) {
    return (
      <div className="hidden md:flex items-center gap-2.5 bg-enterprise-card/60 border border-enterprise-border/60 rounded-xl px-3 py-1.5 text-xs text-gray-300">
        <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
        <div className="text-[11px] leading-tight">
          <span className="text-gray-400">Snapshot:</span>{' '}
          <span className="font-mono text-white font-medium">{currentShort}</span>
          {lastPublishedAt && (
            <span className="text-gray-400 text-[10px] ml-1.5">
              ({new Date(lastPublishedAt).toLocaleTimeString()})
            </span>
          )}
        </div>
      </div>
    );
  }

  return null;
};
