import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertCircle,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { useScanDataRefresh } from '../hooks/useScanDataRefresh';

const PHASE_LABELS: Record<string, { label: string; detail: string }> = {
  discovery: {
    label: 'Discovery',
    detail: 'Collecting AWS resources & IAM entities',
  },
  iam_analysis: {
    label: 'IAM Analysis',
    detail: 'Resolving AWS-managed policy documents & permissions',
  },
  graph_construction: {
    label: 'Graph Construction',
    detail: 'Building identity & resource relationship graph',
  },
  path_analysis: {
    label: 'Attack Path Analysis',
    detail: 'Analyzing privilege escalation paths & lateral movement',
  },
  cloudtrail_correlation: {
    label: 'CloudTrail Correlation',
    detail: 'Correlating runtime CloudTrail events & activities',
  },
  finding_synthesis: {
    label: 'Finding Synthesis',
    detail: 'Synthesizing posture assessment findings & risks',
  },
};

const formatSeconds = (sec: number): string => {
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
};

const formatDurationFriendly = (sec: number): string => {
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  if (m === 0) return `${s}s`;
  return `${m}m ${s}s`;
};

export const ScanTrigger: React.FC = () => {
  const {
    scanStatus,
    isScanning,
    scanJustCompleted,
    scanError,
    activePhase,
    elapsedSeconds,
    completedCollectors,
    totalCollectors,
    collectorStatus,
    progressSecondsAgo,
    hasProgressWarning,
    progressWarningText,
    lastPublishedScanId,
    lastPublishedAt,
    lastSuccessfulScanAt,
    lastSuccessfulScanId,
    isPartial,
    isFailed,
    failedRegions,
    triggerScan,
    manualTriggerNotice,
  } = useScanDataRefresh();

  const [expanded, setExpanded] = useState(false);

  const phaseInfo = activePhase ? PHASE_LABELS[activePhase] || { label: activePhase, detail: 'In progress' } : null;
  const snapshotDisplayId = (lastPublishedScanId || lastSuccessfulScanId || scanStatus?.scan_id || '').slice(0, 8);
  const currentScanShortId = (scanStatus?.scan_id || '').slice(0, 8);

  const durationSec = scanStatus?.last_result?.duration_seconds ?? elapsedSeconds;
  const resourcesFound = scanStatus?.resources_discovered ?? scanStatus?.last_result?.resources ?? 0;
  const risksFound = scanStatus?.last_result?.risks ?? 0;

  return (
    <div className="relative inline-flex flex-col items-end">
      <div className="flex items-center gap-2">
        {/* Main Trigger Button */}
        <button
          disabled={isScanning}
          onClick={triggerScan}
          title={
            scanError
              ? `Error: ${scanError}`
              : lastSuccessfulScanAt
                ? `Last successful scan: ${new Date(lastSuccessfulScanAt).toLocaleTimeString()}`
                : undefined
          }
          className={`relative flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
            scanError
              ? 'bg-enterprise-critical/20 text-enterprise-critical border border-enterprise-critical/30 hover:bg-enterprise-critical/30'
              : scanJustCompleted
                ? 'bg-enterprise-success/20 text-enterprise-success border border-enterprise-success/30'
                : isScanning
                  ? 'bg-blue-600/15 text-blue-300 border border-blue-500/30 cursor-wait'
                  : 'bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 border border-blue-500/30 shadow-sm'
          }`}
        >
          {scanError ? (
            <AlertCircle className="w-3.5 h-3.5 shrink-0" />
          ) : scanJustCompleted ? (
            <CheckCircle2 className="w-3.5 h-3.5 shrink-0 text-enterprise-success" />
          ) : isScanning ? (
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
          ) : (
            <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
          )}

          <span className="font-semibold">
            {scanError
              ? 'Scan Failed'
              : manualTriggerNotice
                ? manualTriggerNotice
                : scanJustCompleted
                  ? isPartial
                    ? 'Scan Partial'
                    : 'Scan Complete!'
                  : isScanning
                    ? `Scanning (${formatSeconds(elapsedSeconds)})`
                    : 'Scan Again'}
          </span>
        </button>

        {/* Expand / Details toggle button during scan or completed view */}
        {(isScanning || scanJustCompleted || expanded) && (
          <button
            onClick={() => setExpanded(!expanded)}
            className="p-1 rounded-md text-gray-400 hover:text-white hover:bg-gray-800/60 border border-enterprise-border text-xs transition-colors"
            title="Toggle scan observability details"
          >
            {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        )}
      </div>

      {/* Live Scan Observability Bar (Requirement 21, 22, 23, 24) */}
      {isScanning && (
        <div className="mt-2 w-72 sm:w-80 bg-enterprise-card/95 backdrop-blur border border-blue-500/30 rounded-xl p-3 shadow-xl text-left text-xs z-30">
          <div className="flex items-center justify-between pb-2 border-b border-enterprise-border/60">
            <span className="font-semibold text-white flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-blue-400 animate-ping" />
              Scanning AWS
            </span>
            <span className="font-mono text-blue-400 font-medium">
              {formatSeconds(elapsedSeconds)}
            </span>
          </div>

          <div className="mt-2 space-y-1.5">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-enterprise-subtext">Phase:</span>
              <span className="font-medium text-white">{phaseInfo?.label || 'Initializing'}</span>
            </div>

            {activePhase === 'discovery' && (
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-enterprise-subtext">Collectors:</span>
                <span className="font-mono text-enterprise-accent">
                  {completedCollectors} / {totalCollectors}
                </span>
              </div>
            )}

            <p className="text-[11px] text-gray-300 italic pt-0.5 leading-tight">
              {phaseInfo?.detail}
            </p>

            {/* Baseline snapshot indicator (Requirement 22) */}
            <div className="pt-2 border-t border-enterprise-border/40 text-[10px] text-gray-400 space-y-0.5">
              {lastPublishedAt && (
                <div>
                  Showing snapshot from {new Date(lastPublishedAt).toLocaleTimeString()}
                </div>
              )}
              {currentScanShortId && (
                <div className="text-blue-300">
                  Updating from scan {currentScanShortId}...
                </div>
              )}
            </div>

            {/* Heartbeat / Progress check (Requirement 24, 25) */}
            <div className="pt-1 text-[10px]">
              {hasProgressWarning ? (
                <div className="flex items-start gap-1 text-amber-400">
                  <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />
                  <span>{progressWarningText}</span>
                </div>
              ) : progressSecondsAgo !== null ? (
                <span className="text-gray-400">
                  Last progress {progressSecondsAgo}s ago
                </span>
              ) : null}
            </div>

            {/* Expanded collector list */}
            {expanded && collectorStatus && (
              <div className="mt-2 pt-2 border-t border-enterprise-border/50 max-h-36 overflow-y-auto space-y-1">
                <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider block">
                  Collectors:
                </span>
                <div className="grid grid-cols-2 gap-1 text-[10px]">
                  {Object.entries(collectorStatus).map(([name, status]) => (
                    <div key={name} className="flex items-center justify-between bg-enterprise-bg/60 px-1.5 py-0.5 rounded border border-enterprise-border/40">
                      <span className="text-gray-300 truncate max-w-[80px]">{name}</span>
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
      )}

      {/* Completion Banner (Requirement 23) */}
      {scanJustCompleted && !isScanning && (
        <div className="mt-2 w-72 sm:w-80 bg-enterprise-card/95 backdrop-blur border border-enterprise-success/30 rounded-xl p-3 shadow-xl text-left text-xs z-30">
          <div className="flex items-center justify-between pb-1.5 border-b border-enterprise-border/60">
            <span className="font-semibold text-enterprise-success flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              {isPartial ? 'Scan completed partially' : '✓ Scan completed'}
            </span>
            <span className="font-mono text-gray-300 text-[11px]">
              {formatDurationFriendly(durationSec)}
            </span>
          </div>

          <div className="mt-2 text-[11px] space-y-1">
            <div className="flex justify-between text-gray-300">
              <span className="text-enterprise-subtext">Snapshot:</span>
              <span className="font-mono text-enterprise-accent">{snapshotDisplayId || 'Active'}</span>
            </div>
            {resourcesFound > 0 && (
              <div className="flex justify-between text-gray-300">
                <span className="text-enterprise-subtext">Resources:</span>
                <span className="font-mono text-white">{resourcesFound}</span>
              </div>
            )}
            {risksFound > 0 && (
              <div className="flex justify-between text-gray-300">
                <span className="text-enterprise-subtext">Risks:</span>
                <span className="font-mono text-amber-400">{risksFound}</span>
              </div>
            )}
            {isPartial && failedRegions.length > 0 && (
              <div className="pt-1 text-[10px] text-amber-400">
                Unavailable regions: {failedRegions.join(', ')}
              </div>
            )}
            <div className="text-[10px] text-gray-400 pt-1">
              Updated to scan {snapshotDisplayId}
            </div>
          </div>
        </div>
      )}

      {/* Failure banner (Requirement 19) */}
      {isFailed && !isScanning && scanError && (
        <div className="mt-2 w-72 sm:w-80 bg-enterprise-card/95 backdrop-blur border border-enterprise-critical/30 rounded-xl p-3 shadow-xl text-left text-xs z-30">
          <div className="flex items-center gap-1.5 text-enterprise-critical font-semibold pb-1.5 border-b border-enterprise-border/60">
            <AlertCircle className="w-3.5 h-3.5 shrink-0" />
            <span>Latest scan failed</span>
          </div>
          <p className="text-[11px] text-gray-300 mt-1.5">
            Showing last completed snapshot{lastSuccessfulScanAt ? ` from ${new Date(lastSuccessfulScanAt).toLocaleTimeString()}` : ''}.
          </p>
          <p className="text-[10px] text-red-400 font-mono mt-1 truncate">
            {scanError}
          </p>
        </div>
      )}
    </div>
  );
};

// Export useScanTrigger alias for backwards compatibility if needed elsewhere
export const useScanTrigger = () => {
  const {
    isScanning,
    scanJustCompleted,
    scanError,
    lastSuccessfulScanAt,
    triggerScan,
  } = useScanDataRefresh();

  return {
    isScanning,
    scanSuccess: scanJustCompleted,
    scanError,
    lastSuccessfulScanAt,
    handleScanClick: triggerScan,
  };
};
