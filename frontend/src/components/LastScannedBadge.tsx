import React, { useState, useEffect, useMemo } from 'react';
import { Clock, AlertTriangle, ShieldCheck, RefreshCw } from 'lucide-react';
import { useScanLifecycle } from '../hooks/useScanLifecycle.ts';

export const formatRelativeTime = (isoString?: string | null, nowMs: number = Date.now()): string => {
  if (!isoString) return '';
  try {
    const time = new Date(isoString).getTime();
    if (isNaN(time)) return '';
    const diffSeconds = Math.max(0, Math.floor((nowMs - time) / 1000));
    if (diffSeconds < 45) return 'just now';
    const diffMinutes = Math.floor(diffSeconds / 60);
    if (diffMinutes < 60) return `${diffMinutes}m ago`;
    const diffHours = Math.floor(diffMinutes / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  } catch {
    return '';
  }
};

export const formatTimeDisplay = (isoString?: string | null): string => {
  if (!isoString) return 'Never';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return 'Never';
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return 'Never';
  }
};

export interface LastScannedBadgeProps {
  className?: string;
  showSnapshotId?: boolean;
}

export const LastScannedBadge: React.FC<LastScannedBadgeProps> = ({
  className = '',
  showSnapshotId = true,
}) => {
  const {
    lastPublishedAt,
    lastCompletedAt,
    lastSuccessfulScanAt,
    currentSnapshotId,
    isPartial,
    failedRegions,
    isScanning,
  } = useScanLifecycle();

  // Authoritative timestamp priority: last_published_at || last_completed_at || last_successful_scan_at
  const authoritativeTime = lastPublishedAt || lastCompletedAt || lastSuccessfulScanAt || null;

  // Lightweight 30s interval for relative time rendering
  const [nowMs, setNowMs] = useState(Date.now());
  useEffect(() => {
    const interval = setInterval(() => setNowMs(Date.now()), 30_000);
    return () => clearInterval(interval);
  }, []);

  const relativeText = useMemo(() => {
    return formatRelativeTime(authoritativeTime, nowMs);
  }, [authoritativeTime, nowMs]);

  const timeFormatted = useMemo(() => {
    return formatTimeDisplay(authoritativeTime);
  }, [authoritativeTime]);

  const shortSnapshot = currentSnapshotId ? currentSnapshotId.slice(0, 8) : null;

  if (!authoritativeTime && !shortSnapshot) {
    return (
      <div
        className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border bg-enterprise-card border-enterprise-border text-gray-400 shadow-sm shrink-0 select-none ${className}`}
        title="No completed scan snapshot has been published yet"
      >
        <Clock className="w-3.5 h-3.5 text-gray-500 shrink-0" />
        <span>Last scanned: <span className="text-gray-300 font-medium">Never</span></span>
      </div>
    );
  }

  return (
    <div
      className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium border bg-enterprise-card border-enterprise-border text-gray-300 shadow-sm shrink-0 select-none transition-colors hover:border-gray-600 ${className}`}
      title={
        authoritativeTime
          ? `Snapshot captured: ${new Date(authoritativeTime).toLocaleString()}${
              shortSnapshot ? ` (ID: ${shortSnapshot})` : ''
            }${isPartial ? ` - Partial scan: ${failedRegions.join(', ')} failed` : ''}`
          : 'Published snapshot status'
      }
    >
      {isPartial ? (
        <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
      ) : isScanning ? (
        <RefreshCw className="w-3.5 h-3.5 text-blue-400 shrink-0 animate-spin" />
      ) : (
        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
      )}

      <div className="flex items-center gap-1.5">
        <span className="text-enterprise-subtext font-normal">Last scanned:</span>
        <span className="text-white font-semibold">{timeFormatted}</span>
        {relativeText && (
          <span className="text-gray-400 font-normal text-[11px]">({relativeText})</span>
        )}
      </div>

      {showSnapshotId && shortSnapshot && (
        <span className="hidden sm:inline-flex items-center gap-1 pl-1.5 border-l border-enterprise-border/60 text-gray-400 text-[11px] font-mono">
          <span className="text-enterprise-subtext font-sans">Snap:</span> {shortSnapshot}
        </span>
      )}

      {isPartial && (
        <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">
          Partial
        </span>
      )}

      {isScanning && (
        <span className="text-[10px] text-blue-300 font-normal animate-pulse">
          Updating...
        </span>
      )}
    </div>
  );
};
