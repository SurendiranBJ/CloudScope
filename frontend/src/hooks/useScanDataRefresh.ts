import { useEffect, useRef, useState, useCallback, useMemo } from 'react';
import { useQuery, useQueryClient, QueryClient } from '@tanstack/react-query';
import { getScanStatus, triggerScan as apiTriggerScan, type ScanStatus } from '../api/graph.ts';

export const SCAN_DEPENDENT_QUERY_KEYS = [
  ['dashboardSummary'],
  ['graphElements'],
  ['cloudResources'],
  ['attackPaths'],
  ['riskAssessmentFindings'],
  ['iamUsers'],
  ['iamRoles'],
  ['iamPolicies'],
  ['policies'],
  ['relationships'],
  ['scanStatus'],
];

/**
 * Refetches all active scan-dependent queries in the React Query cache.
 * Uses queryClient.refetchQueries to ensure authoritative replacement.
 */
export const refreshScanDependentQueries = async (queryClient: QueryClient) => {
  for (const queryKey of SCAN_DEPENDENT_QUERY_KEYS) {
    try {
      await queryClient.refetchQueries({ queryKey, type: 'active' });
    } catch {
      // Invalidation fallback if refetch fails
      await queryClient.invalidateQueries({ queryKey });
    }
  }
};

export interface UseScanDataRefreshOptions {
  onCompleted?: (status: ScanStatus) => void;
  entityName?: string; // e.g. "Policy catalog" or "Relationships"
}

export const useScanDataRefresh = (options: UseScanDataRefreshOptions = {}) => {
  const queryClient = useQueryClient();
  const [scanJustCompleted, setScanJustCompleted] = useState(false);
  const [manualTriggerLoading, setManualTriggerLoading] = useState(false);
  const [manualTriggerNotice, setManualTriggerNotice] = useState<string | null>(null);
  const [manualError, setManualError] = useState<string | null>(null);

  const lastProcessedPublishedIdRef = useRef<string | null>(null);
  const wasScanningRef = useRef<boolean>(false);
  const clearTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const noticeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Single shared polling query across the entire frontend
  const { data: scanStatus } = useQuery<ScanStatus>({
    queryKey: ['scanStatus'],
    queryFn: getScanStatus,
    refetchInterval: (query) => {
      const data = query.state.data;
      // 2 seconds while scanning, 7 seconds while idle
      return data?.is_scanning ? 2000 : 7000;
    },
    staleTime: 1500,
  });

  const isScanning = !!(scanStatus?.is_scanning || manualTriggerLoading);
  const currentPublishedId = scanStatus?.last_published_scan_id || scanStatus?.last_successful_scan_id || scanStatus?.last_completed_scan_id || null;
  const scanState = (
    scanStatus?.scan_status ||
    scanStatus?.last_result?.scan_status ||
    scanStatus?.last_result?.status ||
    ''
  ).toUpperCase();

  const isPartial = scanState === 'PARTIAL';
  const isFailed = scanState === 'FAILED';
  const isSuccess = scanState === 'SUCCESS';

  const triggerCompletion = useCallback((status: ScanStatus) => {
    refreshScanDependentQueries(queryClient);

    setScanJustCompleted(true);
    setManualError(null);
    if (clearTimerRef.current) clearTimeout(clearTimerRef.current);
    clearTimerRef.current = setTimeout(() => {
      setScanJustCompleted(false);
    }, 6000);

    if (options.onCompleted) {
      options.onCompleted(status);
    }
  }, [queryClient, options]);

  useEffect(() => {
    if (!scanStatus) return;

    // Initialize baseline published id on first mount without triggering refresh
    if (lastProcessedPublishedIdRef.current === null && currentPublishedId) {
      lastProcessedPublishedIdRef.current = currentPublishedId;
      wasScanningRef.current = !!scanStatus.is_scanning;
      return;
    }

    // Detect scan completion or new snapshot published
    const finishedScanning = wasScanningRef.current && !scanStatus.is_scanning;
    const newSnapshotPublished = (
      currentPublishedId !== null &&
      currentPublishedId !== lastProcessedPublishedIdRef.current
    );

    if (finishedScanning || newSnapshotPublished) {
      if (currentPublishedId) {
        lastProcessedPublishedIdRef.current = currentPublishedId;
      }

      // Handle SUCCESS and PARTIAL: refresh all scan-dependent data
      if (isSuccess || isPartial || newSnapshotPublished) {
        triggerCompletion(scanStatus);
      } else if (isFailed) {
        // FAILED: Do NOT invalidate good data; only keep scanStatus up to date
        queryClient.refetchQueries({ queryKey: ['scanStatus'], type: 'active' });
      }
    }

    wasScanningRef.current = !!scanStatus.is_scanning;
  }, [scanStatus, currentPublishedId, isSuccess, isPartial, isFailed, triggerCompletion, queryClient]);

  // Manual scan trigger handler
  const handleTriggerScan = useCallback(async () => {
    if (isScanning) return;
    setManualTriggerLoading(true);
    setManualError(null);

    // Optimistically update query client so UI reacts immediately
    queryClient.setQueryData<ScanStatus>(['scanStatus'], (old) => ({
      ...(old || { started_at: new Date().toISOString(), last_result: null }),
      is_scanning: true,
      scan_status: 'SCANNING',
      active_phase: 'discovery',
      elapsed_seconds: 0,
    }));

    try {
      const res = await apiTriggerScan();
      if (res?.status === 'already_running') {
        setManualTriggerNotice('Scan already running');
      } else {
        setManualTriggerNotice('Scan started');
      }
      if (noticeTimerRef.current) clearTimeout(noticeTimerRef.current);
      noticeTimerRef.current = setTimeout(() => setManualTriggerNotice(null), 4000);

      // Immediately poll scan status to sync authoritative backend state
      await queryClient.refetchQueries({ queryKey: ['scanStatus'], type: 'active' });
    } catch (err: any) {
      const msg = err?.response?.data?.message || err?.message || 'Failed to start scan';
      setManualError(msg);
      // Revert/sync with backend
      await queryClient.refetchQueries({ queryKey: ['scanStatus'], type: 'active' });
    } finally {
      setManualTriggerLoading(false);
    }
  }, [isScanning, queryClient]);

  // Heartbeat & progress warning detection
  const now = Date.now();
  const lastProgressAt = scanStatus?.last_progress_at || null;
  const progressSecondsAgo = useMemo(() => {
    if (!lastProgressAt) return null;
    try {
      const diff = Math.floor((now - new Date(lastProgressAt).getTime()) / 1000);
      return Math.max(0, diff);
    } catch {
      return null;
    }
  }, [lastProgressAt, now]);

  const hasProgressWarning = isScanning && progressSecondsAgo !== null && progressSecondsAgo > 60;
  const progressWarningText = hasProgressWarning
    ? 'Scan is still running, but this phase has not reported progress recently.'
    : null;

  useEffect(() => {
    return () => {
      if (clearTimerRef.current) clearTimeout(clearTimerRef.current);
      if (noticeTimerRef.current) clearTimeout(noticeTimerRef.current);
    };
  }, []);

  const scanError = manualError || (isFailed ? (scanStatus?.last_error || 'Scan failed') : null);

  return {
    scanStatus,
    isScanning,
    scanJustCompleted,
    scanError,
    activePhase: scanStatus?.active_phase ?? null,
    elapsedSeconds: scanStatus?.elapsed_seconds ?? 0,
    completedCollectors: scanStatus?.completed_collectors ?? 0,
    totalCollectors: scanStatus?.total_collectors ?? 12,
    collectorStatus: scanStatus?.collector_status ?? {},
    lastProgressAt,
    progressSecondsAgo,
    hasProgressWarning,
    progressWarningText,
    lastPublishedScanId: scanStatus?.last_published_scan_id ?? null,
    lastPublishedAt: scanStatus?.last_published_at ?? null,
    lastCompletedAt: scanStatus?.last_completed_scan_at || scanStatus?.last_successful_scan_at || null,
    lastSuccessfulScanAt: scanStatus?.last_successful_scan_at ?? null,
    lastSuccessfulScanId: scanStatus?.last_successful_scan_id ?? null,
    hasCompletedSnapshot: !!(scanStatus?.last_published_scan_id || scanStatus?.last_successful_scan_id || scanStatus?.last_completed_scan_id),
    isPartial,
    isFailed,
    isSuccess,
    failedRegions: scanStatus?.failed_regions ?? [],
    successfulRegions: scanStatus?.successful_regions ?? [],
    scheduledInterval: scanStatus?.scheduled_scan_interval_minutes ?? 5,
    nextScheduledScanAt: scanStatus?.next_scheduled_scan_at ?? null,
    triggerScan: handleTriggerScan,
    manualTriggerNotice,
    refreshAll: () => refreshScanDependentQueries(queryClient),
  };
};
