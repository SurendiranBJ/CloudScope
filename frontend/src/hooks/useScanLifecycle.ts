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

export const PHASE_DESCRIPTIONS: Record<string, string> = {
  INITIALIZING: 'Preparing scan...',
  DISCOVERY: 'Collecting AWS inventory...',
  IAM_ANALYSIS: 'Evaluating IAM policies...',
  GRAPH_CONSTRUCTION: 'Building identity graph...',
  PATH_ANALYSIS: 'Analyzing attack paths...',
  CLOUDTRAIL_CORRELATION: 'Correlating CloudTrail activity...',
  FINDING_SYNTHESIS: 'Reconciling security findings...',
  PUBLISHING: 'Publishing new security snapshot...',
  COMPLETED: 'Scan completed',
  FAILED: 'Scan failed',
  PARTIAL: 'Scan completed with regional failures',
};

export const getPhaseDescription = (phase?: string | null, scanStatus?: string): string => {
  if (!phase && !scanStatus) return 'Ready';
  const normPhase = (phase || '').toUpperCase();
  if (PHASE_DESCRIPTIONS[normPhase]) {
    return PHASE_DESCRIPTIONS[normPhase];
  }
  const normStatus = (scanStatus || '').toUpperCase();
  if (normStatus === 'PARTIAL') return PHASE_DESCRIPTIONS.PARTIAL;
  if (normStatus === 'FAILED') return PHASE_DESCRIPTIONS.FAILED;
  if (normStatus === 'SUCCESS' || normStatus === 'COMPLETED') return PHASE_DESCRIPTIONS.COMPLETED;
  return normPhase ? normPhase.replace(/_/g, ' ') : 'Ready';
};

export const formatDuration = (seconds?: number): string => {
  if (seconds === undefined || seconds === null || isNaN(seconds)) return '00:00';
  const total = Math.max(0, Math.floor(seconds));
  const mins = Math.floor(total / 60);
  const secs = total % 60;
  return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
};

/**
 * Refetches all active scan-dependent queries in the React Query cache.
 */
export const refreshScanDependentQueries = async (queryClient: QueryClient) => {
  for (const queryKey of SCAN_DEPENDENT_QUERY_KEYS) {
    try {
      await queryClient.refetchQueries({ queryKey, type: 'active' });
    } catch {
      await queryClient.invalidateQueries({ queryKey });
    }
  }
};

export interface UseScanLifecycleOptions {
  onCompleted?: (status: ScanStatus) => void;
  entityName?: string;
}

export const useScanLifecycle = (options: UseScanLifecycleOptions = {}) => {
  const queryClient = useQueryClient();
  const [scanJustCompleted, setScanJustCompleted] = useState(false);
  const [manualTriggerLoading, setManualTriggerLoading] = useState(false);
  const [manualTriggerNotice, setManualTriggerNotice] = useState<string | null>(null);
  const [manualError, setManualError] = useState<string | null>(null);

  // Authoritative tracking of published snapshot ID to avoid duplicate refreshes
  const lastProcessedSnapshotIdRef = useRef<string | null>(null);
  const clearTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const noticeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // EXACTLY ONE React Query key ['scanStatus'] and polling mechanism across the entire frontend
  const { data: scanStatus } = useQuery<ScanStatus>({
    queryKey: ['scanStatus'],
    queryFn: getScanStatus,
    refetchInterval: (query) => {
      const data = query.state.data;
      // 2000ms while scanning, 7000ms while idle
      return data?.is_scanning ? 2000 : 7000;
    },
    staleTime: 1500,
  });

  const isScanning = !!(scanStatus?.is_scanning || manualTriggerLoading);
  const currentSnapshotId = (
    scanStatus?.snapshot_id ||
    scanStatus?.current_snapshot_id ||
    scanStatus?.last_published_scan_id ||
    scanStatus?.last_successful_scan_id ||
    scanStatus?.last_completed_scan_id ||
    null
  );
  const newScanId = scanStatus?.new_scan_id || (isScanning ? scanStatus?.scan_id : null) || null;
  const snapshotPublishedAt = scanStatus?.snapshot_published_at || scanStatus?.last_published_at || null;

  const rawState = (
    scanStatus?.scan_status ||
    scanStatus?.last_result?.scan_status ||
    scanStatus?.last_result?.status ||
    ''
  ).toUpperCase();

  const isPartial = rawState === 'PARTIAL';
  const isFailed = rawState === 'FAILED';
  const isSuccess = rawState === 'SUCCESS' || rawState === 'COMPLETED';

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

  // Section 15 & 16: Authoritative snapshot publication detection
  useEffect(() => {
    if (!scanStatus) return;

    // Baseline initialization on first load: do NOT refresh
    if (lastProcessedSnapshotIdRef.current === null) {
      if (currentSnapshotId) {
        lastProcessedSnapshotIdRef.current = currentSnapshotId;
      }
      return;
    }

    // Refresh ONLY when a new authoritative snapshot ID has been published
    if (currentSnapshotId && currentSnapshotId !== lastProcessedSnapshotIdRef.current) {
      lastProcessedSnapshotIdRef.current = currentSnapshotId;
      triggerCompletion(scanStatus);
    }
  }, [scanStatus, currentSnapshotId, triggerCompletion]);

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
      active_phase: 'INITIALIZING',
      elapsed_seconds: 0,
    }));

    try {
      const res = await apiTriggerScan();
      const statusUpper = (res?.status || '').toUpperCase();
      if (statusUpper === 'ALREADY_RUNNING') {
        setManualTriggerNotice('Scan already running');
      } else {
        setManualTriggerNotice('Scan started');
      }
      if (noticeTimerRef.current) clearTimeout(noticeTimerRef.current);
      noticeTimerRef.current = setTimeout(() => setManualTriggerNotice(null), 4000);

      // Immediately poll to sync authoritative backend scan ID & phase
      await queryClient.refetchQueries({ queryKey: ['scanStatus'], type: 'active' });
    } catch (err: any) {
      const msg = err?.response?.data?.message || err?.message || 'Failed to start scan';
      setManualError(msg);
      await queryClient.refetchQueries({ queryKey: ['scanStatus'], type: 'active' });
    } finally {
      setManualTriggerLoading(false);
    }
  }, [isScanning, queryClient]);

  // Progress heartbeat calculation
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!isScanning) return;
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, [isScanning]);

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
  const activePhase = (scanStatus?.active_phase || (isScanning ? 'INITIALIZING' : null));
  const phaseDescription = getPhaseDescription(activePhase, scanStatus?.scan_status);
  const elapsedSeconds = scanStatus?.elapsed_seconds ?? 0;
  const elapsedFormatted = formatDuration(elapsedSeconds);

  return {
    scanStatus,
    isScanning,
    scanJustCompleted,
    scanError,
    activePhase,
    phaseDescription,
    elapsedSeconds,
    elapsedFormatted,
    completedCollectors: scanStatus?.completed_collectors ?? 0,
    totalCollectors: scanStatus?.total_collectors ?? 12,
    collectorStatus: scanStatus?.collector_status ?? {},
    lastProgressAt,
    progressSecondsAgo,
    hasProgressWarning,
    progressWarningText,
    currentSnapshotId,
    newScanId,
    snapshotPublishedAt,
    lastPublishedScanId: scanStatus?.last_published_scan_id ?? currentSnapshotId,
    lastPublishedAt: scanStatus?.last_published_at ?? snapshotPublishedAt,
    lastCompletedAt: scanStatus?.last_completed_scan_at || scanStatus?.last_successful_scan_at || null,
    lastSuccessfulScanAt: scanStatus?.last_successful_scan_at ?? null,
    lastSuccessfulScanId: scanStatus?.last_successful_scan_id ?? null,
    hasCompletedSnapshot: !!currentSnapshotId,
    isPartial,
    isFailed,
    isSuccess,
    failedRegions: scanStatus?.failed_regions ?? [],
    successfulRegions: scanStatus?.successful_regions ?? [],
    scheduledInterval: scanStatus?.scheduled_scan_interval_minutes ?? 5,
    nextScheduledScanAt: scanStatus?.next_scheduled_scan_at ?? null,
    triggerScan: handleTriggerScan,
    manualTriggerLoading,
    manualTriggerNotice,
    refreshAll: () => refreshScanDependentQueries(queryClient),
  };
};
