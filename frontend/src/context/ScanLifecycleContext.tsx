import React, { createContext, useContext, useEffect, useRef, useState, useCallback, useMemo } from 'react';
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
  INITIALIZING: 'Authenticating AWS connection...',
  DISCOVERY: 'Collecting AWS inventory...',
  IAM_ANALYSIS: 'Evaluating IAM policies...',
  GRAPH_CONSTRUCTION: 'Building identity graph...',
  PATH_ANALYSIS: 'Analyzing attack paths...',
  CLOUDTRAIL_CORRELATION: 'Correlating CloudTrail activity...',
  FINDING_SYNTHESIS: 'Reconciling security findings...',
  PUBLISHING: 'Publishing security snapshot...',
  COMPLETED: 'Scan completed',
  FAILED: 'Scan failed',
  PARTIAL: 'Scan completed with regional failures',
};

export const getPhaseDescription = (
  phase?: string | null,
  scanStatus?: string,
  initStage?: string | null
): string => {
  const normPhase = (phase || '').toUpperCase();
  if (normPhase === 'INITIALIZING') {
    const stage = (initStage || '').toUpperCase();
    if (stage === 'AUTHENTICATING_AWS') return 'Authenticating AWS connection...';
    if (stage === 'RESOLVING_REGIONS') return 'Resolving AWS regions...';
    if (stage === 'STARTING_COLLECTORS') return 'Starting collectors...';
    return PHASE_DESCRIPTIONS.INITIALIZING;
  }
  if (!phase && !scanStatus) return 'Ready';
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

export const refreshScanDependentQueries = async (queryClient: QueryClient) => {
  for (const queryKey of SCAN_DEPENDENT_QUERY_KEYS) {
    try {
      await queryClient.refetchQueries({ queryKey, type: 'active' });
    } catch {
      await queryClient.invalidateQueries({ queryKey });
    }
  }
};

export interface ScanLifecycleContextValue {
  scanStatus: ScanStatus | undefined;
  isScanning: boolean;
  scanJustCompleted: boolean;
  scanError: string | null;
  activePhase: string | null;
  initializationStage: string | null;
  phaseDescription: string;
  elapsedSeconds: number;
  elapsed: number;
  elapsedFormatted: string;
  completedCollectors: number;
  totalCollectors: number;
  collectorStatus: Record<string, string>;
  lastProgressAt: string | null;
  progressSecondsAgo: number | null;
  hasProgressWarning: boolean;
  progressWarningText: string | null;
  currentSnapshotId: string | null;
  snapshotId: string | null;
  newScanId: string | null;
  snapshotPublishedAt: string | null;
  lastPublishedScanId: string | null;
  lastPublishedAt: string | null;
  lastCompletedAt: string | null;
  lastSuccessfulScanAt: string | null;
  lastSuccessfulScanId: string | null;
  hasCompletedSnapshot: boolean;
  isPartial: boolean;
  isFailed: boolean;
  isSuccess: boolean;
  failedRegions: string[];
  successfulRegions: string[];
  scheduledInterval: number;
  nextScheduledScanAt: string | null;
  triggerScan: () => Promise<void>;
  manualTriggerLoading: boolean;
  manualTriggerNotice: string | null;
  refreshAll: () => Promise<void>;
}

const ScanLifecycleContext = createContext<ScanLifecycleContextValue | null>(null);

export interface ScanLifecycleProviderProps {
  children: React.ReactNode;
}

export const ScanLifecycleProvider: React.FC<ScanLifecycleProviderProps> = ({ children }) => {
  const queryClient = useQueryClient();
  const [scanJustCompleted, setScanJustCompleted] = useState(false);
  const [manualTriggerLoading, setManualTriggerLoading] = useState(false);
  const [manualTriggerNotice, setManualTriggerNotice] = useState<string | null>(null);
  const [manualError, setManualError] = useState<string | null>(null);
  const [activeTriggerScanId, setActiveTriggerScanId] = useState<string | null>(null);

  // Authoritative tracking of published snapshot ID to avoid duplicate refreshes
  const lastProcessedSnapshotIdRef = useRef<string | null>(null);
  const clearTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const noticeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // SINGLE POLLING SOURCE: Polls GET /api/v1/scan/status (2s while scanning, 7s while idle)
  const { data: scanStatus } = useQuery<ScanStatus>({
    queryKey: ['scanStatus'],
    queryFn: getScanStatus,
    refetchInterval: (query) => {
      const data = query.state.data;
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

  const newScanId = activeTriggerScanId || scanStatus?.new_scan_id || (isScanning ? scanStatus?.scan_id : null) || null;
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

  // Live timer: animates locally every second from authoritative backend started_at
  const [liveElapsed, setLiveElapsed] = useState<number>(0);

  useEffect(() => {
    if (!isScanning) {
      setActiveTriggerScanId(null);
      const backendElapsed = scanStatus?.elapsed_seconds ?? 0;
      setLiveElapsed(backendElapsed);
      return;
    }

    const startTs = scanStatus?.started_at ? new Date(scanStatus.started_at).getTime() : Date.now();

    const updateTimer = () => {
      const diff = Math.max(0, Math.floor((Date.now() - startTs) / 1000));
      const backendElapsed = scanStatus?.elapsed_seconds ?? 0;
      setLiveElapsed(Math.max(diff, Math.floor(backendElapsed)));
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [isScanning, scanStatus?.started_at, scanStatus?.elapsed_seconds]);

  // Snapshot publication detection: refresh active queries ONLY when snapshot ID changes
  const triggerCompletion = useCallback((_status?: ScanStatus) => {
    refreshScanDependentQueries(queryClient);

    setScanJustCompleted(true);
    setManualError(null);
    if (clearTimerRef.current) clearTimeout(clearTimerRef.current);
    clearTimerRef.current = setTimeout(() => {
      setScanJustCompleted(false);
    }, 6000);
  }, [queryClient]);

  useEffect(() => {
    if (!scanStatus) return;

    if (lastProcessedSnapshotIdRef.current === null) {
      if (currentSnapshotId) {
        lastProcessedSnapshotIdRef.current = currentSnapshotId;
      }
      return;
    }

    if (currentSnapshotId && currentSnapshotId !== lastProcessedSnapshotIdRef.current) {
      lastProcessedSnapshotIdRef.current = currentSnapshotId;
      triggerCompletion(scanStatus);
    }
  }, [scanStatus, currentSnapshotId, triggerCompletion]);

  // Manual trigger handler: POST /api/v1/scan
  const handleTriggerScan = useCallback(async () => {
    if (isScanning) return;
    setManualTriggerLoading(true);
    setManualError(null);

    try {
      const res = await apiTriggerScan();
      if (res?.scan_id) {
        setActiveTriggerScanId(res.scan_id);
      }
      const statusUpper = (res?.status || '').toUpperCase();
      if (statusUpper === 'ALREADY_RUNNING') {
        setManualTriggerNotice('Scan already running');
      } else {
        setManualTriggerNotice('Scan started');
      }
      if (noticeTimerRef.current) clearTimeout(noticeTimerRef.current);
      noticeTimerRef.current = setTimeout(() => setManualTriggerNotice(null), 4000);

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
    ? 'Scan is still running — no progress reported recently.'
    : null;

  useEffect(() => {
    return () => {
      if (clearTimerRef.current) clearTimeout(clearTimerRef.current);
      if (noticeTimerRef.current) clearTimeout(noticeTimerRef.current);
    };
  }, []);

  const scanError = manualError || (isFailed ? (scanStatus?.last_error || 'Scan failed') : null);
  const activePhase = scanStatus?.active_phase || (isScanning ? 'INITIALIZING' : null);
  const initializationStage = scanStatus?.initialization_stage || (activePhase === 'INITIALIZING' ? 'AUTHENTICATING_AWS' : null);
  const phaseDescription = getPhaseDescription(activePhase, scanStatus?.scan_status, initializationStage);
  const elapsedFormatted = formatDuration(liveElapsed);

  const value: ScanLifecycleContextValue = {
    scanStatus,
    isScanning,
    scanJustCompleted,
    scanError,
    activePhase,
    initializationStage,
    phaseDescription,
    elapsedSeconds: liveElapsed,
    elapsed: liveElapsed,
    elapsedFormatted,
    completedCollectors: scanStatus?.completed_collectors ?? 0,
    totalCollectors: scanStatus?.total_collectors ?? 12,
    collectorStatus: scanStatus?.collector_status ?? {},
    lastProgressAt,
    progressSecondsAgo,
    hasProgressWarning,
    progressWarningText,
    currentSnapshotId,
    snapshotId: currentSnapshotId,
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

  return (
    <ScanLifecycleContext.Provider value={value}>
      {children}
    </ScanLifecycleContext.Provider>
  );
};

export const useScanLifecycleContext = (): ScanLifecycleContextValue => {
  const context = useContext(ScanLifecycleContext);
  if (!context) {
    throw new Error('useScanLifecycleContext must be used within a ScanLifecycleProvider');
  }
  return context;
};
