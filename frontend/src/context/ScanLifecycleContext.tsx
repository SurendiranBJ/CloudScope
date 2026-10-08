import React, { createContext, useContext, useEffect, useRef, useState, useCallback, useMemo } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getScanStatus, triggerScan as apiTriggerScan, type ScanStatus } from '../api/graph.ts';

import {
  SCAN_DEPENDENT_QUERY_KEYS,
  PHASE_DESCRIPTIONS,
  getPhaseDescription,
  formatDuration,
  refreshScanDependentQueries,
  didPublishedSnapshotChange,
} from '../utils/scanLifecycleUtils.ts';

export {
  SCAN_DEPENDENT_QUERY_KEYS,
  PHASE_DESCRIPTIONS,
  getPhaseDescription,
  formatDuration,
  refreshScanDependentQueries,
  didPublishedSnapshotChange,
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
  regionalStatus: Record<string, string>;
  publicationState: string;
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
  const hasSeenInitialStatusRef = useRef(false);
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

    if (!hasSeenInitialStatusRef.current) {
      hasSeenInitialStatusRef.current = true;
      lastProcessedSnapshotIdRef.current = currentSnapshotId;
      return;
    }

    if (didPublishedSnapshotChange(
      hasSeenInitialStatusRef.current,
      lastProcessedSnapshotIdRef.current,
      currentSnapshotId,
    )) {
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
    regionalStatus: scanStatus?.regional_status ?? {},
    publicationState: scanStatus?.publication_state ?? 'NOT_PUBLISHED',
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
