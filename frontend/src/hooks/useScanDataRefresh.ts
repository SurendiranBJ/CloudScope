import { useEffect, useRef, useState, useCallback } from 'react';
import { useQuery, useQueryClient, QueryClient } from '@tanstack/react-query';
import { getScanStatus, type ScanStatus } from '../api/graph.ts';

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
 * Invalidates and refetches all scan-dependent queries in the React Query cache.
 */
export const refreshScanDependentQueries = async (queryClient: QueryClient) => {
  for (const queryKey of SCAN_DEPENDENT_QUERY_KEYS) {
    await queryClient.invalidateQueries({ queryKey });
  }
};

export interface UseScanDataRefreshOptions {
  onCompleted?: (status: ScanStatus) => void;
  entityName?: string; // e.g. "Policy catalog" or "Relationships"
}

export const useScanDataRefresh = (options: UseScanDataRefreshOptions = {}) => {
  const queryClient = useQueryClient();
  const [scanJustCompleted, setScanJustCompleted] = useState(false);
  const lastProcessedScanIdRef = useRef<string | null>(null);
  const wasScanningRef = useRef<boolean>(false);
  const clearTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { data: scanStatus } = useQuery<ScanStatus>({
    queryKey: ['scanStatus'],
    queryFn: getScanStatus,
    refetchInterval: (query) => {
      const data = query.state.data;
      return data?.is_scanning ? 2000 : 5000;
    },
    staleTime: 2000,
  });

  const isScanning = !!scanStatus?.is_scanning;
  const currentCompletedId = scanStatus?.last_completed_scan_id ?? null;
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
    if (clearTimerRef.current) clearTimeout(clearTimerRef.current);
    clearTimerRef.current = setTimeout(() => {
      setScanJustCompleted(false);
    }, 4000);

    if (options.onCompleted) {
      options.onCompleted(status);
    }
  }, [queryClient, options]);

  useEffect(() => {
    if (!scanStatus) return;

    // Track initial completed scan id without triggering an unnecessary refresh on mount
    if (lastProcessedScanIdRef.current === null && currentCompletedId) {
      lastProcessedScanIdRef.current = currentCompletedId;
      wasScanningRef.current = isScanning;
      return;
    }

    // Detect scan completion transition:
    // 1. Scan was actively running and now stopped
    const finishedScanning = wasScanningRef.current && !isScanning;
    // 2. Or a new completed scan ID has appeared that we haven't processed
    const newScanCompleted = (
      currentCompletedId !== null &&
      currentCompletedId !== lastProcessedScanIdRef.current
    );

    if (finishedScanning || newScanCompleted) {
      if (currentCompletedId) {
        lastProcessedScanIdRef.current = currentCompletedId;
      }

      // Handle SUCCESS and PARTIAL: refresh all scan-dependent data
      if (isSuccess || isPartial) {
        triggerCompletion(scanStatus);
      } else if (isFailed) {
        // FAILED: Do NOT invalidate good data; only keep scanStatus up to date
        queryClient.invalidateQueries({ queryKey: ['scanStatus'] });
      }
    }

    wasScanningRef.current = isScanning;
  }, [scanStatus, currentCompletedId, isScanning, isSuccess, isPartial, isFailed, triggerCompletion, queryClient]);

  useEffect(() => {
    return () => {
      if (clearTimerRef.current) clearTimeout(clearTimerRef.current);
    };
  }, []);

  return {
    scanStatus,
    isScanning,
    scanJustCompleted,
    isPartial,
    isFailed,
    lastCompletedAt: scanStatus?.last_completed_scan_at || scanStatus?.last_successful_scan_at || null,
    failedRegions: scanStatus?.failed_regions ?? [],
    refreshAll: () => refreshScanDependentQueries(queryClient),
  };
};
