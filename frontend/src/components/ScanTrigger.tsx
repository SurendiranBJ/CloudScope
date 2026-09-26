import React, { useState, useEffect, useCallback, useRef } from 'react';
import { ShieldCheck, AlertCircle } from 'lucide-react';
import { useQueryClient } from '@tanstack/react-query';
import { rebuildGraph, getScanStatus } from '../api/graph';
import { refreshScanDependentQueries } from '../hooks/useScanDataRefresh';

export const useScanTrigger = () => {
  const queryClient = useQueryClient();
  const [isScanning, setIsScanning] = useState(false);
  const [scanSuccess, setScanSuccess] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [lastSuccessfulScanAt, setLastSuccessfulScanAt] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const startPolling = useCallback(() => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      try {
        const status = await getScanStatus();
        queryClient.setQueryData(['scanStatus'], status);

        if (!status.is_scanning) {
          stopPolling();
          setIsScanning(false);

          const scanState = status.scan_status || (status.last_result?.status || '').toUpperCase();

          if (scanState === 'SUCCESS' || scanState === 'PARTIAL') {
            setScanSuccess(true);
            setScanError(null);
            setLastSuccessfulScanAt(status.last_successful_scan_at || status.last_result?.timestamp || null);

            // Immediately invalidate and refetch all scan-dependent data
            refreshScanDependentQueries(queryClient);

            setTimeout(() => setScanSuccess(false), 4000);
          } else if (scanState === 'FAILED') {
            setScanSuccess(false);
            const err = status.last_error || status.last_result?.error || 'Scan Failed';
            setScanError(err);
            setLastSuccessfulScanAt(status.last_successful_scan_at || null);
            queryClient.invalidateQueries({ queryKey: ['scanStatus'] });
            queryClient.invalidateQueries({ queryKey: ['dashboardSummary'] });

            setTimeout(() => setScanError(null), 6000);
          }
        }
      } catch {
        // Ignore network blips during polling
      }
    }, 2000); // Poll every 2 seconds
  }, [queryClient, stopPolling]);

  useEffect(() => {
    getScanStatus().then((status) => {
      queryClient.setQueryData(['scanStatus'], status);
      if (status.is_scanning) {
        setIsScanning(true);
        startPolling();
      }
      if (status.last_successful_scan_at) {
        setLastSuccessfulScanAt(status.last_successful_scan_at);
      }
    }).catch(() => {});

    return () => stopPolling();
  }, [queryClient, startPolling, stopPolling]);

  const handleScanClick = useCallback(async () => {
    if (isScanning) return;
    setIsScanning(true);
    setScanSuccess(false);
    setScanError(null);

    // Update scan status immediately so other listeners update
    queryClient.setQueryData(['scanStatus'], {
      is_scanning: true,
      scan_status: 'SCANNING',
      started_at: new Date().toISOString(),
      last_result: null,
    });

    try {
      await rebuildGraph(); // Returns immediately (async on backend)
      startPolling(); // Start polling for completion
    } catch (err: any) {
      console.error('Failed to trigger scan:', err);
      setIsScanning(false);
      setScanError(err?.message || 'Failed to trigger scan');
      // Re-fetch correct status from backend
      getScanStatus().then((status) => {
        queryClient.setQueryData(['scanStatus'], status);
      }).catch(() => {});
    }
  }, [isScanning, startPolling, queryClient]);

  return {
    isScanning,
    scanSuccess,
    scanError,
    lastSuccessfulScanAt,
    handleScanClick,
  };
};

interface ScanTriggerPresenterProps {
  isScanning: boolean;
  scanSuccess: boolean;
  scanError?: string | null;
  lastSuccessfulScanAt?: string | null;
  onClick: () => void;
}

const ScanTriggerPresenter: React.FC<ScanTriggerPresenterProps> = ({
  isScanning,
  scanSuccess,
  scanError,
  lastSuccessfulScanAt,
  onClick,
}) => {
  return (
    <div className="flex items-center gap-2">
      <button
        disabled={isScanning}
        onClick={onClick}
        title={scanError ? `Error: ${scanError}` : lastSuccessfulScanAt ? `Last successful scan: ${new Date(lastSuccessfulScanAt).toLocaleTimeString()}` : undefined}
        className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
          scanError
            ? 'bg-enterprise-critical/20 text-enterprise-critical border border-enterprise-critical/30 hover:bg-enterprise-critical/30'
            : scanSuccess
              ? 'bg-enterprise-success/20 text-enterprise-success border border-enterprise-success/30'
              : isScanning
                ? 'bg-blue-600/10 text-blue-400/50 border border-blue-500/10 cursor-not-allowed'
                : 'bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 border border-blue-500/30'
        }`}
      >
        {scanError ? (
          <AlertCircle className="w-3.5 h-3.5" />
        ) : scanSuccess ? (
          <ShieldCheck className="w-3.5 h-3.5" />
        ) : (
          <svg
            className={isScanning ? 'animate-spin' : ''}
            xmlns="http://www.w3.org/2000/svg"
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
            <path d="M3 3v5h5" />
            <path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16" />
            <path d="M16 21v-5h5" />
          </svg>
        )}
        {scanError
          ? 'Scan Failed'
          : scanSuccess
            ? 'Scan Complete!'
            : isScanning
              ? 'Scanning AWS...'
              : 'Scan Again'}
      </button>
      {scanError && lastSuccessfulScanAt && (
        <span className="text-[10px] text-gray-400 hidden sm:inline">
          (last good: {new Date(lastSuccessfulScanAt).toLocaleTimeString()})
        </span>
      )}
    </div>
  );
};

const ScanTriggerWithInternalState: React.FC = () => {
  const { isScanning, scanSuccess, scanError, lastSuccessfulScanAt, handleScanClick } = useScanTrigger();
  return (
    <ScanTriggerPresenter
      isScanning={isScanning}
      scanSuccess={scanSuccess}
      scanError={scanError}
      lastSuccessfulScanAt={lastSuccessfulScanAt}
      onClick={handleScanClick}
    />
  );
};

interface ScanTriggerProps {
  isScanning?: boolean;
  scanSuccess?: boolean;
  scanError?: string | null;
  lastSuccessfulScanAt?: string | null;
  onScanClick?: () => void;
}

export const ScanTrigger: React.FC<ScanTriggerProps> = ({
  isScanning,
  scanSuccess,
  scanError,
  lastSuccessfulScanAt,
  onScanClick,
}) => {
  // If external state is passed, bypass the hook call completely to avoid extra timers/polling
  if (isScanning !== undefined && scanSuccess !== undefined && onScanClick !== undefined) {
    return (
      <ScanTriggerPresenter
        isScanning={isScanning}
        scanSuccess={scanSuccess}
        scanError={scanError}
        lastSuccessfulScanAt={lastSuccessfulScanAt}
        onClick={onScanClick}
      />
    );
  }

  return <ScanTriggerWithInternalState />;
};
