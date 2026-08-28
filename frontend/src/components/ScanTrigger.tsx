import React, { useState, useEffect, useCallback, useRef } from 'react';
import { ShieldCheck } from 'lucide-react';
import { useQueryClient } from '@tanstack/react-query';
import { rebuildGraph, getScanStatus } from '../api/graph';

export const useScanTrigger = () => {
  const queryClient = useQueryClient();
  const [isScanning, setIsScanning] = useState(false);
  const [scanSuccess, setScanSuccess] = useState(false);
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
          setScanSuccess(true);

          // Refresh all dashboard, graph, and resource query keys
          queryClient.invalidateQueries({ queryKey: ['dashboardSummary'] });
          queryClient.invalidateQueries({ queryKey: ['graphElements'] });
          queryClient.invalidateQueries({ queryKey: ['cloudResources'] });
          queryClient.invalidateQueries({ queryKey: ['attackPaths'] });
          queryClient.invalidateQueries({ queryKey: ['riskAssessmentFindings'] });

          setTimeout(() => setScanSuccess(false), 4000);
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
    }).catch(() => {});

    return () => stopPolling();
  }, [queryClient, startPolling, stopPolling]);

  const handleScanClick = useCallback(async () => {
    if (isScanning) return;
    setIsScanning(true);
    setScanSuccess(false);

    // Update scan status immediately so other listeners (e.g. Navbar) update
    queryClient.setQueryData(['scanStatus'], {
      is_scanning: true,
      started_at: new Date().toISOString(),
      last_result: null,
    });

    try {
      await rebuildGraph(); // Returns immediately (async on backend)
      startPolling(); // Start polling for completion
    } catch (err) {
      console.error('Failed to trigger scan:', err);
      setIsScanning(false);
      // Re-fetch correct status from backend
      getScanStatus().then((status) => {
        queryClient.setQueryData(['scanStatus'], status);
      }).catch(() => {});
    }
  }, [isScanning, startPolling, queryClient]);

  return {
    isScanning,
    scanSuccess,
    handleScanClick,
  };
};

export const ScanTrigger: React.FC = () => {
  const { isScanning, scanSuccess, handleScanClick } = useScanTrigger();

  return (
    <button
      disabled={isScanning}
      onClick={handleScanClick}
      className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
        scanSuccess
          ? 'bg-enterprise-success/20 text-enterprise-success border border-enterprise-success/30'
          : isScanning
            ? 'bg-blue-600/10 text-blue-400/50 border border-blue-500/10 cursor-not-allowed'
            : 'bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 border border-blue-500/30'
      }`}
    >
      {scanSuccess ? (
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
      {scanSuccess ? 'Scan Complete!' : isScanning ? 'Scanning AWS...' : 'Scan Again'}
    </button>
  );
};
