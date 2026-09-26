import { useEffect, useRef } from 'react';
import {
  useScanLifecycleContext,
  type ScanLifecycleContextValue,
  PHASE_DESCRIPTIONS,
  getPhaseDescription,
  formatDuration,
  refreshScanDependentQueries,
  SCAN_DEPENDENT_QUERY_KEYS,
} from '../context/ScanLifecycleContext.tsx';
import type { ScanStatus } from '../api/graph.ts';

export {
  PHASE_DESCRIPTIONS,
  getPhaseDescription,
  formatDuration,
  refreshScanDependentQueries,
  SCAN_DEPENDENT_QUERY_KEYS,
};

export interface UseScanLifecycleOptions {
  onCompleted?: (status: ScanStatus) => void;
  entityName?: string;
}

/**
 * Unified application hook consuming the single ScanLifecycleProvider context.
 * Guarantees zero duplicate polling and coherent shared lifecycle state across all components.
 */
export const useScanLifecycle = (options: UseScanLifecycleOptions = {}): ScanLifecycleContextValue => {
  const context = useScanLifecycleContext();
  const onCompletedRef = useRef(options.onCompleted);
  onCompletedRef.current = options.onCompleted;

  useEffect(() => {
    if (context.scanJustCompleted && context.scanStatus && onCompletedRef.current) {
      onCompletedRef.current(context.scanStatus);
    }
  }, [context.scanJustCompleted, context.scanStatus]);

  return context;
};
