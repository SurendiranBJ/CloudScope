/**
 * Backward-compatibility wrapper forwarding to the unified single source of truth hook.
 */
export * from './useScanLifecycle.ts';
import { useScanLifecycle, type UseScanLifecycleOptions } from './useScanLifecycle.ts';

export const useScanDataRefresh = (options: UseScanLifecycleOptions = {}) => {
  return useScanLifecycle(options);
};
