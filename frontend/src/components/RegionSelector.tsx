import React, { useState, useEffect } from 'react';
import { Globe, MapPin, AlertTriangle, ChevronDown, Loader2 } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getAvailableRegions, postScanRegion } from '../api/settings';
import { getRegionFriendlyName } from '../utils/regionNames';

interface RegionSelectorProps {
  /** Current active scan mode from the health endpoint */
  currentMode?: string;
  /** Currently selected region code from the health endpoint (null when in global mode) */
  currentRegion?: string | null;
  /** Called after a successful region change so the parent can trigger a rescan poll */
  onRegionChanged: () => void;
}

export const RegionSelector: React.FC<RegionSelectorProps> = ({
  currentMode,
  currentRegion,
  onRegionChanged,
}) => {
  const [pendingCode, setPendingCode] = useState<string>('');
  const [showGlobalWarning, setShowGlobalWarning] = useState(false);
  const [isChanging, setIsChanging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Keep the dropdown in sync when health data loads / changes
  useEffect(() => {
    if (!isChanging) {
      setPendingCode(currentMode === 'global' ? 'global' : (currentRegion ?? ''));
    }
  }, [currentMode, currentRegion, isChanging]);

  const { data: regions = [], isLoading: isLoadingRegions } = useQuery({
    queryKey: ['availableRegions'],
    queryFn: getAvailableRegions,
    staleTime: Infinity, // static list — no need to re-fetch
  });

  const handleSelectChange = (code: string) => {
    if (code === pendingCode) return;
    setError(null);

    if (code === 'global') {
      // Show inline warning before switching to global (slow) mode
      setPendingCode('global');
      setShowGlobalWarning(true);
    } else {
      applyRegion('single', code);
    }
  };

  const applyRegion = async (mode: 'single' | 'global', region?: string) => {
    setIsChanging(true);
    setShowGlobalWarning(false);
    setError(null);
    try {
      await postScanRegion(mode, region);
      onRegionChanged();
    } catch (err: any) {
      const detail = err?.response?.data?.detail ?? 'Failed to update scan region';
      setError(detail);
      // Revert the dropdown to the previous value
      setPendingCode(currentMode === 'global' ? 'global' : (currentRegion ?? ''));
    } finally {
      setIsChanging(false);
    }
  };

  const handleGlobalConfirm = () => {
    applyRegion('global');
  };

  const handleGlobalCancel = () => {
    setShowGlobalWarning(false);
    // Revert to prior selection
    setPendingCode(currentMode === 'global' ? 'global' : (currentRegion ?? ''));
  };

  const isGlobal = pendingCode === 'global';

  return (
    <div className="flex flex-col gap-1.5 items-end">
      {/* Selector row */}
      <div
        className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors ${
          isGlobal
            ? 'bg-amber-500/10 border-amber-500/40 text-amber-300'
            : 'bg-enterprise-card border-enterprise-border text-enterprise-subtext'
        }`}
      >
        {isChanging ? (
          <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-400 shrink-0" />
        ) : isGlobal ? (
          <Globe className="w-3.5 h-3.5 shrink-0 text-amber-400" />
        ) : (
          <MapPin className="w-3.5 h-3.5 shrink-0 text-enterprise-accent" />
        )}

        <div className="relative flex items-center">
          <select
            disabled={isChanging || isLoadingRegions}
            value={pendingCode}
            onChange={(e) => handleSelectChange(e.target.value)}
            className="appearance-none bg-transparent pr-5 text-xs font-medium focus:outline-none cursor-pointer disabled:cursor-not-allowed disabled:opacity-60"
            style={{ color: 'inherit' }}
            aria-label="Scan region selector"
          >
            {isLoadingRegions ? (
              <option value="">Loading regions…</option>
            ) : (
              regions.map((r) => (
                <option
                  key={r.code}
                  value={r.code}
                  className="bg-[#1e293b] text-white"
                >
                  {r.code === 'global'
                    ? r.friendly_name
                    : `${getRegionFriendlyName(r.code)} (${r.code})`}
                </option>
              ))
            )}
          </select>
          <ChevronDown className="absolute right-0 w-3 h-3 pointer-events-none opacity-60" />
        </div>
      </div>

      {/* Global mode warning confirmation */}
      {showGlobalWarning && (
        <div className="flex items-start gap-2 bg-amber-500/10 border border-amber-500/30 rounded-lg px-3 py-2 text-xs max-w-xs animate-in fade-in duration-150">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-amber-300 font-semibold leading-snug">
              Scanning all regions is significantly slower.
            </p>
            <p className="text-amber-400/70 mt-0.5 leading-snug">
              This will sweep every enabled AWS region. Are you sure?
            </p>
            <div className="flex gap-2 mt-2">
              <button
                onClick={handleGlobalConfirm}
                className="px-2.5 py-1 bg-amber-500/20 hover:bg-amber-500/35 border border-amber-500/40 text-amber-300 rounded font-semibold transition-colors"
              >
                Confirm
              </button>
              <button
                onClick={handleGlobalCancel}
                className="px-2.5 py-1 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-300 rounded font-semibold transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Inline error */}
      {error && (
        <p className="text-[10px] text-enterprise-critical font-medium max-w-xs text-right">
          {error}
        </p>
      )}
    </div>
  );
};
