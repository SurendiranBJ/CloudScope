import React from 'react';
import { Globe, MapPin } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getDashboardSummary } from '../api/dashboard';

export const formatScannedRegionsText = (regions?: string[]): string => {
  if (!regions || regions.length === 0) return 'Live';
  if (regions.length > 5) return 'All regions (global)';
  return regions.join(', ');
};

interface ScannedRegionBadgeProps {
  scannedRegions?: string[];
  className?: string;
}

export const ScannedRegionBadge: React.FC<ScannedRegionBadgeProps> = ({
  scannedRegions: propRegions,
  className = ''
}) => {
  const { data } = useQuery({
    queryKey: ['dashboardSummary'],
    queryFn: getDashboardSummary,
    staleTime: 5000
  });

  const regions = propRegions || data?.scannedRegions || data?.lastScan?.scanned_regions;
  const displayText = formatScannedRegionsText(regions);
  const isGlobal = regions && regions.length > 5;

  return (
    <div
      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border bg-enterprise-card border-enterprise-border text-gray-300 shadow-sm shrink-0 transition-colors hover:border-gray-600 ${className}`}
      title={regions && regions.length > 0 ? `Source data region(s): ${regions.join(', ')}` : 'Scan region metadata'}
    >
      {isGlobal ? (
        <Globe className="w-3.5 h-3.5 text-blue-400 shrink-0" />
      ) : (
        <MapPin className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
      )}
      <span className="truncate max-w-[220px]">
        <span className="text-enterprise-subtext font-normal">Scanned region(s):</span>{' '}
        <span className="text-white font-semibold">{displayText}</span>
      </span>
    </div>
  );
};
