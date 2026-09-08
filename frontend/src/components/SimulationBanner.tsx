import { useQuery } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { Link } from 'react-router-dom';
import { AlertTriangle, TrendingUp, TrendingDown, Activity, ChevronRight, X } from 'lucide-react';
import { getSimulationState, getSimulationRisk } from '../api/simulation';

interface SimulationBannerProps {
  onDismiss?: () => void;
}

export const SimulationBanner: React.FC<SimulationBannerProps> = ({ onDismiss }) => {
  const { data: simState } = useQuery({
    queryKey: ['simulation-state'],
    queryFn: getSimulationState,
    refetchInterval: 5000,
  });

  const { data: riskData } = useQuery({
    queryKey: ['simulation-risk'],
    queryFn: getSimulationRisk,
    enabled: !!(simState?.simulation_active),
    staleTime: 15_000,
  });

  if (!simState?.simulation_active || simState.pending_changes === 0) return null;

  const delta = riskData?.delta ?? 0;
  const currentScore = riskData?.current_score;
  const desiredScore = riskData?.desired_score;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ height: 0, opacity: 0 }}
        animate={{ height: 'auto', opacity: 1 }}
        exit={{ height: 0, opacity: 0 }}
        transition={{ duration: 0.2 }}
        className="shrink-0 overflow-hidden"
      >
        <div className="flex items-center gap-4 px-6 py-2.5 bg-amber-500/10 border-b border-amber-500/25">
          {/* Icon + label */}
          <div className="flex items-center gap-2 shrink-0">
            <div className="w-6 h-6 rounded-full bg-amber-500/20 flex items-center justify-center">
              <Activity className="w-3.5 h-3.5 text-amber-400" />
            </div>
            <span className="text-xs font-bold text-amber-400 uppercase tracking-wide">Simulation Active</span>
          </div>

          {/* Pending changes */}
          <div className="flex items-center gap-1 text-xs text-amber-300">
            <span className="font-bold">{simState.pending_changes}</span>
            <span className="text-amber-500/80">pending change{simState.pending_changes !== 1 ? 's' : ''}</span>
          </div>

          {/* Risk comparison */}
          {currentScore !== undefined && desiredScore !== undefined && (
            <div className="flex items-center gap-2 text-xs">
              <span className="text-enterprise-subtext">Risk:</span>
              <span className="font-mono font-semibold text-gray-300">{currentScore}</span>
              <ChevronRight className="w-3 h-3 text-enterprise-subtext" />
              <span className={`font-mono font-semibold ${delta > 5 ? 'text-red-400' : delta < -5 ? 'text-green-400' : 'text-gray-300'}`}>
                {desiredScore}
              </span>
              {delta !== 0 && (
                <span className={`flex items-center gap-0.5 ${delta > 0 ? 'text-red-400' : 'text-green-400'} font-semibold`}>
                  {delta > 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                  {delta > 0 ? '+' : ''}{delta}
                </span>
              )}
            </div>
          )}

          {/* Safety note */}
          <div className="flex items-center gap-1 text-[10px] text-amber-600 ml-1 shrink-0">
            <AlertTriangle className="w-3 h-3" />
            NOT applied to AWS
          </div>

          {/* Spacer */}
          <div className="flex-1" />

          {/* View changes link */}
          <Link
            to="/changes"
            id="sim-banner-view-changes"
            className="flex items-center gap-1 text-xs text-amber-400 hover:text-amber-300 font-semibold transition-colors shrink-0"
          >
            View Changes <ChevronRight className="w-3.5 h-3.5" />
          </Link>

          {/* Dismiss */}
          {onDismiss && (
            <button onClick={onDismiss} className="shrink-0 p-1 rounded text-amber-600 hover:text-amber-400 transition-colors">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </motion.div>
    </AnimatePresence>
  );
};
