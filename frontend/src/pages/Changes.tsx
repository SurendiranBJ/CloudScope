import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  AlertTriangle, Trash2, RotateCcw, Plus, Minus,
  Activity, Shield, ChevronRight, RefreshCw, ArrowRight,
  TrendingUp, TrendingDown, Minus as MdMinus
} from 'lucide-react';
import {
  getSimulationState, resetSimulation, removeSimulationChange, getSimulationRisk
} from '../api/simulation';
import type { SimulationChange } from '../types';

function DeltaBadge({ delta }: { delta: number }) {
  if (delta > 0) return (
    <span className="inline-flex items-center gap-1 text-red-400 font-bold">
      <TrendingUp className="w-4 h-4" /> +{delta}
    </span>
  );
  if (delta < 0) return (
    <span className="inline-flex items-center gap-1 text-green-400 font-bold">
      <TrendingDown className="w-4 h-4" /> {delta}
    </span>
  );
  return (
    <span className="inline-flex items-center gap-1 text-gray-400 font-bold">
      <MdMinus className="w-4 h-4" /> 0
    </span>
  );
}

const SeverityColor: Record<string, string> = {
  critical: 'text-red-400',
  high:     'text-amber-400',
  medium:   'text-blue-400',
  low:      'text-green-400',
  unknown:  'text-gray-400',
};

function ChangeRow({ change, onRemove }: { change: SimulationChange; onRemove: () => void }) {
  const isAttach = change.action === 'ATTACH_POLICY';
  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 12 }}
      className="flex items-center gap-3 p-4 bg-enterprise-card border border-enterprise-border rounded-xl"
    >
      <div className={`shrink-0 w-8 h-8 rounded-lg flex items-center justify-center ${isAttach ? 'bg-green-500/15' : 'bg-red-500/15'}`}>
        {isAttach ? <Plus className="w-4 h-4 text-green-400" /> : <Minus className="w-4 h-4 text-red-400" />}
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className={`text-xs font-semibold ${isAttach ? 'text-green-400' : 'text-red-400'}`}>
            {isAttach ? 'ATTACH' : 'DETACH'}
          </span>
          <span className="text-xs text-enterprise-subtext">{change.action.replace('_POLICY', '')}</span>
        </div>
        <div className="flex items-center gap-1.5 mt-0.5">
          <span className="text-sm font-semibold text-white truncate">{change.policy_name || change.policy_arn.split('/').pop()}</span>
        </div>
        <div className="flex items-center gap-1 mt-0.5 text-[10px] text-enterprise-subtext">
          <span className="text-enterprise-accent">{change.principal_type}</span>
          <ArrowRight className="w-2.5 h-2.5" />
          <span className="font-mono">{change.principal_id}</span>
        </div>
        <div className="mt-0.5 text-[9px] text-enterprise-subtext font-mono truncate">{change.policy_arn}</div>
      </div>

      <button
        id={`remove-change-${change.change_id}`}
        onClick={onRemove}
        className="shrink-0 p-2 rounded-lg text-enterprise-subtext hover:text-red-400 hover:bg-red-500/10 transition-colors"
        title="Remove this simulation change"
      >
        <Trash2 className="w-4 h-4" />
      </button>
    </motion.div>
  );
}

export const Changes: React.FC = () => {
  const qc = useQueryClient();

  const { data: simState, isLoading } = useQuery({
    queryKey: ['simulation-state'],
    queryFn: getSimulationState,
    refetchInterval: 5000,
  });

  const { data: riskData } = useQuery({
    queryKey: ['simulation-risk'],
    queryFn: getSimulationRisk,
    enabled: !!(simState?.simulation_active),
    staleTime: 10_000,
  });

  const resetMutation = useMutation({
    mutationFn: resetSimulation,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['simulation-state'] });
      qc.invalidateQueries({ queryKey: ['simulation-risk'] });
    },
  });

  const removeMutation = useMutation({
    mutationFn: removeSimulationChange,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['simulation-state'] });
      qc.invalidateQueries({ queryKey: ['simulation-risk'] });
    },
  });

  const changes: SimulationChange[] = simState?.changes ?? [];
  const pendingCount = simState?.pending_changes ?? 0;

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* SIMULATION ONLY Banner */}
      <div className="shrink-0 flex items-center gap-3 px-6 py-2.5 bg-amber-500/10 border-b border-amber-500/20">
        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
        <p className="text-xs font-semibold text-amber-300">
          SIMULATION ONLY — Changes shown here are <span className="underline">NOT APPLIED TO AWS</span>. 
          This is a local what-if analysis. Reset at any time.
        </p>
      </div>

      <div className="flex-1 overflow-y-auto">
        <div className="max-w-4xl mx-auto px-6 py-6 space-y-6">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-xl font-bold text-white flex items-center gap-2">
                <Activity className="w-5 h-5 text-amber-400" />
                Pending Simulation Changes
              </h1>
              <p className="text-xs text-enterprise-subtext mt-0.5">
                {pendingCount} pending change{pendingCount !== 1 ? 's' : ''} — 
                {pendingCount === 0 ? ' application reflects real AWS current state' : ' desired state diverges from real AWS'}
              </p>
            </div>

            {pendingCount > 0 && (
              <button
                id="reset-simulation-btn"
                onClick={() => resetMutation.mutate()}
                disabled={resetMutation.isPending}
                className="flex items-center gap-2 px-4 py-2 rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 hover:bg-red-500/20 text-sm font-semibold transition-colors disabled:opacity-50"
              >
                <RotateCcw className="w-4 h-4" />
                Reset Simulation
              </button>
            )}
          </div>

          {/* Risk comparison */}
          {simState?.simulation_active && riskData && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="grid grid-cols-3 gap-4"
            >
              {/* Current */}
              <div className="bg-enterprise-card border border-enterprise-border rounded-xl p-4 text-center">
                <p className="text-[10px] uppercase tracking-wider text-enterprise-subtext mb-2">Current Risk</p>
                <p className="text-3xl font-bold text-white">{riskData.current_score}<span className="text-sm text-enterprise-subtext">/100</span></p>
                <p className={`text-xs font-semibold mt-1 uppercase ${SeverityColor[riskData.current_severity] ?? 'text-gray-400'}`}>
                  {riskData.current_severity}
                </p>
                <p className="text-[10px] text-enterprise-subtext mt-1">CURRENT AWS STATE</p>
              </div>

              {/* Delta */}
              <div className="bg-enterprise-card border border-enterprise-accent/20 rounded-xl p-4 text-center flex flex-col items-center justify-center">
                <p className="text-[10px] uppercase tracking-wider text-enterprise-subtext mb-2">Risk Change</p>
                <div className="text-2xl font-bold">
                  <DeltaBadge delta={riskData.delta} />
                </div>
                <p className="text-[10px] text-enterprise-subtext mt-2">from simulation changes</p>
                {riskData.top_reasons && riskData.top_reasons.length > 0 && (
                  <div className="mt-3 text-left w-full space-y-1">
                    {riskData.top_reasons.slice(0, 3).map((r, i) => (
                      <p key={i} className="text-[10px] text-enterprise-subtext flex items-start gap-1">
                        <span className="text-amber-400 shrink-0">•</span> {r}
                      </p>
                    ))}
                  </div>
                )}
              </div>

              {/* Desired */}
              <div className={`bg-enterprise-card border rounded-xl p-4 text-center ${
                riskData.delta > 0 ? 'border-red-500/30' : riskData.delta < 0 ? 'border-green-500/30' : 'border-enterprise-border'
              }`}>
                <p className="text-[10px] uppercase tracking-wider text-enterprise-subtext mb-2">Projected Risk</p>
                <p className={`text-3xl font-bold ${
                  riskData.delta > 10 ? 'text-red-400' : riskData.delta < -5 ? 'text-green-400' : 'text-white'
                }`}>{riskData.desired_score}<span className="text-sm text-enterprise-subtext">/100</span></p>
                <p className={`text-xs font-semibold mt-1 uppercase ${SeverityColor[riskData.desired_severity] ?? 'text-gray-400'}`}>
                  {riskData.desired_severity}
                </p>
                <p className="text-[10px] text-enterprise-subtext mt-1">DESIRED STATE</p>
              </div>
            </motion.div>
          )}

          {/* Changes list */}
          {isLoading ? (
            <div className="flex items-center justify-center h-32 text-enterprise-subtext">
              <RefreshCw className="w-5 h-5 animate-spin mr-2" /> Loading...
            </div>
          ) : changes.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-40 gap-3 text-enterprise-subtext">
              <Shield className="w-10 h-10" />
              <p className="text-sm font-medium">No simulation changes</p>
              <p className="text-xs text-center max-w-xs">
                Application reflects real AWS current state. Go to{' '}
                <Link to="/policies" className="text-enterprise-accent hover:underline">Policies</Link>{' '}
                to attach/detach policies and simulate changes.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              <p className="text-xs text-enterprise-subtext uppercase tracking-wider">Simulation Changes</p>
              <AnimatePresence mode="popLayout">
                {changes.map(change => (
                  <ChangeRow
                    key={change.change_id}
                    change={change}
                    onRemove={() => removeMutation.mutate(change.change_id)}
                  />
                ))}
              </AnimatePresence>
            </div>
          )}

          {/* Navigation hints */}
          {pendingCount > 0 && (
            <div className="grid grid-cols-2 gap-3">
              {[
                { to: '/risks', label: 'View Risk Comparison', icon: <Shield className="w-4 h-4" /> },
                { to: '/attack-paths', label: 'View Attack Path Diff', icon: <Activity className="w-4 h-4" /> },
              ].map(item => (
                <Link
                  key={item.to}
                  to={item.to}
                  className="flex items-center justify-between gap-2 px-4 py-3 bg-enterprise-card border border-enterprise-border rounded-xl text-sm text-gray-300 hover:text-white hover:border-enterprise-accent/30 transition-colors"
                >
                  <span className="flex items-center gap-2">{item.icon} {item.label}</span>
                  <ChevronRight className="w-4 h-4 text-enterprise-subtext" />
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
