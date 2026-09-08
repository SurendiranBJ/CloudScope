import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert, ArrowRight, X, Check,
  Activity, TrendingUp, TrendingDown,
  Info, Loader2, AlertCircle
} from 'lucide-react';
import { previewSimulationChange, type SimulationChangePayload } from '../api/simulation';
import type { SimulationAnalysis } from '../types';

interface SimulationPreviewModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => Promise<void> | void;
  payload: SimulationChangePayload | null;
  policyName?: string;
  isConfirming?: boolean;
}

export const SimulationPreviewModal: React.FC<SimulationPreviewModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  payload,
  policyName,
  isConfirming = false,
}) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<SimulationAnalysis | null>(null);

  useEffect(() => {
    if (!isOpen || !payload) {
      setAnalysis(null);
      setError(null);
      return;
    }

    let isMounted = true;
    setLoading(true);
    setError(null);

    previewSimulationChange(payload)
      .then((data) => {
        if (isMounted) {
          setAnalysis(data);
          setLoading(false);
        }
      })
      .catch((err: any) => {
        if (isMounted) {
          const detail = err?.response?.data?.detail || err?.message || 'Failed to generate preview analysis';
          setError(detail);
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [isOpen, payload]);

  if (!isOpen || !payload) return null;

  const risk = analysis?.risk_comparison;
  const blast = analysis?.blast_radius_comparison;
  const attackDiff = analysis?.attack_path_comparison;
  const newPaths = attackDiff?.new_paths || [];
  const removedPaths = attackDiff?.removed_paths || [];
  const newResources = analysis?.new_reachable_resources || [];
  const removedResources = analysis?.removed_reachable_resources || [];

  const riskDelta = risk ? risk.delta : 0;
  const isHigherRisk = riskDelta > 0;
  const isLowerRisk = riskDelta < 0;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 10 }}
          transition={{ duration: 0.2 }}
          className="relative w-full max-w-3xl bg-[#0F172A] border border-gray-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col my-8 max-h-[90vh]"
        >
          {/* TOP BANNER: SIMULATION ONLY */}
          <div className="bg-amber-500/15 border-b border-amber-500/30 px-6 py-2.5 flex items-center justify-between text-amber-300 text-xs font-semibold uppercase tracking-wider">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
              <span>SIMULATION ONLY — NOT APPLIED TO AWS</span>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-200 border border-amber-500/30">
              PREVIEW MODE
            </span>
          </div>

          {/* MODAL HEADER */}
          <div className="px-6 py-4 border-b border-gray-800 flex items-start justify-between bg-slate-900/60">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${
                  payload.action === 'ATTACH_POLICY'
                    ? 'bg-blue-500/20 text-blue-300 border-blue-500/40'
                    : 'bg-red-500/20 text-red-300 border-red-500/40'
                }`}>
                  {payload.action === 'ATTACH_POLICY' ? 'ATTACH POLICY' : 'DETACH POLICY'}
                </span>
                <span className="text-xs text-gray-400">to {payload.principal_type}</span>
              </div>
              <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                <span className="text-enterprise-accent">{policyName || payload.policy_arn.split('/').pop()}</span>
                <ArrowRight className="w-3.5 h-3.5 text-gray-500" />
                <span className="text-gray-200 font-mono text-xs">{payload.principal_id}</span>
              </h2>
            </div>

            <button
              onClick={onClose}
              className="text-gray-400 hover:text-white p-1 rounded-lg hover:bg-gray-800 transition-colors"
              title="Close Preview"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* MODAL CONTENT */}
          <div className="p-6 overflow-y-auto space-y-6 text-sm text-gray-300">
            {/* LOADING STATE */}
            {loading && (
              <div className="py-16 flex flex-col items-center justify-center gap-3 text-gray-400">
                <Loader2 className="w-8 h-8 animate-spin text-enterprise-accent" />
                <p className="text-xs font-medium">Evaluating policy simulation against IAM topology...</p>
                <span className="text-[11px] text-gray-500 font-mono">Computing graph diff, attack paths, blast radius, and risk impact</span>
              </div>
            )}

            {/* ERROR STATE */}
            {!loading && error && (
              <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-red-200">Simulation Preview Failed</h4>
                  <p className="text-xs text-red-300/90">{error}</p>
                  <p className="text-[11px] text-red-400/70">Data unavailable. Please check the policy ARN and principal ID.</p>
                </div>
              </div>
            )}

            {/* ANALYSIS RESULT */}
            {!loading && !error && analysis && (
              <>
                {/* 1. RISK POSTURE COMPARISON CARDS */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="p-3.5 rounded-xl bg-slate-900 border border-gray-800">
                    <span className="text-[10px] text-gray-400 font-semibold uppercase tracking-wider block mb-1">Current Risk</span>
                    <div className="flex items-baseline gap-2">
                      <span className="text-2xl font-bold font-mono text-white">{risk?.current_score ?? '—'}</span>
                      <span className="text-[11px] text-gray-400 font-mono">/ 100</span>
                    </div>
                    <span className="text-[10px] font-semibold uppercase tracking-wider text-gray-400 mt-1 block">
                      {risk?.current_severity ?? 'Unknown'}
                    </span>
                  </div>

                  <div className="p-3.5 rounded-xl bg-slate-900 border border-gray-800">
                    <span className="text-[10px] text-gray-400 font-semibold uppercase tracking-wider block mb-1">Projected Risk</span>
                    <div className="flex items-baseline gap-2">
                      <span className="text-2xl font-bold font-mono text-white">{risk?.desired_score ?? '—'}</span>
                      <span className="text-[11px] text-gray-400 font-mono">/ 100</span>
                    </div>
                    <span className="text-[10px] font-semibold uppercase tracking-wider text-enterprise-accent mt-1 block">
                      {risk?.desired_severity ?? 'Unknown'}
                    </span>
                  </div>

                  <div className={`p-3.5 rounded-xl border ${
                    isHigherRisk
                      ? 'bg-red-950/30 border-red-500/40 text-red-300'
                      : isLowerRisk
                      ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
                      : 'bg-slate-900 border-gray-800 text-gray-300'
                  }`}>
                    <span className="text-[10px] font-semibold uppercase tracking-wider block mb-1">Risk Delta</span>
                    <div className="flex items-center gap-2">
                      {isHigherRisk ? (
                        <TrendingUp className="w-5 h-5 text-red-400" />
                      ) : isLowerRisk ? (
                        <TrendingDown className="w-5 h-5 text-emerald-400" />
                      ) : (
                        <Check className="w-5 h-5 text-gray-400" />
                      )}
                      <span className="text-2xl font-bold font-mono">
                        {riskDelta > 0 ? `+${riskDelta}` : riskDelta}
                      </span>
                    </div>
                    <span className="text-[10px] font-medium mt-1 block">
                      {isHigherRisk ? 'Risk increases after change' : isLowerRisk ? 'Risk decreases after change' : 'No net score change'}
                    </span>
                  </div>
                </div>

                {/* 2. BLAST RADIUS METRICS */}
                <div className="p-4 rounded-xl bg-slate-900/90 border border-gray-800 space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                      <Activity className="w-3.5 h-3.5 text-blue-400" />
                      <span>Blast Radius Impact</span>
                    </h3>
                    <span className="text-[11px] font-mono text-gray-400">
                      Blast Score: {blast?.current_blast_score ?? 0} → {blast?.desired_blast_score ?? 0} ({blast?.delta !== undefined ? (blast.delta > 0 ? `+${blast.delta}` : blast.delta) : 0})
                    </span>
                  </div>

                  <div className="grid grid-cols-3 gap-2.5 pt-1">
                    <div className="p-2.5 rounded-lg bg-gray-950 border border-gray-800/80">
                      <span className="text-[10px] text-gray-400 block font-medium">Affected Identities</span>
                      <div className="flex items-center justify-between mt-1">
                        <span className="text-sm font-bold font-mono text-white">{blast?.desired_identities_count ?? 0}</span>
                        <span className={`text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded ${
                          (blast?.identities_delta ?? 0) > 0
                            ? 'text-red-400 bg-red-500/10'
                            : (blast?.identities_delta ?? 0) < 0
                            ? 'text-emerald-400 bg-emerald-500/10'
                            : 'text-gray-400'
                        }`}>
                          {(blast?.identities_delta ?? 0) > 0 ? `+${blast?.identities_delta}` : (blast?.identities_delta ?? 0)}
                        </span>
                      </div>
                    </div>

                    <div className="p-2.5 rounded-lg bg-gray-950 border border-gray-800/80">
                      <span className="text-[10px] text-gray-400 block font-medium">Reachable Resources</span>
                      <div className="flex items-center justify-between mt-1">
                        <span className="text-sm font-bold font-mono text-white">{blast?.desired_resource_count ?? 0}</span>
                        <span className={`text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded ${
                          (blast?.resources_delta ?? (blast?.desired_resource_count ?? 0) - (blast?.current_resource_count ?? 0)) > 0
                            ? 'text-red-400 bg-red-500/10'
                            : (blast?.resources_delta ?? (blast?.desired_resource_count ?? 0) - (blast?.current_resource_count ?? 0)) < 0
                            ? 'text-emerald-400 bg-emerald-500/10'
                            : 'text-gray-400'
                        }`}>
                          {((blast?.resources_delta ?? (blast?.desired_resource_count ?? 0) - (blast?.current_resource_count ?? 0)) > 0)
                            ? `+${blast?.resources_delta ?? (blast?.desired_resource_count ?? 0) - (blast?.current_resource_count ?? 0)}`
                            : (blast?.resources_delta ?? (blast?.desired_resource_count ?? 0) - (blast?.current_resource_count ?? 0))}
                        </span>
                      </div>
                    </div>

                    <div className="p-2.5 rounded-lg bg-gray-950 border border-gray-800/80">
                      <span className="text-[10px] text-gray-400 block font-medium">Sensitive Assets</span>
                      <div className="flex items-center justify-between mt-1">
                        <span className="text-sm font-bold font-mono text-white">{blast?.desired_sensitive_count ?? 0}</span>
                        <span className={`text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded ${
                          (blast?.sensitive_delta ?? 0) > 0
                            ? 'text-red-400 bg-red-500/10'
                            : (blast?.sensitive_delta ?? 0) < 0
                            ? 'text-emerald-400 bg-emerald-500/10'
                            : 'text-gray-400'
                        }`}>
                          {(blast?.sensitive_delta ?? 0) > 0 ? `+${blast?.sensitive_delta}` : (blast?.sensitive_delta ?? 0)}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 3. ATTACK PATHS DIFF SUMMARY */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="p-3.5 rounded-xl bg-slate-900/80 border border-gray-800">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-red-400" />
                        <span>New Attack Paths ({newPaths.length})</span>
                      </span>
                    </div>
                    {newPaths.length === 0 ? (
                      <p className="text-xs text-gray-500 italic">No new lateral attack paths detected.</p>
                    ) : (
                      <ul className="space-y-1.5 max-h-28 overflow-y-auto pr-1">
                        {newPaths.slice(0, 5).map((p, idx) => (
                          <li key={idx} className="text-[11px] bg-gray-950/70 p-1.5 rounded border border-red-500/20 text-red-200 flex items-center justify-between">
                            <span className="truncate max-w-[200px]">{p.name || `${p.source} → ${p.destination}`}</span>
                            <span className="text-[10px] font-mono font-bold uppercase text-red-400">{p.severity || 'HIGH'}</span>
                          </li>
                        ))}
                        {newPaths.length > 5 && (
                          <li className="text-[10px] text-gray-500 text-center pt-1">+ {newPaths.length - 5} more paths</li>
                        )}
                      </ul>
                    )}
                  </div>

                  <div className="p-3.5 rounded-xl bg-slate-900/80 border border-gray-800">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-emerald-400" />
                        <span>Removed Attack Paths ({removedPaths.length})</span>
                      </span>
                    </div>
                    {removedPaths.length === 0 ? (
                      <p className="text-xs text-gray-500 italic">No attack paths eliminated by this change.</p>
                    ) : (
                      <ul className="space-y-1.5 max-h-28 overflow-y-auto pr-1">
                        {removedPaths.slice(0, 5).map((p, idx) => (
                          <li key={idx} className="text-[11px] bg-gray-950/70 p-1.5 rounded border border-emerald-500/20 text-emerald-200 flex items-center justify-between">
                            <span className="truncate max-w-[200px]">{p.name || `${p.source} → ${p.destination}`}</span>
                            <span className="text-[10px] font-mono font-bold uppercase text-emerald-400">{p.severity || 'HIGH'}</span>
                          </li>
                        ))}
                        {removedPaths.length > 5 && (
                          <li className="text-[10px] text-gray-500 text-center pt-1">+ {removedPaths.length - 5} more paths</li>
                        )}
                      </ul>
                    )}
                  </div>
                </div>

                {/* 4. REACHABLE RESOURCES DIFF */}
                {(newResources.length > 0 || removedResources.length > 0) && (
                  <div className="p-3.5 rounded-xl bg-slate-900/60 border border-gray-800 space-y-2 text-xs">
                    <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider block">Reachable Resource Changes</span>
                    <div className="flex flex-wrap gap-2">
                      {newResources.slice(0, 6).map((r, i) => (
                        <span key={i} className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-red-300 font-mono text-[10px]">
                          + {r.name || r.id || r.resource_id} ({r.type || 'Resource'})
                        </span>
                      ))}
                      {removedResources.slice(0, 6).map((r, i) => (
                        <span key={i} className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 font-mono text-[10px]">
                          - {r.name || r.id || r.resource_id} ({r.type || 'Resource'})
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* 5. TOP REASONS */}
                {risk?.top_reasons && risk.top_reasons.length > 0 && (
                  <div className="space-y-1.5 pt-1">
                    <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider block">Key Security Drivers</span>
                    <div className="space-y-1">
                      {risk.top_reasons.map((reason, idx) => (
                        <div key={idx} className="flex items-start gap-2 text-xs text-gray-300">
                          <span className="text-enterprise-accent mt-0.5">•</span>
                          <span>{reason}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* SUMMARY STATEMENT */}
                {analysis.summary && (
                  <div className="p-3 rounded-lg bg-gray-900 border border-gray-800 text-xs text-gray-300 flex items-start gap-2">
                    <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                    <span>{analysis.summary}</span>
                  </div>
                )}
              </>
            )}
          </div>

          {/* FOOTER ACTIONS */}
          <div className="px-6 py-4 border-t border-gray-800 bg-slate-900/60 flex items-center justify-between">
            <button
              onClick={onClose}
              disabled={isConfirming}
              className="px-4 py-2 rounded-xl text-xs font-semibold text-gray-400 hover:text-white hover:bg-gray-800 transition-colors disabled:opacity-50"
            >
              Cancel
            </button>

            <div className="flex items-center gap-3">
              <button
                onClick={onConfirm}
                disabled={loading || !!error || isConfirming}
                className="flex items-center gap-2 px-5 py-2 rounded-xl text-xs font-semibold bg-enterprise-accent hover:bg-blue-600 text-white shadow-lg shadow-blue-500/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isConfirming ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Applying Simulation...</span>
                  </>
                ) : (
                  <>
                    <Check className="w-4 h-4" />
                    <span>Confirm Simulation</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
