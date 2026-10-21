import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  AlertTriangle, Trash2, RotateCcw, Plus, Minus, Activity, Shield, ChevronRight, RefreshCw, ArrowRight,
  TrendingUp, TrendingDown, Minus as MdMinus, Check, Pencil, Play, X
} from 'lucide-react';
import {
  getSimulationState, resetSimulation, removeSimulationChange, getSimulationRisk, addSimulationChange,
  getSimulationGroups, previewSimulationChange, updateSimulationChange, type SimulationChangePayload
} from '../api/simulation';
import { getIAMUsers } from '../api/users';
import { getIAMRoles } from '../api/roles';
import { getPolicyCatalog } from '../api/policies';
import type { SimulationAnalysis, SimulationChange } from '../types';
import { useState } from 'react';

function getErrorText(error: unknown): string {
  const value = error as { response?: { data?: { detail?: unknown } }; message?: string };
  const detail = value.response?.data?.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) return detail.map((item) => typeof item === 'object' && item && 'msg' in item ? String(item.msg) : String(item)).join('; ');
  return value.message || 'The request failed. Check the server connection and try again.';
}

function DeltaBadge({ delta }: { delta: number }) {
  if (delta > 0) return (
    <span className="inline-flex items-center gap-1 text-green-400 font-bold">
      <TrendingUp className="w-4 h-4" /> +{delta}
    </span>
  );
  if (delta < 0) return (
    <span className="inline-flex items-center gap-1 text-red-400 font-bold">
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
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editValue, setEditValue] = useState<SimulationChangePayload | null>(null);
  const [analysis, setAnalysis] = useState<SimulationAnalysis | null>(null);
  const [analysisError, setAnalysisError] = useState('');
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [adding, setAdding] = useState(false);
  const [addValue, setAddValue] = useState<SimulationChangePayload>({ action: 'ATTACH_POLICY', principal_type: 'USER', principal_id: '', policy_arn: '' });
  const [policySearch, setPolicySearch] = useState('');

  const { data: editInputs } = useQuery({
    queryKey: ['simulation-edit-inputs'],
    queryFn: async () => {
      const first = await getPolicyCatalog({ page: 1, page_size: 1000 });
      const rest = first.total_pages > 1
        ? await Promise.all(Array.from({ length: first.total_pages - 1 }, (_, i) => getPolicyCatalog({ page: i + 2, page_size: 1000 })))
        : [];
      const [users, roles, groups] = await Promise.all([getIAMUsers(), getIAMRoles(), getSimulationGroups()]);
      return { policies: [...first.items, ...rest.flatMap((page) => page.items)].filter((p) => p.isAttachable && p.arn), users, roles, groups };
    },
    enabled: !!editingId || adding,
    staleTime: 60_000,
  });

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
      setAnalysis(null); setAnalysisError('');
      qc.invalidateQueries({ queryKey: ['simulation-state'] });
      qc.invalidateQueries({ queryKey: ['simulation-risk'] });
    },
  });

  const removeMutation = useMutation({
    mutationFn: removeSimulationChange,
    onSuccess: () => {
      setAnalysis(null); setAnalysisError('');
      qc.invalidateQueries({ queryKey: ['simulation-state'] });
      qc.invalidateQueries({ queryKey: ['simulation-risk'] });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, change }: { id: string; change: SimulationChangePayload }) => updateSimulationChange(id, change),
    onSuccess: () => {
      setEditingId(null); setEditValue(null); setAnalysis(null);
      qc.invalidateQueries({ queryKey: ['simulation-state'] });
      qc.invalidateQueries({ queryKey: ['simulation-risk'] });
    },
  });

  const addMutation = useMutation({
    mutationFn: addSimulationChange,
    onSuccess: () => {
      setAdding(false); setAddValue({ action: 'ATTACH_POLICY', principal_type: 'USER', principal_id: '', policy_arn: '' }); setAnalysis(null);
      qc.invalidateQueries({ queryKey: ['simulation-state'] });
      qc.invalidateQueries({ queryKey: ['simulation-risk'] });
    },
  });

  const changes: SimulationChange[] = simState?.changes ?? [];
  const pendingCount = simState?.pending_changes ?? 0;
  const identityOptions = [
    ...(editInputs?.users ?? []).map((x) => ({ type: 'USER' as const, id: x.name, label: `User · ${x.name}` })),
    ...(editInputs?.roles ?? []).map((x) => ({ type: 'ROLE' as const, id: x.name, label: `Role · ${x.name}` })),
    ...(editInputs?.groups ?? []).map((x) => ({ type: 'GROUP' as const, id: x.name, label: `Group · ${x.name}` })),
  ];
  const matchingEditPolicies = (editInputs?.policies ?? []).filter((policy) => {
    const q = policySearch.trim().toLowerCase();
    return !q || `${policy.name} ${policy.arn} ${policy.type}`.toLowerCase().includes(q);
  });
  const runSavedAnalysis = async () => {
    if (!changes.length) return;
    if (changes.length > 50) { setAnalysisError('This saved set has more than 50 changes. Remove or split changes before running one preview.'); return; }
    setAnalysisLoading(true); setAnalysisError('');
    try {
      setAnalysis(await previewSimulationChange({ changes: changes.map(({ action, principal_type, principal_id, policy_arn }) => ({ action, principal_type, principal_id, policy_arn })) }));
    } catch (error) {
      const value = error as { response?: { data?: { detail?: unknown } }; message?: string };
      const detail = value.response?.data?.detail;
      setAnalysisError(typeof detail === 'string' ? detail : value.message || 'The saved change set could not be analyzed.');
    } finally { setAnalysisLoading(false); }
  };

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
                Saved Changes
              </h1>
              <p className="text-xs text-enterprise-subtext mt-0.5">
                {pendingCount} saved change{pendingCount !== 1 ? 's' : ''} in this draft set — edit and re-run the analysis at any time
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {pendingCount > 0 && <button
                onClick={runSavedAnalysis}
                disabled={analysisLoading}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-enterprise-accent text-white text-sm font-semibold disabled:opacity-50"
              ><Play className="w-4 h-4" />{analysisLoading ? 'Analyzing…' : 'Run analysis'}</button>}
              <button
                onClick={() => { setAdding((value) => !value); setEditingId(null); setEditValue(null); setPolicySearch(''); }}
                className="flex items-center gap-2 px-4 py-2 rounded-lg border border-enterprise-accent/40 text-enterprise-accent text-sm font-semibold hover:bg-enterprise-accent/10"
              ><Plus className="w-4 h-4" />Add change</button>
              {pendingCount > 0 && <button
                id="reset-simulation-btn"
                onClick={() => resetMutation.mutate()}
                disabled={resetMutation.isPending}
                className="flex items-center gap-2 px-4 py-2 rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 hover:bg-red-500/20 text-sm font-semibold transition-colors disabled:opacity-50"
              >
                <RotateCcw className="w-4 h-4" />
                Reset Simulation
              </button>}
            </div>
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
                <p className="text-[10px] uppercase tracking-wider text-enterprise-subtext mb-2">Current Security Posture</p>
                <p className="text-3xl font-bold text-white">{riskData.current_score}<span className="text-sm text-enterprise-subtext">/100</span></p>
                <p className={`text-xs font-semibold mt-1 uppercase ${SeverityColor[riskData.current_severity] ?? 'text-gray-400'}`}>
                  {riskData.current_severity} residual risk
                </p>
                <p className="text-[10px] text-enterprise-subtext mt-1">CURRENT AWS STATE</p>
              </div>

              {/* Delta */}
              <div className="bg-enterprise-card border border-enterprise-accent/20 rounded-xl p-4 text-center flex flex-col items-center justify-center">
                <p className="text-[10px] uppercase tracking-wider text-enterprise-subtext mb-2">Risk Change</p>
                <div className="text-2xl font-bold">
                  <DeltaBadge delta={riskData.delta} />
                </div>
                <p className="text-[10px] text-enterprise-subtext mt-2">Positive means posture improved</p>
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
                riskData.delta < 0 ? 'border-red-500/30' : riskData.delta > 0 ? 'border-green-500/30' : 'border-enterprise-border'
              }`}>
                <p className="text-[10px] uppercase tracking-wider text-enterprise-subtext mb-2">Projected Security Posture</p>
                <p className={`text-3xl font-bold ${
                  riskData.delta < -10 ? 'text-red-400' : riskData.delta > 5 ? 'text-green-400' : 'text-white'
                }`}>{riskData.desired_score}<span className="text-sm text-enterprise-subtext">/100</span></p>
                <p className={`text-xs font-semibold mt-1 uppercase ${SeverityColor[riskData.desired_severity] ?? 'text-gray-400'}`}>
                  {riskData.desired_severity} residual risk
                </p>
                <p className="text-[10px] text-enterprise-subtext mt-1">PROJECTED POSTURE</p>
              </div>
            </motion.div>
          )}

          {analysisError && <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">{analysisError}</div>}
          {analysis && <section className="rounded-xl border border-enterprise-accent/30 bg-enterprise-card p-4 space-y-3">
            <div className="flex items-center justify-between"><div><h2 className="font-semibold text-white">Latest saved-set analysis</h2><p className="text-xs text-enterprise-subtext">Recalculated against the current scan · simulation only</p></div><button onClick={() => setAnalysis(null)} aria-label="Dismiss analysis" className="p-1 text-enterprise-subtext hover:text-white"><X className="h-4 w-4" /></button></div>
            {analysis.risk_comparison && <div className="grid gap-2 sm:grid-cols-3"><div className="rounded-lg bg-enterprise-bg p-3 text-sm">Current posture <strong className="float-right">{analysis.risk_comparison.current_score}/100</strong></div><div className="rounded-lg bg-enterprise-bg p-3 text-sm">Projected posture <strong className="float-right">{analysis.risk_comparison.desired_score}/100</strong></div><div className="rounded-lg bg-enterprise-bg p-3 text-sm">Posture change <strong className="float-right">{analysis.risk_comparison.delta > 0 ? '+' : ''}{analysis.risk_comparison.delta}</strong></div></div>}
            <div className="flex flex-wrap gap-4 text-xs"><span className="text-red-300">{analysis.attack_path_comparison?.new_paths?.length ?? 0} added paths</span><span className="text-emerald-300">{analysis.attack_path_comparison?.removed_paths?.length ?? 0} removed paths</span><span className="text-amber-200">{analysis.new_reachable_resources?.length ?? 0} newly reachable assets</span></div>
            {analysis.analysis_warnings?.map((warning) => <p key={warning} className="text-xs text-amber-200">{warning}</p>)}
          </section>}

          {adding && <section className="rounded-xl border border-enterprise-accent/30 bg-enterprise-card p-4">
            <h2 className="mb-3 font-semibold text-white">Add a change to this saved set</h2>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="text-xs text-enterprise-subtext">Change type<select value={addValue.action} onChange={(e) => setAddValue({ ...addValue, action: e.target.value as SimulationChangePayload['action'] })} className="mt-1 block w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-2 text-sm text-white"><option value="ATTACH_POLICY">Attach policy</option><option value="DETACH_POLICY">Detach policy</option></select></label>
              <label className="text-xs text-enterprise-subtext">Identity<select value={`${addValue.principal_type}:${addValue.principal_id}`} onChange={(e) => { const target = identityOptions.find((x) => `${x.type}:${x.id}` === e.target.value); if (target) setAddValue({ ...addValue, principal_type: target.type, principal_id: target.id }); }} className="mt-1 block w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-2 text-sm text-white"><option value="">Choose an identity</option>{identityOptions.map((x) => <option key={`${x.type}:${x.id}`} value={`${x.type}:${x.id}`}>{x.label}</option>)}</select></label>
              <label className="text-xs text-enterprise-subtext sm:col-span-2">Find a policy<input value={policySearch} onChange={(e) => setPolicySearch(e.target.value)} placeholder="Search policy name or ARN" className="mt-1 block w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-2 text-sm text-white placeholder:text-enterprise-subtext" /></label>
              <label className="text-xs text-enterprise-subtext sm:col-span-2">Policy<select value={addValue.policy_arn} onChange={(e) => setAddValue({ ...addValue, policy_arn: e.target.value })} className="mt-1 block w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-2 text-sm text-white"><option value="">Choose a policy ({matchingEditPolicies.length} matches)</option>{matchingEditPolicies.map((policy) => <option key={policy.arn} value={policy.arn}>{policy.name} · {policy.type}</option>)}</select></label>
              <div className="flex gap-2 sm:col-span-2"><button onClick={() => addMutation.mutate(addValue)} disabled={addMutation.isPending || !addValue.principal_id || !addValue.policy_arn} className="inline-flex items-center gap-2 rounded-lg bg-enterprise-accent px-3 py-2 text-xs font-semibold text-white disabled:opacity-50"><Check className="h-4 w-4" />{addMutation.isPending ? 'Adding…' : 'Add to saved set'}</button><button onClick={() => { setAdding(false); addMutation.reset(); }} className="rounded-lg border border-enterprise-border px-3 py-2 text-xs text-enterprise-subtext">Cancel</button></div>
              {addMutation.isError && <p role="alert" className="text-xs text-red-300 sm:col-span-2">{getErrorText(addMutation.error)}</p>}
            </div>
          </section>}

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
                Saved change sets will appear here for later review. Start in{' '}
                <Link to="/simulation" className="text-enterprise-accent hover:underline">What‑If Analysis</Link>.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              <p className="text-xs text-enterprise-subtext uppercase tracking-wider">Simulation Changes</p>
              <AnimatePresence mode="popLayout">
                {changes.map(change => (
                  <div key={change.change_id} className="space-y-2">
                    <ChangeRow change={change} onRemove={() => removeMutation.mutate(change.change_id)} />
                    {editingId === change.change_id && editValue && <div className="grid gap-3 rounded-xl border border-enterprise-accent/25 bg-enterprise-card p-4 sm:grid-cols-2">
                      <label className="text-xs text-enterprise-subtext">Change type<select value={editValue.action} onChange={(e) => setEditValue({ ...editValue, action: e.target.value as SimulationChangePayload['action'] })} className="mt-1 block w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-2 text-sm text-white"><option value="ATTACH_POLICY">Attach policy</option><option value="DETACH_POLICY">Detach policy</option></select></label>
                      <label className="text-xs text-enterprise-subtext">Identity<select value={`${editValue.principal_type}:${editValue.principal_id}`} onChange={(e) => { const target = identityOptions.find((x) => `${x.type}:${x.id}` === e.target.value); if (target) setEditValue({ ...editValue, principal_type: target.type, principal_id: target.id }); }} className="mt-1 block w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-2 text-sm text-white">{identityOptions.map((x) => <option key={`${x.type}:${x.id}`} value={`${x.type}:${x.id}`}>{x.label}</option>)}</select></label>
                      <label className="text-xs text-enterprise-subtext sm:col-span-2">Find a policy<input value={policySearch} onChange={(e) => setPolicySearch(e.target.value)} placeholder="Search policy name or ARN" className="mt-1 block w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-2 text-sm text-white placeholder:text-enterprise-subtext" /></label>
                      <label className="text-xs text-enterprise-subtext sm:col-span-2">Policy<select value={editValue.policy_arn} onChange={(e) => setEditValue({ ...editValue, policy_arn: e.target.value })} className="mt-1 block w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-2 text-sm text-white">{!matchingEditPolicies.some((policy) => policy.arn === editValue.policy_arn) && <option value={editValue.policy_arn}>{change.policy_name} · currently saved</option>}{matchingEditPolicies.map((policy) => <option key={policy.arn} value={policy.arn}>{policy.name} · {policy.type}</option>)}</select></label>
                      <div className="flex gap-2 sm:col-span-2"><button onClick={() => updateMutation.mutate({ id: change.change_id, change: editValue })} disabled={updateMutation.isPending || !editValue.policy_arn || !editValue.principal_id} className="inline-flex items-center gap-2 rounded-lg bg-enterprise-accent px-3 py-2 text-xs font-semibold text-white disabled:opacity-50"><Check className="h-4 w-4" />{updateMutation.isPending ? 'Saving…' : 'Save edit'}</button><button onClick={() => { setEditingId(null); setEditValue(null); }} className="rounded-lg border border-enterprise-border px-3 py-2 text-xs text-enterprise-subtext">Cancel</button></div>
                      {updateMutation.isError && <p role="alert" className="text-xs text-red-300 sm:col-span-2">{getErrorText(updateMutation.error)}</p>}
                    </div>}
                    {editingId !== change.change_id && <button onClick={() => { setEditingId(change.change_id); setEditValue({ action: change.action, principal_type: change.principal_type, principal_id: change.principal_id, policy_arn: change.policy_arn }); }} className="ml-12 inline-flex items-center gap-1 text-xs text-enterprise-accent hover:underline"><Pencil className="h-3 w-3" />Edit saved change</button>}
                  </div>
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
