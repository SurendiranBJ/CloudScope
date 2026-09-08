import { useState, useMemo } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, Shield, RefreshCw,
  AlertTriangle, CheckCircle, Info, ChevronDown, ChevronUp,
  Lock, Tag, Users, Activity, Plus, Minus, X
} from 'lucide-react';
import { getPolicyCatalog, getPolicyById } from '../api/policies';
import { getSimulationState, addSimulationChange, type SimulationChangePayload } from '../api/simulation';
import { getIAMUsers } from '../api/users';
import { getIAMRoles } from '../api/roles';
import { SimulationPreviewModal } from '../components/SimulationPreviewModal';
import type { PolicyCatalogEntry } from '../types';

type FilterType = 'all' | 'aws-managed' | 'customer-managed' | 'inline';
type SortField = 'name' | 'riskScore' | 'attachmentCount';

const severityColors = {
  critical: { bg: 'bg-red-500/15', text: 'text-red-400', border: 'border-red-500/30' },
  high: { bg: 'bg-amber-500/15', text: 'text-amber-400', border: 'border-amber-500/30' },
  medium: { bg: 'bg-blue-500/15', text: 'text-blue-400', border: 'border-blue-500/30' },
  low: { bg: 'bg-green-500/15', text: 'text-green-400', border: 'border-green-500/30' },
  unknown: { bg: 'bg-gray-500/15', text: 'text-gray-400', border: 'border-gray-500/30' },
};

function SeverityBadge({ severity }: { severity: string }) {
  const c = severityColors[severity as keyof typeof severityColors] ?? severityColors.unknown;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wide border ${c.bg} ${c.text} ${c.border}`}>
      {severity}
    </span>
  );
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 80 ? '#EF4444' : score >= 60 ? '#F59E0B' : score >= 40 ? '#3B82F6' : '#10B981';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${score}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs font-mono text-gray-300 w-8 text-right">{score}</span>
    </div>
  );
}

export const Policies: React.FC = () => {
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<FilterType>('all');
  const [sortField, setSortField] = useState<SortField>('riskScore');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [selected, setSelected] = useState<PolicyCatalogEntry | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [attachPrincipalType, setAttachPrincipalType] = useState<'USER' | 'GROUP' | 'ROLE'>('USER');
  const [attachPrincipalId, setAttachPrincipalId] = useState('');
  const [attachMsg, setAttachMsg] = useState('');
  const [previewModalOpen, setPreviewModalOpen] = useState(false);
  const [pendingChange, setPendingChange] = useState<SimulationChangePayload | null>(null);
  const qc = useQueryClient();

  const { data: discoveredUsers = [] } = useQuery({
    queryKey: ['iam-users'],
    queryFn: getIAMUsers,
  });

  const { data: discoveredRoles = [] } = useQuery({
    queryKey: ['iam-roles'],
    queryFn: getIAMRoles,
  });

  const { data: policies = [], isLoading, refetch } = useQuery({
    queryKey: ['policies', filter, search],
    queryFn: () => getPolicyCatalog({
      type_filter: filter === 'all' ? undefined : filter,
      search: search || undefined,
      limit: 500,
    }),
    staleTime: 60_000,
  });

  const { data: simState } = useQuery({
    queryKey: ['simulation-state'],
    queryFn: getSimulationState,
    refetchInterval: 5000,
  });

  const addChangeMutation = useMutation({
    mutationFn: addSimulationChange,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['simulation-state'] });
      setAttachMsg('✓ Simulation change added. SIMULATION ONLY — NOT APPLIED TO AWS.');
      setTimeout(() => setAttachMsg(''), 4000);
    },
    onError: (err: Error) => {
      setAttachMsg(`Error: ${err.message}`);
    },
  });

  const sorted = useMemo(() => {
    return [...policies].sort((a, b) => {
      const av = a[sortField] ?? 0;
      const bv = b[sortField] ?? 0;
      if (typeof av === 'string' && typeof bv === 'string') {
        return sortDir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
      }
      return sortDir === 'asc' ? (av as number) - (bv as number) : (bv as number) - (av as number);
    });
  }, [policies, sortField, sortDir]);

  const handleSelectPolicy = async (policy: PolicyCatalogEntry) => {
    setSelected(policy);
    if (!policy.document) {
      setDetailLoading(true);
      try {
        const detail = await getPolicyById(policy.arn || policy.name);
        setSelected(detail);
      } catch { /* keep metadata-only view */ }
      finally { setDetailLoading(false); }
    }
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortField(field); setSortDir('desc'); }
  };

  const handleOpenPreview = (action: 'ATTACH_POLICY' | 'DETACH_POLICY') => {
    if (!selected || !attachPrincipalId.trim()) {
      setAttachMsg('Enter or select a principal ID first.');
      return;
    }
    setPendingChange({
      action,
      principal_type: attachPrincipalType,
      principal_id: attachPrincipalId.trim(),
      policy_arn: selected.arn,
    });
    setPreviewModalOpen(true);
  };

  const handleConfirmSimulation = async () => {
    if (!pendingChange) return;
    try {
      await addChangeMutation.mutateAsync(pendingChange);
      setPreviewModalOpen(false);
      setPendingChange(null);
    } catch {
      // Error handled in addChangeMutation.onError
    }
  };

  const filterTabs: { label: string; value: FilterType }[] = [
    { label: 'All', value: 'all' },
    { label: 'Customer-Managed', value: 'customer-managed' },
    { label: 'AWS-Managed', value: 'aws-managed' },
    { label: 'Inline', value: 'inline' },
  ];

  return (
    <div className="flex h-full overflow-hidden">
      {/* Left: Policy Catalog */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden border-r border-enterprise-border">
        {/* Header */}
        <div className="shrink-0 px-6 py-4 border-b border-enterprise-border">
          <div className="flex items-center justify-between gap-4 mb-4">
            <div>
              <h1 className="text-xl font-bold text-white flex items-center gap-2">
                <Lock className="w-5 h-5 text-enterprise-accent" />
                Policy Catalog
              </h1>
              <p className="text-xs text-enterprise-subtext mt-0.5">Browse AWS IAM policies and simulate changes</p>
            </div>
            <div className="flex items-center gap-2">
              {simState?.simulation_active && (
                <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-semibold">
                  <Activity className="w-3.5 h-3.5" />
                  {simState.pending_changes} sim change{simState.pending_changes !== 1 ? 's' : ''} active
                </div>
              )}
              <button onClick={() => refetch()} className="p-2 rounded-lg border border-enterprise-border hover:bg-gray-800/50 text-enterprise-subtext hover:text-white transition-colors">
                <RefreshCw className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Search */}
          <div className="relative mb-3">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-enterprise-subtext" />
            <input
              id="policy-search"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search policies by name..."
              className="w-full pl-9 pr-4 py-2 bg-enterprise-card border border-enterprise-border rounded-lg text-sm text-gray-200 placeholder-enterprise-subtext focus:outline-none focus:border-enterprise-accent"
            />
          </div>

          {/* Filter tabs */}
          <div className="flex gap-1">
            {filterTabs.map(t => (
              <button
                key={t.value}
                onClick={() => setFilter(t.value)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  filter === t.value
                    ? 'bg-enterprise-accent/15 text-enterprise-accent border border-enterprise-accent/30'
                    : 'text-enterprise-subtext hover:text-white hover:bg-gray-800/50'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        {/* Sort header */}
        <div className="shrink-0 grid grid-cols-[1fr_120px_100px_80px] gap-2 px-6 py-2 text-[10px] uppercase tracking-wider text-enterprise-subtext border-b border-enterprise-border">
          <button onClick={() => handleSort('name')} className="text-left flex items-center gap-1 hover:text-white">
            Policy Name {sortField === 'name' && (sortDir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />)}
          </button>
          <button onClick={() => handleSort('attachmentCount')} className="flex items-center gap-1 hover:text-white">
            Attachments {sortField === 'attachmentCount' && (sortDir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />)}
          </button>
          <button onClick={() => handleSort('riskScore')} className="flex items-center gap-1 hover:text-white">
            Risk {sortField === 'riskScore' && (sortDir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />)}
          </button>
          <span>Type</span>
        </div>

        {/* Policy list */}
        <div className="flex-1 overflow-y-auto">
          {isLoading ? (
            <div className="flex items-center justify-center h-40 text-enterprise-subtext">
              <RefreshCw className="w-5 h-5 animate-spin mr-2" /> Loading policy catalog...
            </div>
          ) : sorted.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-40 gap-2 text-enterprise-subtext">
              <Shield className="w-8 h-8" />
              <p className="text-sm">No policies found</p>
              <p className="text-xs">Run a scan first to populate the catalog</p>
            </div>
          ) : (
            sorted.map((policy) => (
              <motion.button
                key={policy.arn || policy.name}
                onClick={() => handleSelectPolicy(policy)}
                whileHover={{ backgroundColor: 'rgba(255,255,255,0.03)' }}
                className={`w-full grid grid-cols-[1fr_120px_100px_80px] gap-2 items-center px-6 py-3 border-b border-enterprise-border/50 text-left transition-colors ${
                  selected?.arn === policy.arn ? 'bg-enterprise-accent/5 border-l-2 border-l-enterprise-accent' : ''
                }`}
              >
                <div className="min-w-0">
                  <p className="text-sm font-medium text-gray-200 truncate">{policy.name}</p>
                  <p className="text-[10px] text-enterprise-subtext truncate font-mono">{policy.arn}</p>
                </div>
                <div className="flex items-center gap-1 text-xs text-enterprise-subtext">
                  <Users className="w-3 h-3" />
                  {policy.attachmentCount}
                </div>
                <div>
                  <RiskBar score={policy.riskScore} />
                </div>
                <div>
                  <SeverityBadge severity={policy.severity} />
                </div>
              </motion.button>
            ))
          )}
        </div>

        {/* Count footer */}
        {!isLoading && (
          <div className="shrink-0 px-6 py-2 border-t border-enterprise-border text-[10px] text-enterprise-subtext">
            {sorted.length} polic{sorted.length !== 1 ? 'ies' : 'y'} displayed
          </div>
        )}
      </div>

      {/* Right: Policy Detail Panel */}
      <AnimatePresence>
        {selected && (
          <motion.div
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 420, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            className="shrink-0 w-[420px] flex flex-col overflow-hidden bg-enterprise-card"
          >
            <div className="flex items-center justify-between px-5 py-4 border-b border-enterprise-border">
              <h2 className="text-sm font-semibold text-white truncate pr-2">{selected.name}</h2>
              <button onClick={() => setSelected(null)} className="shrink-0 p-1 rounded hover:bg-gray-700 text-enterprise-subtext hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
              {detailLoading && (
                <div className="flex items-center gap-2 text-enterprise-subtext text-xs">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Loading policy document...
                </div>
              )}

              {/* Meta */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <SeverityBadge severity={selected.severity} />
                  <span className="text-xs font-mono text-enterprise-subtext">{selected.riskScore}/100 risk</span>
                </div>
                <div className="text-[10px] text-enterprise-subtext font-mono break-all">{selected.arn}</div>
                <div className="flex gap-2 flex-wrap">
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-gray-800 text-gray-400 border border-gray-700">
                    <Tag className="w-2.5 h-2.5" /> {selected.type}
                  </span>
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-gray-800 text-gray-400 border border-gray-700">
                    <Users className="w-2.5 h-2.5" /> {selected.attachmentCount} attachment{selected.attachmentCount !== 1 ? 's' : ''}
                  </span>
                  {selected.isAttachable && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-green-900/30 text-green-400 border border-green-700/30">
                      <CheckCircle className="w-2.5 h-2.5" /> Attachable
                    </span>
                  )}
                </div>
                {selected.description && (
                  <p className="text-xs text-enterprise-subtext">{selected.description}</p>
                )}
              </div>

              {/* Risk findings */}
              {selected.findings && selected.findings.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wider">Risk Findings</p>
                  <div className="space-y-1.5">
                    {selected.findings.map((f, i) => (
                      <div key={i} className="flex items-start gap-2 p-2 rounded-lg bg-red-500/5 border border-red-500/15">
                        <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                        <div>
                          <p className="text-[10px] font-mono text-red-300">{f.code} (+{f.points}pts)</p>
                          <p className="text-[10px] text-gray-400">{f.reason}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Attached to */}
              {selected.attachedTo && selected.attachedTo.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wider">Attached To</p>
                  <div className="space-y-1">
                    {selected.attachedTo.map((a, i) => (
                      <div key={i} className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-gray-800/50 text-xs">
                        <span className="text-enterprise-accent font-mono text-[10px]">{a.type}</span>
                        <span className="text-gray-300">{a.name}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Document preview */}
              {selected.document && (
                <div>
                  <p className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wider">Policy Document</p>
                  <pre className="text-[10px] font-mono text-gray-400 bg-gray-900/50 rounded-lg p-3 overflow-auto max-h-48 border border-enterprise-border">
                    {JSON.stringify(JSON.parse(selected.document), null, 2)}
                  </pre>
                </div>
              )}
              {selected.documentUnavailable && !selected.document && (
                <div className="flex items-center gap-2 text-xs text-amber-400 p-3 rounded-lg bg-amber-500/5 border border-amber-500/15">
                  <Info className="w-3.5 h-3.5 shrink-0" />
                  Policy document not available. AWS permissions may be insufficient to read this document.
                </div>
              )}

              {/* Simulation attach/detach */}
              {selected.isAttachable && (
                <div className="border border-enterprise-border rounded-lg p-4 space-y-3">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-amber-400">
                    <Activity className="w-3.5 h-3.5" />
                    Simulate Policy Change
                  </div>
                  <p className="text-[10px] text-enterprise-subtext">
                    Changes are <strong className="text-amber-400">SIMULATION ONLY</strong> — NOT applied to AWS.
                  </p>

                  <div className="space-y-2">
                    <div className="flex gap-2">
                      {(['USER', 'GROUP', 'ROLE'] as const).map(pt => (
                        <button
                          key={pt}
                          onClick={() => setAttachPrincipalType(pt)}
                          className={`flex-1 py-1.5 rounded-lg text-[10px] font-medium transition-all ${
                            attachPrincipalType === pt
                              ? 'bg-enterprise-accent text-white'
                              : 'bg-gray-800 text-gray-400 hover:text-white'
                          }`}
                        >
                          {pt}
                        </button>
                      ))}
                    </div>
                    <input
                      id={`sim-principal-${selected.name}`}
                      list="discovered-principals"
                      value={attachPrincipalId}
                      onChange={e => setAttachPrincipalId(e.target.value)}
                      placeholder={`Select or enter ${attachPrincipalType.toLowerCase()} name...`}
                      className="w-full px-3 py-2 bg-enterprise-bg border border-enterprise-border rounded-lg text-xs text-gray-200 placeholder-enterprise-subtext focus:outline-none focus:border-enterprise-accent font-mono"
                    />
                    <datalist id="discovered-principals">
                      {attachPrincipalType === 'USER' && discoveredUsers.map(u => (
                        <option key={u.name} value={u.name} />
                      ))}
                      {attachPrincipalType === 'ROLE' && discoveredRoles.map(r => (
                        <option key={r.name} value={r.name} />
                      ))}
                    </datalist>

                    <div className="flex gap-2">
                      <button
                        id={`attach-btn-${selected.name}`}
                        onClick={() => handleOpenPreview('ATTACH_POLICY')}
                        disabled={addChangeMutation.isPending}
                        className="flex-1 flex items-center justify-center gap-1.5 py-2 rounded-lg bg-green-600/80 hover:bg-green-600 text-white text-xs font-semibold transition-colors disabled:opacity-50"
                      >
                        <Plus className="w-3.5 h-3.5" /> Attach
                      </button>
                      <button
                        id={`detach-btn-${selected.name}`}
                        onClick={() => handleOpenPreview('DETACH_POLICY')}
                        disabled={addChangeMutation.isPending}
                        className="flex-1 flex items-center justify-center gap-1.5 py-2 rounded-lg bg-red-600/80 hover:bg-red-600 text-white text-xs font-semibold transition-colors disabled:opacity-50"
                      >
                        <Minus className="w-3.5 h-3.5" /> Detach
                      </button>
                    </div>
                    {attachMsg && (
                      <p className={`text-[10px] ${attachMsg.startsWith('✓') ? 'text-green-400' : 'text-red-400'}`}>
                        {attachMsg}
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* SIMULATION PREVIEW MODAL */}
      <SimulationPreviewModal
        isOpen={previewModalOpen}
        onClose={() => {
          setPreviewModalOpen(false);
          setPendingChange(null);
        }}
        onConfirm={handleConfirmSimulation}
        payload={pendingChange}
        policyName={selected?.name}
        isConfirming={addChangeMutation.isPending}
      />
    </div>
  );
};
