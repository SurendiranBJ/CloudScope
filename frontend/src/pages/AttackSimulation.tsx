import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Link } from 'react-router-dom';
import { AlertTriangle, ArrowDownRight, ArrowUpRight, Check, Maximize2, Minimize2, Play, Plus, RefreshCw, Search, ShieldCheck, Trash2, Waypoints, X } from 'lucide-react';
import { addSimulationChanges, getSimulationGroups, previewSimulationChange, type SimulationChangePayload } from '../api/simulation';
import { getIAMUsers } from '../api/users';
import { getIAMRoles } from '../api/roles';
import { getPolicyCatalog } from '../api/policies';
import type { AttackPath, IAMRole, IAMUser, PolicyCatalogEntry, SimulationAnalysis, SimulationResourceDelta } from '../types';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { ENTITY_STYLES, normalizeGraphType } from '../constants/graphStyles';
import { useSnapshotView } from '../context/SnapshotViewContext';

cytoscape.use(dagre);

type Principal = { id: string; name: string; type: 'USER' | 'ROLE' | 'GROUP'; policyNames: string[]; policyArns?: Record<string, string> };
type QueuedChange = SimulationChangePayload & { localId: string };

const errorMessage = (error: unknown) => {
  const responseError = error as { response?: { data?: { detail?: unknown } }; message?: string };
  const detail = responseError.response?.data?.detail;
  if (typeof detail === 'string') return detail;
  if (detail && typeof detail === 'object') return Object.values(detail as Record<string, unknown>).map(String).join(' ');
  return responseError.message || 'The request could not be completed.';
};

const isPolicyAttached = (principal: Principal | undefined, policy: PolicyCatalogEntry, queuedChanges: QueuedChange[]) => {
  if (!principal) return false;
  let attached = principal.policyNames.includes(policy.name) || Object.values(principal.policyArns || {}).includes(policy.arn);
  queuedChanges.forEach((change) => {
    if (change.principal_type === principal.type && change.principal_id === principal.id && change.policy_arn === policy.arn) {
      attached = change.action === 'ATTACH_POLICY';
    }
  });
  return attached;
};

const POLICY_SEARCH_ALIASES: Record<string, string[]> = {
  ecr: ['containerregistry', 'elasticcontainerregistry', 'elastic container registry'],
  ecs: ['containerservice', 'elasticcontainerservice', 'elastic container service'],
};

const policyMatchesSearch = (policy: PolicyCatalogEntry, rawQuery: string) => {
  const query = rawQuery.trim().toLowerCase();
  if (!query) return true;
  const searchable = `${policy.name} ${policy.arn} ${policy.type}`.toLowerCase();
  const aliases = POLICY_SEARCH_ALIASES[query] || [];
  return searchable.includes(query) || aliases.some((alias) => searchable.includes(alias));
};

export const AttackSimulation: React.FC = () => {
  const { snapshotId } = useSnapshotView();
  const [users, setUsers] = useState<IAMUser[]>([]);
  const [roles, setRoles] = useState<IAMRole[]>([]);
  const [groups, setGroups] = useState<{ name: string; attachedPolicies?: string[]; attachedPolicyArns?: Record<string, string> }[]>([]);
  const [policies, setPolicies] = useState<PolicyCatalogEntry[]>([]);
  const [loadingCatalog, setLoadingCatalog] = useState(true);
  const [catalogError, setCatalogError] = useState('');
  const [action, setAction] = useState<SimulationChangePayload['action']>('ATTACH_POLICY');
  const [principalKey, setPrincipalKey] = useState('');
  const [policyArn, setPolicyArn] = useState('');
  const [policySearch, setPolicySearch] = useState('');
  const [policyPickerOpen, setPolicyPickerOpen] = useState(false);
  const [identitySearch, setIdentitySearch] = useState('');
  const [queuedChanges, setQueuedChanges] = useState<QueuedChange[]>([]);
  const [analysis, setAnalysis] = useState<SimulationAnalysis | null>(null);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState('');
  const [draftSaved, setDraftSaved] = useState(false);
  const [savingDraft, setSavingDraft] = useState(false);
  const [comparisonFullscreen, setComparisonFullscreen] = useState(false);

  useEffect(() => {
    if (!comparisonFullscreen) return;
    const priorOverflow = document.body.style.overflow;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setComparisonFullscreen(false); };
    document.body.style.overflow = 'hidden';
    window.addEventListener('keydown', closeOnEscape);
    return () => {
      document.body.style.overflow = priorOverflow;
      window.removeEventListener('keydown', closeOnEscape);
    };
  }, [comparisonFullscreen]);

  useEffect(() => {
    let active = true;
    const loadAllPolicies = async () => {
      const firstPage = await getPolicyCatalog({ page: 1, page_size: 1000 });
      if (firstPage.total_pages <= 1) return firstPage.items;
      const remainingPages = await Promise.all(Array.from({ length: firstPage.total_pages - 1 }, (_, index) => getPolicyCatalog({ page: index + 2, page_size: 1000 })));
      return [...firstPage.items, ...remainingPages.flatMap((page) => page.items)];
    };
    Promise.all([getIAMUsers(), getIAMRoles(), getSimulationGroups(), loadAllPolicies()])
      .then(([userData, roleData, groupData, policyData]) => {
        if (!active) return;
        setUsers(userData);
        setRoles(roleData);
        setGroups(groupData);
        setPolicies(policyData.filter((policy) => policy.isAttachable && policy.arn));
        setCatalogError('');
      })
      .catch((error: unknown) => { if (active) setCatalogError(errorMessage(error)); })
      .finally(() => { if (active) setLoadingCatalog(false); });
    return () => { active = false; };
  }, []);

  const principals = useMemo<Principal[]>(() => [
    ...users.map((user) => ({ id: user.name, name: user.name, type: 'USER' as const, policyNames: user.policies || [] })),
    ...roles.map((role) => ({ id: role.name, name: role.name, type: 'ROLE' as const, policyNames: role.attachedPolicies || role.policies || [] })),
    ...groups.map((group) => ({ id: group.name, name: group.name, type: 'GROUP' as const, policyNames: group.attachedPolicies || [], policyArns: group.attachedPolicyArns })),
  ], [users, roles, groups]);

  const selectedPrincipal = principals.find((principal) => `${principal.type}:${principal.id}` === principalKey);
  const visiblePrincipals = useMemo(() => {
    const query = identitySearch.trim().toLowerCase();
    return query ? principals.filter((principal) => `${principal.name} ${principal.id} ${principal.type}`.toLowerCase().includes(query)) : principals;
  }, [identitySearch, principals]);
  const matchingPolicies = useMemo(() => {
    return policies.filter((policy) => policyMatchesSearch(policy, policySearch));
  }, [policies, policySearch]);
  const availablePolicies = useMemo(() => action === 'DETACH_POLICY'
    ? matchingPolicies.filter((policy) => isPolicyAttached(selectedPrincipal, policy, queuedChanges))
    : matchingPolicies,
  [action, matchingPolicies, selectedPrincipal, queuedChanges]);
  const accountPolicies = availablePolicies.filter((policy) => policy.type === 'customer-managed');
  const awsPolicies = availablePolicies.filter((policy) => policy.type === 'aws-managed');
  const selectedPolicy = policies.find((policy) => policy.arn === policyArn);
  const selectedPolicyAttached = !!selectedPolicy && isPolicyAttached(selectedPrincipal, selectedPolicy, queuedChanges);
  const canQueueSelectedPolicy = !!selectedPrincipal && !!selectedPolicy && (action === 'ATTACH_POLICY' ? !selectedPolicyAttached : selectedPolicyAttached);

  useEffect(() => {
    if (!visiblePrincipals.some((principal) => `${principal.type}:${principal.id}` === principalKey)) {
      const first = visiblePrincipals[0];
      setPrincipalKey(first ? `${first.type}:${first.id}` : '');
    }
  }, [visiblePrincipals, principalKey]);

  useEffect(() => {
    if (!availablePolicies.some((policy) => policy.arn === policyArn)) setPolicyArn(availablePolicies[0]?.arn || '');
  }, [availablePolicies, policyArn]);

  const runPreview = async () => {
    if (!queuedChanges.length) {
      setRunError('Add at least one policy change to the preview list first.');
      return;
    }
    setRunning(true);
    setRunError('');
    setDraftSaved(false);
    setAnalysis(null);
    try {
      setAnalysis(await previewSimulationChange({ changes: queuedChanges.map(({ localId: _localId, ...change }) => change) }));
    } catch (error: unknown) {
      setRunError(errorMessage(error));
    } finally {
      setRunning(false);
    }
  };

  const saveDraft = async () => {
    if (snapshotId || !analysis || !queuedChanges.length) return;
    setSavingDraft(true);
    setRunError('');
    try {
      await addSimulationChanges(queuedChanges.map(({ localId: _localId, ...change }) => change));
      setDraftSaved(true);
    } catch (error: unknown) {
      setRunError(errorMessage(error));
    } finally {
      setSavingDraft(false);
    }
  };

  const queueSelectedChange = () => {
    if (!canQueueSelectedPolicy || !selectedPrincipal || !selectedPolicy) return;
    setQueuedChanges((changes) => [...changes, {
      localId: `${Date.now()}-${changes.length}`,
      action,
      principal_type: selectedPrincipal.type,
      principal_id: selectedPrincipal.id,
      policy_arn: selectedPolicy.arn,
    }]);
    setAnalysis(null);
    setRunError('');
    setDraftSaved(false);
  };

  const risk = analysis?.risk_comparison;
  const blast = analysis?.blast_radius_comparison;
  const scopedIdentityNames = useMemo(() => {
    const names = new Set<string>();
    queuedChanges.forEach((change) => {
      names.add(change.principal_id.toLowerCase());
      if (change.principal_type === 'GROUP') {
        users.filter((user) => user.groups?.includes(change.principal_id)).forEach((user) => names.add(user.name.toLowerCase()));
      }
    });
    return names;
  }, [queuedChanges, users]);
  const graphFocusIdentities = useMemo(() => {
    const unique = new Map<string, { type: string; name: string }>();
    queuedChanges.forEach((change) => {
      const key = `${change.principal_type}:${change.principal_id}`;
      unique.set(key, { type: change.principal_type, name: change.principal_id });
    });
    return [...unique.values()];
  }, [queuedChanges]);
  const pathMatchesScope = (path: AttackPath) => {
    const candidates = [path.source, path.source_asset, path.destination, path.target, ...(path.ordered_nodes || path.nodes || []).flatMap((node) => [node.id, node.name])];
    return candidates.some((value) => {
      const raw = String(value || '').toLowerCase();
      const normalized = raw.replace(/^aws:(user|role|group):/, '');
      return scopedIdentityNames.has(raw) || scopedIdentityNames.has(normalized);
    });
  };
  const newPaths = (analysis?.attack_path_comparison?.new_paths || []).filter(pathMatchesScope);
  const removedPaths = (analysis?.attack_path_comparison?.removed_paths || []).filter(pathMatchesScope);
  const changedPaths = (analysis?.attack_path_comparison?.changed_paths || []).filter((item) => pathMatchesScope(item.current) || pathMatchesScope(item.desired));
  const scopedCurrentPaths = (analysis?.current_attack_paths || []).filter(pathMatchesScope);
  const scopedDesiredPaths = (analysis?.desired_attack_paths || []).filter(pathMatchesScope);
  const newResources = (analysis?.new_reachable_resources || blast?.new_reachable_resources || []).filter((resource) => scopedIdentityNames.has((resource.identity || '').toLowerCase()));
  const removedResources = (analysis?.removed_reachable_resources || blast?.removed_reachable_resources || []).filter((resource) => scopedIdentityNames.has((resource.identity || '').toLowerCase()));

  return (
    <main className="flex-1 min-w-0 overflow-y-auto bg-enterprise-bg p-6 space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight text-white"><Waypoints className="h-6 w-6 text-enterprise-warning" /> What‑If Security Analysis</h1>
          <p className="mt-1 max-w-3xl text-sm text-enterprise-subtext">Preview how an IAM policy change could affect risk, attack paths, and reachable AWS resources. No changes are made to AWS.</p>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs font-semibold text-emerald-300"><ShieldCheck className="h-4 w-4" /> Draft analysis only · no AWS changes</div>
      </header>

      <ol className="grid gap-3 sm:grid-cols-3" aria-label="What-if analysis steps">
        {['Choose an identity and policy change', 'Review the projected security impact', 'Discard the preview or save it as a draft'].map((step, index) => <li key={step} className="flex items-center gap-3 rounded-lg border border-enterprise-border bg-enterprise-card px-4 py-3 text-xs text-enterprise-subtext"><span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-enterprise-accent/15 font-bold text-enterprise-accent">{index + 1}</span>{step}</li>)}
      </ol>

      <section className="rounded-xl border border-enterprise-border bg-enterprise-card p-5">
        {loadingCatalog ? <div className="flex items-center gap-2 py-6 text-sm text-enterprise-subtext"><RefreshCw className="h-4 w-4 animate-spin" /> Loading scanned identities and policies…</div> : catalogError ? (
          <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200"><p className="font-semibold">Could not load simulation inputs</p><p className="mt-1">{catalogError}</p><p className="mt-2 text-xs text-red-100/70">Check the API connection and confirm a published scan is available.</p></div>
        ) : principals.length === 0 || policies.length === 0 ? (
          <div className="py-8 text-center"><AlertTriangle className="mx-auto h-7 w-7 text-amber-300" /><p className="mt-3 font-semibold text-white">A scan is needed before previewing a change</p><p className="mt-1 text-sm text-enterprise-subtext">The preview requires at least one scanned user or role and one attachable policy.</p></div>
        ) : <>
          <p className="mb-4 text-sm text-enterprise-subtext">Build a change set across IAM users, roles, and groups. You can add or remove several managed policies before calculating one combined result.</p>
          <div className="grid gap-4 md:grid-cols-3">
            <label className="space-y-2 text-xs font-semibold uppercase tracking-wide text-enterprise-subtext">Proposed change
              <select value={action} onChange={(event) => { setAction(event.target.value as SimulationChangePayload['action']); setPolicySearch(''); setAnalysis(null); }} className="block w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-3 text-sm normal-case text-white">
                <option value="ATTACH_POLICY">Attach policy</option><option value="DETACH_POLICY">Detach policy</option>
              </select>
            </label>
            <label className="space-y-2 text-xs font-semibold uppercase tracking-wide text-enterprise-subtext">Search identities
              <span className="relative block"><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-enterprise-subtext" /><input value={identitySearch} onChange={(event) => setIdentitySearch(event.target.value)} placeholder="Find a user, role, or group" className="block w-full rounded-lg border border-enterprise-border bg-enterprise-bg py-2.5 pl-9 pr-3 text-sm normal-case text-white placeholder:text-enterprise-subtext/70" /></span>
              <select value={principalKey} onChange={(event) => { setPrincipalKey(event.target.value); setAnalysis(null); }} className="block w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-3 text-sm normal-case text-white">
                {(['USER', 'ROLE', 'GROUP'] as const).map((type) => {
                  const options = visiblePrincipals.filter((principal) => principal.type === type);
                  return options.length ? <optgroup key={type} label={type === 'USER' ? 'IAM users' : type === 'ROLE' ? 'Available AWS roles' : 'IAM groups'}>{options.map((principal) => <option key={`${principal.type}:${principal.id}`} value={`${principal.type}:${principal.id}`}>{principal.name}</option>)}</optgroup> : null;
                })}
                {!visiblePrincipals.length && <option value="">No matching identities</option>}
              </select>
              <span className="block text-[11px] font-normal normal-case">Includes {roles.length} scanned AWS roles available as simulation targets.</span>
            </label>
            <label className="space-y-2 text-xs font-semibold uppercase tracking-wide text-enterprise-subtext">Search policies
              <span className="relative block">
                <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-enterprise-subtext" />
                <input role="combobox" aria-autocomplete="list" aria-expanded={policyPickerOpen} aria-controls="simulation-policy-options" value={policySearch} onFocus={() => setPolicyPickerOpen(true)} onBlur={() => window.setTimeout(() => setPolicyPickerOpen(false), 120)} onKeyDown={(event) => { if (event.key === 'ArrowDown') { event.preventDefault(); document.querySelector<HTMLButtonElement>('#simulation-policy-options button')?.focus(); } else if (event.key === 'Escape') setPolicyPickerOpen(false); }} onChange={(event) => { setPolicySearch(event.target.value); setPolicyPickerOpen(true); setAnalysis(null); }} placeholder="Type a policy name or ARN…" disabled={policies.length === 0} className="block w-full rounded-lg border border-enterprise-border bg-enterprise-bg py-2.5 pl-9 pr-3 text-sm normal-case text-white placeholder:text-enterprise-subtext/70 disabled:opacity-50" />
                {policyPickerOpen && <div id="simulation-policy-options" role="listbox" aria-label="Matching policies" className="absolute z-30 mt-1 max-h-72 w-full overflow-y-auto rounded-lg border border-enterprise-border bg-enterprise-card p-1 shadow-2xl">
                  {!policySearch.trim() && action !== 'DETACH_POLICY' && <p className="px-3 py-4 text-xs normal-case text-enterprise-subtext">Type a service or policy name to search the full catalog, for example <strong className="text-white">ecr</strong>.</p>}
                  {(policySearch.trim() || action === 'DETACH_POLICY') && accountPolicies.length > 0 && <div><p className="sticky top-0 border-b border-enterprise-border bg-enterprise-card px-2 py-1.5 text-[10px] font-bold uppercase tracking-wide text-enterprise-subtext">AWS account policies · {accountPolicies.length}</p>{accountPolicies.map((policy) => { const attached = isPolicyAttached(selectedPrincipal, policy, queuedChanges); return <button key={policy.arn} type="button" role="option" aria-selected={policyArn === policy.arn} onMouseDown={(event) => event.preventDefault()} onClick={() => { setPolicyArn(policy.arn); setPolicyPickerOpen(false); setAnalysis(null); }} className={`block w-full rounded-md px-2 py-2 text-left hover:bg-enterprise-accent/10 ${policyArn === policy.arn ? 'bg-enterprise-accent/15 text-enterprise-accent' : 'text-white'}`}><span className="flex items-center justify-between gap-2"><span className="truncate text-xs font-semibold">{policy.name}</span>{action === 'ATTACH_POLICY' && attached && <span className="shrink-0 rounded bg-amber-400/10 px-1.5 py-0.5 text-[9px] font-semibold text-amber-300">Already attached</span>}</span><span className="mt-0.5 block truncate font-mono text-[10px] text-enterprise-subtext">{policy.arn}</span></button>; })}</div>}
                  {(policySearch.trim() || action === 'DETACH_POLICY') && awsPolicies.length > 0 && <div><p className="sticky top-0 border-b border-enterprise-border bg-enterprise-card px-2 py-1.5 text-[10px] font-bold uppercase tracking-wide text-enterprise-subtext">AWS-managed policies · {awsPolicies.length}</p>{awsPolicies.map((policy) => { const attached = isPolicyAttached(selectedPrincipal, policy, queuedChanges); return <button key={policy.arn} type="button" role="option" aria-selected={policyArn === policy.arn} onMouseDown={(event) => event.preventDefault()} onClick={() => { setPolicyArn(policy.arn); setPolicyPickerOpen(false); setAnalysis(null); }} className={`block w-full rounded-md px-2 py-2 text-left hover:bg-enterprise-accent/10 ${policyArn === policy.arn ? 'bg-enterprise-accent/15 text-enterprise-accent' : 'text-white'}`}><span className="flex items-center justify-between gap-2"><span className="truncate text-xs font-semibold">{policy.name}</span>{action === 'ATTACH_POLICY' && attached && <span className="shrink-0 rounded bg-amber-400/10 px-1.5 py-0.5 text-[9px] font-semibold text-amber-300">Already attached</span>}</span><span className="mt-0.5 block truncate font-mono text-[10px] text-enterprise-subtext">{policy.arn}</span></button>; })}</div>}
                  {(policySearch.trim() || action === 'DETACH_POLICY') && availablePolicies.length === 0 && <p className="px-3 py-4 text-xs normal-case text-enterprise-subtext">{action === 'DETACH_POLICY' ? 'No policies are attached to this identity.' : 'No policy matches that search.'}</p>}
                </div>}
              </span>
              <span className="block text-[11px] font-normal normal-case">{policyArn ? `Selected: ${selectedPolicy?.name || policyArn}. ` : ''}{policies.length} attachable policies loaded across AWS account and AWS-managed policies.{action === 'ATTACH_POLICY' && selectedPolicyAttached ? ' This policy is already attached to this identity.' : ''}</span>
            </label>
          </div>
          <div className="mt-4 flex flex-wrap items-center justify-end gap-3"><span className="text-xs text-enterprise-subtext">{action === 'ATTACH_POLICY' && selectedPolicyAttached ? 'Already attached; choose another policy or remove it first.' : action === 'DETACH_POLICY' && !selectedPolicyAttached ? 'Select a policy attached to this identity.' : ''}</span><button type="button" onClick={queueSelectedChange} disabled={!canQueueSelectedPolicy} className="inline-flex items-center gap-2 rounded-lg border border-enterprise-accent/40 bg-enterprise-accent/10 px-4 py-2 text-sm font-semibold text-enterprise-accent hover:bg-enterprise-accent/20 disabled:cursor-not-allowed disabled:opacity-50"><Plus className="h-4 w-4" />Add to change set</button></div>
          <div className="mt-5 border-t border-enterprise-border pt-4">
            <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-sm font-bold text-white">Change set <span className="ml-1 text-enterprise-subtext">{queuedChanges.length}</span></h2><p className="mt-1 text-xs text-enterprise-subtext">Each row applies to one identity and one managed policy. Role rows change policies attached to that role.</p></div>{queuedChanges.length > 0 && <button type="button" onClick={() => { setQueuedChanges([]); setAnalysis(null); setDraftSaved(false); }} className="text-xs font-semibold text-enterprise-subtext hover:text-white">Clear all</button>}</div>
            {queuedChanges.length ? <ul className="mt-3 space-y-2">{queuedChanges.map((change) => {
              const principal = principals.find((item) => item.type === change.principal_type && item.id === change.principal_id);
              const policy = policies.find((item) => item.arn === change.policy_arn);
              return <li key={change.localId} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-enterprise-border bg-enterprise-bg/60 px-3 py-2.5"><div className="min-w-0"><p className="text-sm font-medium text-white"><span className={change.action === 'ATTACH_POLICY' ? 'text-emerald-300' : 'text-amber-300'}>{change.action === 'ATTACH_POLICY' ? 'Add' : 'Remove'}</span> {policy?.name || change.policy_arn}</p><p className="mt-0.5 text-xs text-enterprise-subtext">{principal?.type || change.principal_type} · {principal?.name || change.principal_id}</p></div><button type="button" aria-label="Remove change from list" onClick={() => { setQueuedChanges((items) => items.filter((item) => item.localId !== change.localId)); setAnalysis(null); setDraftSaved(false); }} className="rounded-md p-1.5 text-enterprise-subtext hover:bg-white/10 hover:text-white"><X className="h-4 w-4" /></button></li>;
            })}</ul> : <p className="mt-3 rounded-lg border border-dashed border-enterprise-border px-3 py-4 text-sm text-enterprise-subtext">No changes added yet. Choose an action, identity, and policy above, then add it here.</p>}
            <div className="mt-4 flex justify-end"><button onClick={runPreview} disabled={running || savingDraft || queuedChanges.length === 0} className="inline-flex items-center gap-2 rounded-lg bg-enterprise-warning px-5 py-2.5 text-sm font-bold text-enterprise-bg transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50">{running ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}{running ? 'Analyzing change set…' : `Preview ${queuedChanges.length || ''} change${queuedChanges.length === 1 ? '' : 's'}`}</button></div>
          </div>
        </>}
      </section>

      {runError && <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200"><span className="font-semibold">Preview failed: </span>{runError}</div>}

      {analysis && <section aria-live="polite" className="space-y-4">
        <div className="rounded-lg border border-blue-500/25 bg-blue-500/5 px-4 py-3 text-sm text-blue-100"><p>{analysis.summary || analysis.simulation_note || 'This is a non-persistent analysis of the proposed IAM changes.'}</p>{analysis.proposed_change?.map((change, index) => <p key={`${change.principal_type}:${change.principal_id}:${change.policy_arn}:${index}`} className="mt-2 text-xs text-blue-100/75">{change.action === 'ATTACH_POLICY' ? 'Add' : 'Remove'} <strong>{change.policy_name || change.policy_arn}</strong> on {change.principal_type.toLowerCase()} <strong>{change.principal_id}</strong>.</p>)}{analysis.analysis_warnings?.map((warning) => <p key={warning} className="mt-2 rounded-md border border-amber-400/25 bg-amber-400/10 px-3 py-2 text-xs text-amber-100">Analysis limitation: {warning}</p>)}</div>
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-enterprise-border bg-enterprise-card p-4">
          <p className="text-sm text-enterprise-subtext">Review the impact below. {snapshotId ? 'Historical snapshot previews cannot be saved as live drafts.' : 'Save this proposed change as a draft to compare it with other changes, or discard the preview.'}</p>
          <div className="flex shrink-0 gap-2">
            <button type="button" onClick={() => { setAnalysis(null); setRunError(''); setDraftSaved(false); }} disabled={savingDraft} className="inline-flex items-center gap-2 rounded-lg border border-enterprise-border px-3 py-2 text-sm font-semibold text-enterprise-subtext hover:text-white disabled:opacity-50"><Trash2 className="h-4 w-4" />Discard preview</button>
            <button type="button" onClick={saveDraft} disabled={!!snapshotId || savingDraft || draftSaved} title={snapshotId ? 'Exit snapshot view to save a live draft' : undefined} className="inline-flex items-center gap-2 rounded-lg bg-enterprise-accent px-3 py-2 text-sm font-semibold text-white hover:brightness-110 disabled:opacity-60">{savingDraft ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />}{draftSaved ? 'Saved to drafts' : savingDraft ? 'Saving…' : snapshotId ? 'Historical preview' : 'Save as draft'}</button>
          </div>
        </div>
        {draftSaved && <div role="status" className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-emerald-500/25 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300"><span className="flex items-center gap-2"><Check className="h-4 w-4" />Draft saved. It remains an analysis draft and has not changed AWS.</span><Link to="/changes" className="font-semibold underline underline-offset-2">Review saved changes</Link></div>}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Metric title="Security posture" value={risk ? `${risk.current_score} → ${risk.desired_score}` : 'Unavailable'} detail={risk ? `${risk.delta > 0 ? '+' : ''}${risk.delta} points · ${risk.desired_severity} residual risk` : 'No posture comparison returned'} delta={risk?.delta} higherIsWorse={false} />
          <Metric title="Account-wide reachable assets" value={blast ? `${blast.current_resource_count} → ${blast.desired_resource_count}` : 'Unavailable'} detail={blast ? `${blast.resources_delta! > 0 ? '+' : ''}${blast.resources_delta ?? 0} overall · blast score ${blast.current_blast_score} → ${blast.desired_blast_score}` : 'No reachability comparison returned'} delta={blast?.resources_delta} />
          <Metric title="New attack paths" value={String(newPaths.length)} detail={`${removedPaths.length} paths removed`} delta={newPaths.length - removedPaths.length} />
          <Metric title="Assets with changed access" value={String(newResources.length + removedResources.length)} detail={`${newResources.length} newly reachable · ${removedResources.length} no longer reachable`} delta={newResources.length - removedResources.length} />
        </div>
        <div className="rounded-xl border border-enterprise-accent/25 bg-enterprise-accent/5 px-4 py-3"><p className="text-xs font-bold uppercase tracking-wide text-enterprise-accent">Focused identity scope</p><p className="mt-1 break-words text-sm text-white">{Array.from(scopedIdentityNames).join(', ') || 'No selected identities'}</p><p className="mt-1 text-xs text-enterprise-subtext">The two graphs and access-change lists below are limited to paths and resources connected to these selected identities. Account-wide posture totals remain shown separately.</p></div>
        <section aria-label="Before and after graph comparison" className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2"><div><h2 className="text-sm font-bold text-white">Access graph comparison</h2><p className="mt-1 text-xs text-enterprise-subtext">Read, write, execute, and admin badges show modeled permissions in each state.</p></div><button type="button" onClick={() => setComparisonFullscreen(true)} className="inline-flex items-center gap-2 rounded-lg border border-enterprise-border bg-enterprise-card px-3 py-2 text-xs font-semibold text-enterprise-subtext hover:text-white"><Maximize2 className="h-4 w-4" />Full screen comparison</button></div>
          {!comparisonFullscreen && <div className="grid gap-4 xl:grid-cols-2">
            <AttackPathGraph title="Before proposed change" paths={scopedCurrentPaths} elements={analysis.current_elements || []} highlightedPaths={removedPaths} focusedIdentities={graphFocusIdentities} tone="current" />
            <AttackPathGraph title="After proposed change" paths={scopedDesiredPaths} elements={analysis.desired_elements || []} highlightedPaths={newPaths} focusedIdentities={graphFocusIdentities} tone="projected" />
          </div>}
        </section>
        <div className="rounded-lg border border-enterprise-border bg-enterprise-card px-4 py-3 text-xs text-enterprise-subtext">Each graph keeps the selected identities and their policy-to-resource links visible, even when no attack path exists. “Newly reachable” and “no longer reachable” describe modeled effective access to scanned assets; this preview does not create or delete AWS resources.</div>
        <div className="grid gap-4 lg:grid-cols-2">
          <ResultList title="New attack paths" empty="No new paths were identified." items={newPaths.map((path, index) => ({ key: path.id || `${path.source}-${path.target}-${index}`, title: `${path.source || 'Identity'} → ${path.target || path.destination || 'Resource'} · ${(path.severity || 'unknown').toUpperCase()}${path.riskScore !== undefined ? ` · risk ${path.riskScore}` : ''}`, detail: [path.ordered_nodes?.map((node) => node.name || node.id).join(' → '), path.description, path.recommendation && `Suggested action: ${path.recommendation}`].filter(Boolean).join(' | ') || path.orderedRelationships?.join(' · ') || 'Path identified by the current authorization analysis.' }))} />
          <ResourceDeltaList title="Newly reachable assets" empty="No additional scanned assets became reachable." items={newResources} />
          <ResultList title="Removed attack paths" empty="No existing paths were removed." items={removedPaths.map((path, index) => ({ key: path.id || `${path.source}-${path.target}-${index}`, title: `${path.source || 'Identity'} → ${path.target || path.destination || 'Resource'}`, detail: path.description || 'Path no longer reachable' }))} />
          <ResourceDeltaList title="Assets no longer reachable" empty="No scanned asset access was removed." items={removedResources} />
          <ResultList title="Paths with changed risk" empty="No surviving path changed risk classification for these identities." items={changedPaths.map((item, index) => ({ key: item.desired.id || `${item.desired.source}-${item.desired.destination}-${index}`, title: `${item.desired.source || 'Identity'} → ${item.desired.destination || item.desired.target || 'Resource'}`, detail: `Risk ${item.current.riskScore ?? item.current.risk_score ?? '—'} → ${item.desired.riskScore ?? item.desired.risk_score ?? '—'} (${item.risk_delta > 0 ? '+' : ''}${item.risk_delta})` }))} />
          <ResultList title="Why the posture changed" empty="No main risk drivers were returned for this comparison." items={(risk?.top_reasons || []).map((reason, index) => ({ key: `${reason}-${index}`, title: reason, detail: 'Calculated from the simulated identity, permissions, attack paths, and scanned findings.' }))} />
        </div>
      </section>}
      {analysis && comparisonFullscreen && createPortal(<div role="dialog" aria-modal="true" aria-label="Full-screen before and after simulation graphs" className="fixed inset-0 z-[100] flex flex-col overflow-hidden bg-enterprise-bg p-4 sm:p-6">
        <header className="mb-4 flex shrink-0 items-center justify-between gap-3 border-b border-enterprise-border pb-4"><div><h2 className="text-lg font-bold text-white">Access graph comparison</h2><p className="mt-1 text-sm text-enterprise-subtext">Before and after the complete proposed change set · permission badges reflect each state</p></div><button type="button" autoFocus onClick={() => setComparisonFullscreen(false)} className="inline-flex items-center gap-2 rounded-lg border border-enterprise-border px-3 py-2 text-sm font-semibold text-enterprise-subtext hover:text-white"><Minimize2 className="h-4 w-4" />Exit full screen <span className="text-xs opacity-70">Esc</span></button></header>
        <div className="grid min-h-0 flex-1 gap-4 xl:grid-cols-2">
          <AttackPathGraph title="Before proposed change" paths={scopedCurrentPaths} elements={analysis.current_elements || []} highlightedPaths={removedPaths} focusedIdentities={graphFocusIdentities} tone="current" expanded />
          <AttackPathGraph title="After proposed change" paths={scopedDesiredPaths} elements={analysis.desired_elements || []} highlightedPaths={newPaths} focusedIdentities={graphFocusIdentities} tone="projected" expanded />
        </div>
        <p className="mt-3 shrink-0 text-xs text-enterprise-subtext">Red links indicate access paths removed by this change; green links indicate paths added. Permission badges are derived from the simulated policy evidence.</p>
      </div>, document.body)}
    </main>
  );
};

function Metric({ title, value, detail, delta, higherIsWorse = true }: { title: string; value: string; detail: string; delta?: number; higherIsWorse?: boolean }) {
  const improving = delta !== undefined && (higherIsWorse ? delta < 0 : delta > 0);
  const worsening = delta !== undefined && (higherIsWorse ? delta > 0 : delta < 0);
  return <article className="rounded-xl border border-enterprise-border bg-enterprise-card p-4"><p className="text-xs font-semibold uppercase tracking-wide text-enterprise-subtext">{title}</p><p className="mt-2 text-2xl font-bold text-white">{value}</p><p className={`mt-1 flex items-center gap-1 text-xs ${worsening ? 'text-red-300' : improving ? 'text-emerald-300' : 'text-enterprise-subtext'}`}>{worsening ? <ArrowUpRight className="h-3.5 w-3.5" /> : improving ? <ArrowDownRight className="h-3.5 w-3.5" /> : null}{detail}</p></article>;
}

function ResultList({ title, empty, items }: { title: string; empty: string; items: { key: string; title: string; detail: string }[] }) {
  return <article className="rounded-xl border border-enterprise-border bg-enterprise-card p-5"><h2 className="text-sm font-bold text-white">{title}<span className="ml-2 text-enterprise-subtext">{items.length}</span></h2>{items.length ? <ul className="mt-3 divide-y divide-enterprise-border">{items.map((item) => <li key={item.key} className="py-3"><p className="break-all text-sm font-medium text-gray-100">{item.title}</p><p className="mt-1 text-xs text-enterprise-subtext">{item.detail}</p></li>)}</ul> : <p className="mt-3 text-sm text-enterprise-subtext">{empty}</p>}</article>;
}

const accessBadgeLabels = (categories: unknown, actions: unknown): string[] => {
  const categoryValues = Array.isArray(categories) ? categories : typeof categories === 'string' ? [categories] : [];
  const actionValues = Array.isArray(actions) ? actions : typeof actions === 'string' ? [actions] : [];
  const normalized = new Set(categoryValues.map((item) => String(item).trim().toUpperCase().replace(/_/g, ' ')).filter(Boolean));
  for (const action of actionValues) {
    const value = String(action).trim().toLowerCase();
    if (value === '*' || value === '*:*' || value.includes('administratoraccess')) normalized.add('FULL ADMIN');
    else if (value.endsWith(':*')) normalized.add('SERVICE ADMIN');
    else if (value.includes('assumerole')) normalized.add('ASSUME ROLE');
    else if (value.includes('rds-db:connect')) normalized.add('DB CONNECT');
    else if (/:(get|list|describe|view|read|lookup|head|download|batchget)/.test(value)) normalized.add('READ');
    else if (/:(put|create|update|modify|post|batchwrite|attach|set|write)/.test(value)) normalized.add('WRITE');
    else if (/:(invoke|run|start|execute|trigger)/.test(value)) normalized.add('EXECUTE');
    else if (/:(delete|remove|drop|purge|terminate|detach)/.test(value)) normalized.add('DELETE');
    else if (value.startsWith('iam:')) normalized.add('ADMIN');
  }
  const priority = ['FULL ADMIN', 'SERVICE ADMIN', 'ADMIN', 'DELETE', 'WRITE', 'EXECUTE', 'DB CONNECT', 'READ', 'ASSUME ROLE', 'ACCESS'];
  return priority.filter((label) => normalized.has(label)).slice(0, 3);
};

function AttackPathGraph({ title, paths, elements, highlightedPaths, focusedIdentities, tone, expanded = false }: { title: string; paths: AttackPath[]; elements: any[]; highlightedPaths: AttackPath[]; focusedIdentities: { type: string; name: string }[]; tone: 'current' | 'projected'; expanded?: boolean }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [ready, setReady] = useState(false);
  const merged = useMemo(() => {
    const pathNodes = new Map<string, any>();
    const pathEdges = new Map<string, any>();
    const highlighted = new Set<string>();
    const rawNodes = elements.filter((item) => item?.data?.id && !item.data.source && !item.data.target);
    const sourceEdges = elements.filter((item) => item?.data?.source && item?.data?.target);
    const nodeIdByArn = new Map<string, string>();
    const idToCanonical = new Map<string, string>();
    const nodeById = new Map<string, any>();
    rawNodes.forEach((node) => {
      const originalId = String(node.data.id);
      const arn = String(node.data.arn || '');
      const canonicalId = arn ? (nodeIdByArn.get(arn) || originalId) : originalId;
      if (arn && !nodeIdByArn.has(arn)) nodeIdByArn.set(arn, canonicalId);
      idToCanonical.set(originalId, canonicalId);
      if (!nodeById.has(canonicalId)) nodeById.set(canonicalId, { ...node, data: { ...node.data, id: canonicalId } });
    });
    const rawEdges = sourceEdges.flatMap((edge) => {
      const source = idToCanonical.get(String(edge.data.source)) || String(edge.data.source);
      const target = idToCanonical.get(String(edge.data.target)) || String(edge.data.target);
      return source === target ? [] : [{ ...edge, data: { ...edge.data, source, target } }];
    });
    const includePaths = (items: AttackPath[], isHighlighted: boolean) => items.forEach((path) => {
      const nodes = path.ordered_nodes || path.nodes || [];
      nodes.forEach((node) => {
        const originalId = String(node.id || node.name || '');
        const id = (node.arn && nodeIdByArn.get(String(node.arn))) || idToCanonical.get(originalId) || originalId;
        if (id) pathNodes.set(id, { data: { id, label: node.name || id, type: normalizeGraphType(node.type) } });
      });
      for (let index = 0; index < nodes.length - 1; index += 1) {
        const sourceRaw = String(nodes[index].id || nodes[index].name || '');
        const targetRaw = String(nodes[index + 1].id || nodes[index + 1].name || '');
        const source = (nodes[index].arn && nodeIdByArn.get(String(nodes[index].arn))) || idToCanonical.get(sourceRaw) || sourceRaw;
        const target = (nodes[index + 1].arn && nodeIdByArn.get(String(nodes[index + 1].arn))) || idToCanonical.get(targetRaw) || targetRaw;
        if (!source || !target) continue;
        const relation = path.orderedRelationships?.[index] || path.ordered_relationships?.[index] || '';
        const key = `${source}\u0000${target}`;
        if (!pathEdges.has(key)) pathEdges.set(key, { data: { id: `path-${pathEdges.size}`, source, target, label: relation } });
        if (isHighlighted) highlighted.add(key);
      }
    });
    includePaths(paths, false);
    includePaths(highlightedPaths, true);
    const selectedRoots = new Set<string>();
    focusedIdentities.forEach((identity) => {
      const type = identity.type.toLowerCase();
      const id = `aws:${type}:${identity.name}`;
      if (nodeById.has(id)) {
        selectedRoots.add(id);
        return;
      }
      const match = rawNodes.find((node) => normalizeGraphType(node.data.type) === normalizeGraphType(type)
        && String(node.data.label || '').toLowerCase() === identity.name.toLowerCase());
      selectedRoots.add(match ? String(match.data.id) : id);
      if (!match) pathNodes.set(id, { data: { id, label: identity.name, type: normalizeGraphType(type) } });
    });

    // Preserve the focused identity's permission component even when it has
    // no attack path (for example, after its last policy is detached). Follow
    // authorization edges outward: identity → group/role/policy → asset.
    const includedIds = new Set<string>(selectedRoots);
    const traversableRelationships = new Set(['HAS_POLICY', 'MEMBER_OF', 'CAN_ASSUME', 'ASSUMED_ROLE', 'ALLOWS', 'DB_CONNECT', 'BELONGS_TO']);
    let frontier = [...selectedRoots];
    for (let depth = 0; depth < 6 && frontier.length; depth += 1) {
      const next: string[] = [];
      rawEdges.forEach((edge) => {
        const source = String(edge.data.source);
        const target = String(edge.data.target);
        const relationship = String(edge.data.relationship || edge.data.label || '').toUpperCase();
        if (!frontier.includes(source) || !traversableRelationships.has(relationship)) return;
        includedIds.add(source);
        includedIds.add(target);
        const targetType = normalizeGraphType(nodeById.get(target)?.data?.type || pathNodes.get(target)?.data?.type || '');
        if (['Group', 'Role', 'Policy', 'RDS'].includes(targetType) && !frontier.includes(target)) next.push(target);
      });
      frontier = [...new Set(next)];
    }

    // Show workloads attached to a selected role and users belonging to a
    // selected group as context, without traversing into unrelated identities.
    rawEdges.forEach((edge) => {
      const source = String(edge.data.source);
      const target = String(edge.data.target);
      const relationship = String(edge.data.relationship || edge.data.label || '').toUpperCase();
      if (selectedRoots.has(target) && ((relationship === 'ATTACHED_TO' || relationship === 'EXECUTES_WITH')
        || (relationship === 'MEMBER_OF' && focusedIdentities.some((item) => item.type.toUpperCase() === 'GROUP')))) {
        includedIds.add(source);
        includedIds.add(target);
      }
    });
    pathNodes.forEach((_node, id) => includedIds.add(id));

    const nodeRows = [...includedIds].map((id) => {
      const source = nodeById.get(id)?.data || pathNodes.get(id)?.data || { id, label: id, type: 'Resource' };
      return { data: { ...source, id, label: source.label || source.name || id, type: normalizeGraphType(source.type) } };
    });
    const labelsByName = new Map<string, number>();
    nodeRows.forEach((node) => labelsByName.set(String(node.data.label), (labelsByName.get(String(node.data.label)) || 0) + 1));
    const nodes = nodeRows.map((node) => {
      if ((labelsByName.get(String(node.data.label)) || 0) < 2) return node;
      const region = String(node.data.region || '');
      const arnTail = String(node.data.arn || '').split(':').pop()?.split('/').pop() || '';
      const idTail = String(node.data.id).split(':').pop() || '';
      const suffix = region || (arnTail && arnTail !== node.data.label ? arnTail : idTail.slice(-10));
      return { ...node, data: { ...node.data, label: `${node.data.label} · ${suffix}` } };
    });
    const nodeIds = new Set(nodes.map((node) => node.data.id));
    // A selected route can be present both in the inventory graph and in one
    // or more path records. Collapse all copies of the same directed link into
    // one visible edge, combining relationship names and permission evidence.
    const combinedEdges = new Map<string, any>();
    rawEdges.filter((edge) => nodeIds.has(String(edge.data.source)) && nodeIds.has(String(edge.data.target))).forEach((edge) => {
      const source = String(edge.data.source);
      const target = String(edge.data.target);
      const key = `${source}\u0000${target}`;
      const relationship = String(edge.data.relationship || edge.data.label || '').toUpperCase();
      const edgeCategories = Array.isArray(edge.data.access_categories) ? edge.data.access_categories : edge.data.access_categories ? [edge.data.access_categories] : [];
      const edgeActions = Array.isArray(edge.data.actions) ? edge.data.actions : edge.data.actions ? [edge.data.actions] : edge.data.action ? [edge.data.action] : [];
      const existing = combinedEdges.get(key);
      if (!existing) {
        combinedEdges.set(key, { ...edge, data: { ...edge.data, source, target, relationships: [relationship], access_categories: edgeCategories, actions: edgeActions } });
        return;
      }
      existing.data.relationships = [...new Set([...existing.data.relationships, relationship])];
      existing.data.access_categories = [...new Set([...existing.data.access_categories, ...edgeCategories])];
      existing.data.actions = [...new Set([...existing.data.actions, ...edgeActions])];
    });
    const edges = [...combinedEdges.values()].map((edge) => {
      const relationships: string[] = edge.data.relationships;
      const badges = accessBadgeLabels(edge.data.access_categories, edge.data.actions);
      const accessLabel = badges.join(' · ');
      const relationshipLabel = relationships.join(' · ');
      const label = accessLabel && relationships.some((relationship) => relationship === 'ALLOWS' || relationship === 'DB_CONNECT')
        ? accessLabel
        : relationshipLabel;
      return { ...edge, data: { ...edge.data, relationship: relationships[0] || '', label } };
    });
    const edgeKeys = new Set(edges.map((edge) => `${edge.data.source}\u0000${edge.data.target}`));
    pathEdges.forEach((edge, key) => { if (!edgeKeys.has(key)) edges.push(edge); });
    return { nodes, edges, highlighted };
  }, [elements, paths, highlightedPaths, focusedIdentities]);

  useEffect(() => {
    setReady(false);
    if (!containerRef.current || !merged.nodes.length) { cyRef.current?.destroy(); cyRef.current = null; return; }
    cyRef.current?.destroy();
    const cy = cytoscape({
      container: containerRef.current,
      elements: [...merged.nodes, ...merged.edges],
      minZoom: 0.15,
      maxZoom: 2.5,
      wheelSensitivity: 0.2,
      style: ([
        { selector: 'node', style: { label: 'data(label)', 'font-family': 'Inter, sans-serif', 'font-size': 9, color: '#e2e8f0', 'text-valign': 'bottom', 'text-margin-y': 7, 'text-wrap': 'wrap', 'text-max-width': 180, 'text-background-color': '#0f172a', 'text-background-opacity': 0.9, 'text-background-padding': 2, 'background-color': '#64748b', 'border-width': 2, 'border-color': '#94a3b8', width: 38, height: 38 } },
        ...Object.values(ENTITY_STYLES).map((style) => ({ selector: `node[type = "${style.type}"]`, style: { 'background-color': style.backgroundColor, 'border-color': style.borderColor, shape: style.shape as any, width: style.width, height: style.height } })),
        { selector: 'edge', style: { width: 1.5, 'line-color': '#64748b', 'target-arrow-color': '#94a3b8', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', opacity: 0.82, label: 'data(label)', 'font-size': 8, 'font-weight': 700, color: '#bfdbfe', 'text-background-color': '#0f172a', 'text-background-opacity': 0.94, 'text-background-padding': 2 } },
        { selector: 'edge[label *= "READ"]', style: { color: '#7dd3fc' } },
        { selector: 'edge[label *= "WRITE"], edge[label *= "DELETE"]', style: { color: '#fbbf24' } },
        { selector: 'edge[label *= "ADMIN"]', style: { color: '#fca5a5' } },
        { selector: 'edge[label *= "EXECUTE"]', style: { color: '#c4b5fd' } },
        { selector: '.changed-edge', style: { width: '3px', 'line-color': tone === 'current' ? '#ef4444' : '#22c55e', 'target-arrow-color': tone === 'current' ? '#ef4444' : '#22c55e', opacity: 1, 'z-index': 10 } },
      ] as any),
      layout: { name: 'dagre', rankDir: 'LR', nodeSep: 32, rankSep: 72, edgeSep: 12, padding: 28, animate: false } as any,
    });
    cy.edges().forEach((edge) => { if (merged.highlighted.has(`${edge.data('source')}\u0000${edge.data('target')}`)) edge.addClass('changed-edge'); });
    cyRef.current = cy;
    cy.ready(() => setReady(true));
    return () => { cy.destroy(); if (cyRef.current === cy) cyRef.current = null; };
  }, [merged, tone]);

  const zoom = (factor: number) => { const cy = cyRef.current; if (cy) cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }); };
  return <article className={`min-w-0 rounded-xl border border-enterprise-border bg-enterprise-card p-4 ${expanded ? 'flex h-full min-h-0 flex-col' : ''}`}>
    <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-sm font-bold text-white">{title}</h2><p className="mt-1 text-xs text-enterprise-subtext">Selected identities, their policy links, reachable assets, and attack paths.</p></div><div className="flex items-center gap-2"><span className="rounded-full border border-enterprise-border px-2 py-1 text-[11px] text-enterprise-subtext">{paths.length} paths · {merged.nodes.length} nodes</span><button type="button" onClick={() => zoom(1.2)} aria-label="Zoom in" className="rounded border border-enterprise-border px-2 py-1 text-xs text-enterprise-subtext hover:text-white">+</button><button type="button" onClick={() => zoom(0.83)} aria-label="Zoom out" className="rounded border border-enterprise-border px-2 py-1 text-xs text-enterprise-subtext hover:text-white">−</button><button type="button" onClick={() => cyRef.current?.fit(undefined, 30)} className="rounded border border-enterprise-border px-2 py-1 text-xs text-enterprise-subtext hover:text-white">Fit</button></div></div>
    {!merged.nodes.length ? <p className="mt-4 rounded-lg border border-enterprise-border bg-enterprise-bg/60 p-4 text-sm text-enterprise-subtext">No connected identity or resource data is available in this state.</p> : <div ref={containerRef} role="img" aria-label={`${title}: focused identity relationships with ${paths.length} attack paths`} className={`mt-3 w-full overflow-hidden rounded-lg border border-enterprise-border bg-enterprise-bg/60 ${expanded ? 'min-h-0 flex-1' : 'h-[420px]'}`} />}
    <div className="mt-2 flex flex-wrap gap-1.5 text-[10px]" aria-label="Permission badge legend">{['READ', 'WRITE', 'EXECUTE', 'ADMIN'].map((label) => <span key={label} className="rounded-full border border-enterprise-border bg-enterprise-bg px-2 py-0.5 font-semibold text-enterprise-subtext">{label}</span>)}</div>
    {merged.highlighted.size > 0 && <p className={`mt-2 text-xs ${tone === 'current' ? 'text-red-300' : 'text-emerald-300'}`}>{tone === 'current' ? 'Red links are paths removed by this change.' : 'Green links are paths added by this change.'}</p>}
    {!ready && !!merged.nodes.length && <span className="sr-only">Preparing graph…</span>}
  </article>;
}

function ResourceDeltaList({ title, empty, items }: { title: string; empty: string; items: SimulationResourceDelta[] }) {
  return <article className="rounded-xl border border-enterprise-border bg-enterprise-card p-5"><h2 className="text-sm font-bold text-white">{title}<span className="ml-2 text-enterprise-subtext">{items.length}</span></h2>{items.length ? <ul className="mt-3 divide-y divide-enterprise-border">{items.map((item, index) => <li key={`${item.identity_type}:${item.identity}:${item.resource_id || item.id}:${index}`} className="py-3">
    <p className="break-all text-sm font-semibold text-gray-100">{item.name || item.resource_id || item.id || 'AWS resource'} <span className="font-normal text-enterprise-subtext">· {item.type || 'Resource'}</span></p>
    <p className="mt-1 text-xs text-enterprise-subtext">{item.identity_type || 'Identity'} <strong className="text-gray-200">{item.identity || 'Unknown'}</strong>{item.region ? ` · ${item.region}` : ''}{item.policy_names?.length ? ` · via ${item.policy_names.join(', ')}` : ''}</p>
    {item.arn && <p className="mt-1 break-all font-mono text-[11px] text-enterprise-subtext">{item.arn}</p>}
    {item.access_details?.map((detail, detailIndex) => <div key={`${detail.policy}-${detailIndex}`} className="mt-2 rounded-md bg-enterprise-bg/70 px-2.5 py-2 text-[11px] text-enterprise-subtext">{accessBadgeLabels(detail.access_categories, detail.action).map((label) => <span key={label} className={`mb-1 mr-1 inline-flex rounded-full border px-2 py-0.5 font-bold ${label.includes('ADMIN') ? 'border-red-400/30 bg-red-400/10 text-red-200' : label === 'WRITE' || label === 'DELETE' ? 'border-amber-400/30 bg-amber-400/10 text-amber-200' : label === 'READ' ? 'border-sky-400/30 bg-sky-400/10 text-sky-200' : 'border-enterprise-border text-enterprise-subtext'}`}>{label}</span>)}<p><span className="font-semibold text-gray-200">Policy:</span> {detail.policy}</p>{detail.action && <p className="mt-1"><span className="font-semibold text-gray-200">Matching action:</span> {Array.isArray(detail.action) ? detail.action.join(', ') : detail.action}</p>}{detail.access_path?.length ? <p className="mt-1 break-words"><span className="font-semibold text-gray-200">Access chain:</span> {detail.access_path.join(' → ')}</p> : null}{detail.reason && <p className="mt-1">Why: {detail.reason}</p>}</div>)}
  </li>)}</ul> : <p className="mt-3 text-sm text-enterprise-subtext">{empty}</p>}</article>;
}
