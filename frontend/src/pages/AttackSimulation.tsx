import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, ArrowDownRight, ArrowUpRight, Play, RefreshCw, ShieldCheck, Waypoints } from 'lucide-react';
import { previewSimulationChange, type SimulationChangePayload } from '../api/simulation';
import { getIAMUsers } from '../api/users';
import { getIAMRoles } from '../api/roles';
import { getPolicyCatalog } from '../api/policies';
import type { IAMRole, IAMUser, PolicyCatalogEntry, SimulationAnalysis } from '../types';

type Principal = { id: string; name: string; type: 'USER' | 'ROLE'; policyNames: string[] };

const errorMessage = (error: unknown) => {
  const responseError = error as { response?: { data?: { detail?: string } }; message?: string };
  return responseError.response?.data?.detail || responseError.message || 'The request could not be completed.';
};

export const AttackSimulation: React.FC = () => {
  const [users, setUsers] = useState<IAMUser[]>([]);
  const [roles, setRoles] = useState<IAMRole[]>([]);
  const [policies, setPolicies] = useState<PolicyCatalogEntry[]>([]);
  const [loadingCatalog, setLoadingCatalog] = useState(true);
  const [catalogError, setCatalogError] = useState('');
  const [action, setAction] = useState<SimulationChangePayload['action']>('ATTACH_POLICY');
  const [principalKey, setPrincipalKey] = useState('');
  const [policyArn, setPolicyArn] = useState('');
  const [analysis, setAnalysis] = useState<SimulationAnalysis | null>(null);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState('');

  useEffect(() => {
    let active = true;
    Promise.all([getIAMUsers(), getIAMRoles(), getPolicyCatalog({ page: 1, page_size: 200 })])
      .then(([userData, roleData, policyData]) => {
        if (!active) return;
        setUsers(userData);
        setRoles(roleData);
        setPolicies(policyData.items.filter((policy) => policy.isAttachable && policy.arn));
        setCatalogError('');
      })
      .catch((error: unknown) => { if (active) setCatalogError(errorMessage(error)); })
      .finally(() => { if (active) setLoadingCatalog(false); });
    return () => { active = false; };
  }, []);

  const principals = useMemo<Principal[]>(() => [
    ...users.map((user) => ({ id: user.name, name: user.name, type: 'USER' as const, policyNames: user.policies || [] })),
    ...roles.map((role) => ({ id: role.name, name: role.name, type: 'ROLE' as const, policyNames: role.attachedPolicies || role.policies || [] })),
  ], [users, roles]);

  const selectedPrincipal = principals.find((principal) => `${principal.type}:${principal.id}` === principalKey);
  const applicablePolicies = useMemo(() => {
    if (!selectedPrincipal) return [];
    return policies.filter((policy) => action === 'DETACH_POLICY'
      ? selectedPrincipal.policyNames.includes(policy.name)
      : !selectedPrincipal.policyNames.includes(policy.name));
  }, [action, policies, selectedPrincipal]);

  useEffect(() => {
    if (!principals.some((principal) => `${principal.type}:${principal.id}` === principalKey)) {
      const first = principals[0];
      setPrincipalKey(first ? `${first.type}:${first.id}` : '');
    }
  }, [principals, principalKey]);

  useEffect(() => {
    if (!applicablePolicies.some((policy) => policy.arn === policyArn)) setPolicyArn(applicablePolicies[0]?.arn || '');
  }, [applicablePolicies, policyArn]);

  const runPreview = async () => {
    const [principalType, ...idParts] = principalKey.split(':');
    const principalId = idParts.join(':');
    if (!principalType || !principalId || !applicablePolicies.some((policy) => policy.arn === policyArn)) return;
    setRunning(true);
    setRunError('');
    setAnalysis(null);
    try {
      setAnalysis(await previewSimulationChange({
        action,
        principal_type: principalType as 'USER' | 'ROLE',
        principal_id: principalId,
        policy_arn: policyArn,
      }));
    } catch (error: unknown) {
      setRunError(errorMessage(error));
    } finally {
      setRunning(false);
    }
  };

  const risk = analysis?.risk_comparison;
  const blast = analysis?.blast_radius_comparison;
  const newPaths = analysis?.attack_path_comparison?.new_paths || [];
  const removedPaths = analysis?.attack_path_comparison?.removed_paths || [];
  const newResources = analysis?.new_reachable_resources || blast?.new_reachable_resources || [];
  const removedResources = analysis?.removed_reachable_resources || blast?.removed_reachable_resources || [];

  return (
    <main className="flex-1 min-w-0 overflow-y-auto bg-enterprise-bg p-6 space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight text-white"><Waypoints className="h-6 w-6 text-enterprise-warning" /> IAM Change Preview</h1>
          <p className="mt-1 max-w-3xl text-sm text-enterprise-subtext">Evaluate how attaching or detaching a policy changes access, risk, attack paths, and reachable resources.</p>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs font-semibold text-emerald-300"><ShieldCheck className="h-4 w-4" /> Analysis only · no AWS changes</div>
      </header>

      <section className="rounded-xl border border-enterprise-border bg-enterprise-card p-5">
        {loadingCatalog ? <div className="flex items-center gap-2 py-6 text-sm text-enterprise-subtext"><RefreshCw className="h-4 w-4 animate-spin" /> Loading scanned identities and policies…</div> : catalogError ? (
          <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200"><p className="font-semibold">Could not load simulation inputs</p><p className="mt-1">{catalogError}</p><p className="mt-2 text-xs text-red-100/70">Check the API connection and confirm a published scan is available.</p></div>
        ) : principals.length === 0 || policies.length === 0 ? (
          <div className="py-8 text-center"><AlertTriangle className="mx-auto h-7 w-7 text-amber-300" /><p className="mt-3 font-semibold text-white">A scan is needed before previewing a change</p><p className="mt-1 text-sm text-enterprise-subtext">The preview requires at least one scanned user or role and one attachable policy.</p></div>
        ) : <>
          <div className="grid gap-4 md:grid-cols-3">
            <label className="space-y-2 text-xs font-semibold uppercase tracking-wide text-enterprise-subtext">Proposed change
              <select value={action} onChange={(event) => { setAction(event.target.value as SimulationChangePayload['action']); setAnalysis(null); }} className="block w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-3 text-sm normal-case text-white">
                <option value="ATTACH_POLICY">Attach policy</option><option value="DETACH_POLICY">Detach policy</option>
              </select>
            </label>
            <label className="space-y-2 text-xs font-semibold uppercase tracking-wide text-enterprise-subtext">Identity
              <select value={principalKey} onChange={(event) => { setPrincipalKey(event.target.value); setAnalysis(null); }} className="block w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-3 text-sm normal-case text-white">
                {principals.map((principal) => <option key={`${principal.type}:${principal.id}`} value={`${principal.type}:${principal.id}`}>{principal.name} · {principal.type}</option>)}
              </select>
            </label>
            <label className="space-y-2 text-xs font-semibold uppercase tracking-wide text-enterprise-subtext">Policy
              <select value={policyArn} onChange={(event) => { setPolicyArn(event.target.value); setAnalysis(null); }} disabled={applicablePolicies.length === 0} className="block w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-3 text-sm normal-case text-white disabled:opacity-50">
                {applicablePolicies.length ? applicablePolicies.map((policy) => <option key={policy.arn} value={policy.arn}>{policy.name}</option>) : <option value="">No applicable policies for this identity</option>}
              </select>
            </label>
          </div>
          <div className="mt-5 flex justify-end"><button onClick={runPreview} disabled={running || !principalKey || !policyArn || applicablePolicies.length === 0} className="inline-flex items-center gap-2 rounded-lg bg-enterprise-warning px-5 py-2.5 text-sm font-bold text-enterprise-bg transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50">{running ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}{running ? 'Analyzing…' : 'Preview impact'}</button></div>
        </>}
      </section>

      {runError && <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200"><span className="font-semibold">Preview failed: </span>{runError}</div>}

      {analysis && <section aria-live="polite" className="space-y-4">
        <div className="rounded-lg border border-blue-500/25 bg-blue-500/5 px-4 py-3 text-sm text-blue-100">{analysis.summary || analysis.simulation_note || 'This is a non-persistent analysis of the proposed IAM change.'}</div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Metric title="Security posture" value={risk ? `${risk.current_score} → ${risk.desired_score}` : 'Unavailable'} detail={risk ? `${risk.delta > 0 ? '+' : ''}${risk.delta} points · ${risk.desired_severity} residual risk` : 'No posture comparison returned'} delta={risk?.delta} higherIsWorse={false} />
          <Metric title="Blast radius" value={blast ? `${blast.current_resource_count} → ${blast.desired_resource_count}` : 'Unavailable'} detail={blast ? `${blast.delta > 0 ? '+' : ''}${blast.delta} score` : 'No blast radius returned'} delta={blast?.delta} />
          <Metric title="New attack paths" value={String(newPaths.length)} detail={`${removedPaths.length} paths removed`} delta={newPaths.length - removedPaths.length} />
          <Metric title="New reachable resources" value={String(newResources.length)} detail={`${removedResources.length} access paths removed`} delta={newResources.length - removedResources.length} />
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          <ResultList title="New attack paths" empty="No new paths were identified." items={newPaths.map((path, index) => ({ key: path.id || `${path.source}-${path.target}-${index}`, title: `${path.source || 'Identity'} → ${path.target || path.destination || 'Resource'}`, detail: path.orderedRelationships?.join(' · ') || path.description || 'Verified graph path' }))} />
          <ResultList title="Newly reachable resources" empty="No additional resources became reachable." items={newResources.map((resource, index) => ({ key: resource.resource_id || resource.id || `${resource.name}-${index}`, title: resource.name || resource.resource_id || resource.id || 'Resource', detail: [resource.type, resource.identity && `via ${resource.identity}`].filter(Boolean).join(' · ') }))} />
          <ResultList title="Removed attack paths" empty="No existing paths were removed." items={removedPaths.map((path, index) => ({ key: path.id || `${path.source}-${path.target}-${index}`, title: `${path.source || 'Identity'} → ${path.target || path.destination || 'Resource'}`, detail: path.description || 'Path no longer reachable' }))} />
          <ResultList title="Access removed from resources" empty="No resource access was removed." items={removedResources.map((resource, index) => ({ key: resource.resource_id || resource.id || `${resource.name}-${index}`, title: resource.name || resource.resource_id || resource.id || 'Resource', detail: [resource.type, resource.identity && `for ${resource.identity}`].filter(Boolean).join(' · ') }))} />
        </div>
      </section>}
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
