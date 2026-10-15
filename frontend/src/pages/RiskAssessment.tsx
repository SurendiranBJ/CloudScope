import { useMemo, useState } from 'react';
import { AlertTriangle, Check, ChevronDown, Download, ExternalLink, LoaderCircle, Search, ShieldAlert, Sparkles, X } from 'lucide-react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { explainFinding, type CopilotMessage } from '../api/copilot';
import {
  acknowledgeFinding,
  getFindingStatusHistory,
  getRiskAssessmentFindings,
  getSecurityFindings,
  resolveFinding,
  updateFindingTriage,
} from '../api/risks';
import { ScanTrigger } from '../components/ScanTrigger';
import { ScannedRegionBadge } from '../components/ScannedRegionBadge';
import { LastScannedBadge } from '../components/LastScannedBadge';
import { useScanDataRefresh } from '../hooks/useScanDataRefresh';

interface RiskAssessmentProps {
  search?: string;
}

type Finding = Record<string, any>;

const readable = (value: unknown, fallback = 'Not provided') =>
  typeof value === 'string' && value.trim() ? value.trim() : fallback;

const severityStyles: Record<string, string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-800 dark:text-orange-300',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-300',
  low: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-300',
};

const statusStyles: Record<string, string> = {
  open: 'bg-red-500/10 text-red-700 dark:text-red-300',
  acknowledged: 'bg-blue-500/10 text-blue-800 dark:text-blue-300',
  resolved: 'bg-emerald-500/10 text-emerald-800 dark:text-emerald-300',
  suppressed: 'bg-gray-500/10 text-gray-700 dark:text-gray-300',
};

export const RiskAssessment: React.FC<RiskAssessmentProps> = ({ search = '' }) => {
  const [localSearch, setLocalSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('OPEN');
  const [visibleLimit, setVisibleLimit] = useState(20);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [actionError, setActionError] = useState('');
  const [aiExplanation, setAiExplanation] = useState<CopilotMessage | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState('');
  const [triageDraft, setTriageDraft] = useState({ assignedTo: '', dueDate: '', analystNotes: '' });
  const [triageLoading, setTriageLoading] = useState(false);
  const [triageMessage, setTriageMessage] = useState('');
  const queryClient = useQueryClient();
  const { isScanning, hasCompletedSnapshot } = useScanDataRefresh();

  const { data: findingsData, refetch: refetchFindings, isLoading: isFindingsLoading, isError: isFindingsError } = useQuery<Finding[]>({
    queryKey: ['securityFindings'],
    queryFn: () => getSecurityFindings(),
    refetchInterval: 10000,
  });
  const { data: risksData, refetch: refetchRiskFindings, isLoading: isRisksLoading, isError: isRisksError } = useQuery<Finding[]>({
    queryKey: ['riskAssessmentFindings'],
    queryFn: getRiskAssessmentFindings,
    refetchInterval: 10000,
    enabled: !findingsData || findingsData.length === 0,
  });
  const { data: findingHistory = [], isLoading: isHistoryLoading, isError: isHistoryError } = useQuery({
    queryKey: ['findingStatusHistory', selectedFinding?.id],
    queryFn: () => getFindingStatusHistory(String(selectedFinding?.id)),
    enabled: Boolean(selectedFinding?.id),
  });

  const findings: Finding[] = (findingsData?.length ? findingsData : risksData) || [];
  const effectiveSearch = (localSearch || search).trim().toLowerCase();
  const isLoadingFindings = isFindingsLoading || (!findingsData && isRisksLoading);
  const hasFindingsLoadError = !findingsData && !risksData && isFindingsError && isRisksError;
  const filteredFindings = useMemo(() => findings.filter((finding) => {
    const searchable = [finding.identity, finding.principal, finding.resource, finding.title,
      finding.issue, finding.description, finding.recommendation, finding.remediation?.title]
      .map((value) => String(value ?? '').toLowerCase()).join(' ');
    const severity = String(finding.severity ?? '').toUpperCase();
    const status = String(finding.status ?? 'OPEN').toUpperCase();
    return (!effectiveSearch || searchable.includes(effectiveSearch))
      && (severityFilter === 'ALL' || severity === severityFilter)
      && (statusFilter === 'ALL' || status === statusFilter);
  }).sort((a, b) => {
    const rank: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return (rank[String(a.severity ?? '').toUpperCase()] ?? 4) - (rank[String(b.severity ?? '').toUpperCase()] ?? 4);
  }), [findings, effectiveSearch, severityFilter, statusFilter]);
  const visibleFindings = filteredFindings.slice(0, visibleLimit);

  const counts = useMemo(() => ({
    total: findings.length,
    open: findings.filter((f) => String(f.status ?? 'OPEN').toUpperCase() === 'OPEN').length,
    highPriority: findings.filter((f) => ['CRITICAL', 'HIGH'].includes(String(f.severity ?? '').toUpperCase())).length,
    resolved: findings.filter((f) => String(f.status ?? '').toUpperCase() === 'RESOLVED').length,
    overdue: findings.filter((f) => f.dueDate && f.dueDate < new Date().toISOString().slice(0, 10) && !['RESOLVED', 'SUPPRESSED'].includes(String(f.status ?? '').toUpperCase())).length,
  }), [findings]);

  const handleLifecycleAction = async (action: 'acknowledge' | 'resolve') => {
    if (!selectedFinding?.id) return;
    setActionLoading(true);
    setActionError('');
    try {
      if (action === 'acknowledge') await acknowledgeFinding(selectedFinding.id);
      else await resolveFinding(selectedFinding.id);
      await refetchFindings();
      await queryClient.invalidateQueries({ queryKey: ['securityFindings'] });
      await queryClient.invalidateQueries({ queryKey: ['riskAssessmentFindings'] });
      await queryClient.invalidateQueries({ queryKey: ['findingStatusHistory', selectedFinding.id] });
      setSelectedFinding((current) => current ? {
        ...current,
        status: action === 'acknowledge' ? 'ACKNOWLEDGED' : 'RESOLVED',
      } : null);
    } catch {
      setActionError('Could not update this finding. Please try again.');
    } finally {
      setActionLoading(false);
    }
  };

  const closeDetails = () => {
    setSelectedFinding(null);
    setActionError('');
    setAiExplanation(null);
    setAiError('');
    setTriageMessage('');
  };

  const openDetails = (finding: Finding) => {
    setSelectedFinding(finding);
    setActionError('');
    setAiExplanation(null);
    setAiError('');
    setTriageDraft({ assignedTo: finding.assignedTo ?? '', dueDate: finding.dueDate ?? '', analystNotes: finding.analystNotes ?? '' });
    setTriageMessage('');
  };

  const handleSaveTriage = async () => {
    if (!selectedFinding?.id) return;
    setTriageLoading(true);
    setTriageMessage('');
    try {
      const updated = await updateFindingTriage(String(selectedFinding.id), triageDraft);
      setSelectedFinding((current) => current ? { ...current, ...updated } : null);
      await queryClient.invalidateQueries({ queryKey: ['securityFindings'] });
      setTriageMessage('Remediation plan saved.');
    } catch (error: any) {
      setTriageMessage(error?.response?.data?.detail || 'Could not save the remediation plan. Please try again.');
    } finally {
      setTriageLoading(false);
    }
  };

  const handleExplainWithAI = async () => {
    if (!selectedFinding?.id) return;
    setAiLoading(true);
    setAiError('');
    try {
      setAiExplanation(await explainFinding(String(selectedFinding.id)));
    } catch (error: any) {
      setAiError(error?.response?.data?.detail || 'AI could not explain this finding. Check that an AI provider is configured, then try again.');
    } finally {
      setAiLoading(false);
    }
  };

  const exportFindings = () => {
    const columns = [
      ['Finding ID', (finding: Finding) => finding.id],
      ['Severity', (finding: Finding) => finding.severity],
      ['Status', (finding: Finding) => finding.status ?? 'OPEN'],
      ['Category', (finding: Finding) => finding.category],
      ['Issue', (finding: Finding) => finding.title || finding.issue || finding.description],
      ['AWS resource', (finding: Finding) => finding.resource || finding.principal || finding.identity],
      ['Why it matters', (finding: Finding) => finding.impact || finding.description],
      ['Recommended next step', (finding: Finding) => finding.remediation?.title || finding.recommendation],
    ] as const;
    const escapeCsv = (value: unknown) => `"${String(value ?? '').replace(/"/g, '""')}"`;
    const csv = [columns.map(([label]) => escapeCsv(label)).join(','),
      ...filteredFindings.map((finding) => columns.map(([, getValue]) => escapeCsv(getValue(finding))).join(','))].join('\r\n');
    const url = URL.createObjectURL(new Blob([`\uFEFF${csv}`], { type: 'text/csv;charset=utf-8' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'cloudscope-security-findings.csv';
    anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  };

  return (
    <main className="flex-1 min-h-0 overflow-y-auto bg-enterprise-bg p-4 text-enterprise-text sm:p-6 space-y-5">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight text-enterprise-text">
            <ShieldAlert className="h-6 w-6 text-enterprise-critical" /> Security findings
          </h1>
          <p className="mt-1 text-sm text-enterprise-subtext">Issues found in your AWS environment and the steps to address them.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <ScannedRegionBadge />
          <LastScannedBadge />
          <ScanTrigger />
        </div>
      </header>

      {isScanning && (
        <div role="status" className="rounded-lg border border-enterprise-border bg-enterprise-card px-4 py-3 text-sm text-enterprise-subtext">
          Scan in progress. Findings will refresh when it finishes.
        </div>
      )}

      <section aria-label="Finding summary" className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        {[
          { label: 'All findings', value: counts.total },
          { label: 'Needs attention', value: counts.open },
          { label: 'High priority', value: counts.highPriority },
          { label: 'Resolved', value: counts.resolved },
          { label: 'Overdue', value: counts.overdue },
        ].map((item) => (
          <div key={item.label} className="rounded-xl border border-enterprise-border bg-enterprise-card p-4">
            <p className="text-sm text-enterprise-subtext">{item.label}</p>
            <p className="mt-1 text-2xl font-bold text-enterprise-text">{item.value}</p>
          </div>
        ))}
      </section>

      <section className="space-y-4 rounded-xl border border-enterprise-border bg-enterprise-card p-4" aria-label="Findings list">
        <div className="flex flex-col gap-3 md:flex-row">
          <label className="relative min-w-0 flex-1">
            <span className="sr-only">Search findings</span>
            <Search aria-hidden="true" className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-enterprise-subtext" />
            <input
              type="search"
              placeholder="Search by issue or AWS resource"
              value={localSearch}
              onChange={(event) => { setLocalSearch(event.target.value); setVisibleLimit(20); }}
              className="w-full rounded-lg border border-enterprise-border bg-enterprise-bg py-2.5 pl-9 pr-3 text-sm text-enterprise-text placeholder:text-enterprise-subtext focus:border-enterprise-accent focus:outline-none focus:ring-2 focus:ring-enterprise-accent/30"
            />
          </label>
          <label className="flex items-center gap-2 text-sm text-enterprise-subtext">
            <span>Severity</span>
            <select value={severityFilter} onChange={(event) => { setSeverityFilter(event.target.value); setVisibleLimit(20); }}
              className="rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-2.5 text-enterprise-text focus:border-enterprise-accent focus:outline-none focus:ring-2 focus:ring-enterprise-accent/30">
              <option value="ALL">All severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </label>
          <label className="flex items-center gap-2 text-sm text-enterprise-subtext">
            <span>Status</span>
            <select value={statusFilter} onChange={(event) => { setStatusFilter(event.target.value); setVisibleLimit(20); }}
              className="rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-2.5 text-enterprise-text focus:border-enterprise-accent focus:outline-none focus:ring-2 focus:ring-enterprise-accent/30">
              <option value="ALL">All statuses</option>
              <option value="OPEN">Needs attention</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="RESOLVED">Resolved</option>
              <option value="SUPPRESSED">Suppressed</option>
            </select>
          </label>
        </div>

        <p className="text-xs text-enterprise-subtext" aria-live="polite">
          Showing {filteredFindings.length} of {findings.length} findings
        </p>
        {filteredFindings.length > 0 && (
          <div className="flex justify-end">
            <button type="button" onClick={exportFindings}
              className="inline-flex items-center gap-2 rounded-lg border border-enterprise-border px-3 py-2 text-sm font-medium text-enterprise-text hover:bg-enterprise-bg focus:outline-none focus:ring-2 focus:ring-enterprise-accent/50">
              <Download aria-hidden="true" className="h-4 w-4" /> Export filtered findings
            </button>
          </div>
        )}

        {filteredFindings.length === 0 ? (
          <div className="rounded-lg border border-dashed border-enterprise-border px-4 py-10 text-center">
            {isLoadingFindings ? (
              <p className="text-sm text-enterprise-subtext">Loading security findings…</p>
            ) : hasFindingsLoadError ? (
              <div>
                <p className="text-sm text-enterprise-text">Could not load security findings.</p>
                <button type="button" onClick={() => { void Promise.all([refetchFindings(), refetchRiskFindings()]); }}
                  className="mt-3 rounded-lg border border-enterprise-border px-3 py-2 text-sm font-medium text-enterprise-accent hover:bg-enterprise-bg">Try again</button>
              </div>
            ) : isScanning && !hasCompletedSnapshot ? (
              <p className="text-sm text-enterprise-subtext">The first scan is running. Findings will appear here when it completes.</p>
            ) : findings.length > 0 ? (
              <p className="text-sm text-enterprise-subtext">No findings match these filters. Try a different search or choose “All”.</p>
            ) : (
              <div>
                <Check aria-hidden="true" className="mx-auto mb-2 h-6 w-6 text-enterprise-success" />
                <p className="font-medium text-enterprise-text">No findings to show</p>
                <p className="mt-1 text-sm text-enterprise-subtext">Run a scan to check your AWS environment.</p>
              </div>
            )}
          </div>
        ) : (
          <ul className="space-y-3">
          {visibleFindings.map((finding, index) => {
              const severity = readable(finding.severity, 'Unrated');
              const status = readable(finding.status, 'OPEN');
              const target = finding.resource || finding.principal || finding.identity;
              return (
                <li key={finding.id ?? `${target ?? 'finding'}-${index}`}>
                  <button type="button" onClick={() => openDetails(finding)}
                    className="group w-full rounded-xl border border-enterprise-border bg-enterprise-bg p-4 text-left transition-colors hover:border-enterprise-accent/60 focus:outline-none focus:ring-2 focus:ring-enterprise-accent/50">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${severityStyles[severity.toLowerCase()] ?? 'border-enterprise-border bg-enterprise-card text-enterprise-subtext'}`}>{severity}</span>
                      <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${statusStyles[status.toLowerCase()] ?? 'bg-enterprise-card text-enterprise-subtext'}`}>{status.toLowerCase() === 'open' ? 'Needs attention' : status}</span>
                      <span className="text-xs text-enterprise-subtext">{readable(finding.category, 'Security')}</span>
                    </div>
                    <h2 className="mt-3 font-semibold text-enterprise-text group-hover:text-enterprise-accent">
                      {readable(finding.title || finding.issue || finding.description, 'Security issue')}
                    </h2>
                    <p className="mt-1 break-all font-mono text-xs text-enterprise-subtext">{readable(target, 'AWS resource not specified')}</p>
                    {(finding.assignedTo || finding.dueDate) && <p className="mt-2 text-xs text-enterprise-subtext">{finding.assignedTo ? `Owner: ${finding.assignedTo}` : 'Unassigned'}{finding.dueDate ? ` · Due ${finding.dueDate}` : ''}</p>}
                    <div className="mt-3 grid gap-3 sm:grid-cols-2">
                      <div>
                        <p className="text-xs font-semibold text-enterprise-subtext">Why it matters</p>
                        <p className="mt-1 line-clamp-2 text-sm text-enterprise-text">{readable(finding.impact || finding.description || finding.issue, 'Review this configuration to understand its security impact.')}</p>
                      </div>
                      <div>
                        <p className="text-xs font-semibold text-enterprise-subtext">Recommended next step</p>
                        <p className="mt-1 line-clamp-2 text-sm text-enterprise-text">{readable(finding.remediation?.title || finding.recommendation, 'Open the finding for available guidance.')}</p>
                      </div>
                    </div>
                    <span className="mt-3 inline-flex items-center gap-1 text-sm font-medium text-enterprise-accent">View finding <span aria-hidden="true">→</span></span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
        {visibleFindings.length < filteredFindings.length && (
          <button type="button" onClick={() => setVisibleLimit((limit) => limit + 20)}
            className="w-full rounded-lg border border-enterprise-border px-4 py-3 text-sm font-medium text-enterprise-accent hover:bg-enterprise-bg focus:outline-none focus:ring-2 focus:ring-enterprise-accent/50">
            Show 20 more ({filteredFindings.length - visibleFindings.length} remaining)
          </button>
        )}
      </section>

      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/60 p-0 backdrop-blur-sm sm:items-center sm:p-4"
          onMouseDown={(event) => { if (event.target === event.currentTarget) closeDetails(); }}>
          <section role="dialog" aria-modal="true" aria-labelledby="finding-title"
            className="max-h-[92vh] w-full max-w-2xl overflow-y-auto rounded-t-2xl border border-enterprise-border bg-enterprise-card text-enterprise-text shadow-2xl sm:rounded-2xl">
            <header className="sticky top-0 flex items-start justify-between gap-4 border-b border-enterprise-border bg-enterprise-card p-5">
              <div>
                <div className="mb-2 flex flex-wrap gap-2">
                  {(() => {
                    const severity = readable(selectedFinding.severity, 'Unrated');
                    return <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${severityStyles[severity.toLowerCase()] ?? 'border-enterprise-border bg-enterprise-bg text-enterprise-subtext'}`}>{severity}</span>;
                  })()}
                  <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${statusStyles[String(selectedFinding.status ?? 'OPEN').toLowerCase()] ?? 'bg-enterprise-bg text-enterprise-subtext'}`}>
                    {String(selectedFinding.status ?? 'Needs attention').replace('_', ' ').toLowerCase()}
                  </span>
                </div>
                <h2 id="finding-title" className="text-lg font-bold">{readable(selectedFinding.title || selectedFinding.issue || selectedFinding.description, 'Security issue')}</h2>
                <p className="mt-1 break-all font-mono text-xs text-enterprise-subtext">{readable(selectedFinding.resource || selectedFinding.principal || selectedFinding.identity, 'AWS resource not specified')}</p>
              </div>
              <button type="button" onClick={closeDetails} aria-label="Close finding details" className="rounded-lg p-2 text-enterprise-subtext hover:bg-enterprise-bg hover:text-enterprise-text focus:outline-none focus:ring-2 focus:ring-enterprise-accent"><X className="h-5 w-5" /></button>
            </header>

            <div className="space-y-5 p-5">
              <section className="rounded-xl border border-enterprise-accent/30 bg-enterprise-accent/5 p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="flex items-center gap-2 text-sm font-semibold"><Sparkles aria-hidden="true" className="h-4 w-4 text-enterprise-accent" /> Explain this finding with AI</h3>
                    <p className="mt-1 text-xs text-enterprise-subtext">Get a plain-language explanation grounded in this scan’s evidence.</p>
                  </div>
                  <button type="button" onClick={handleExplainWithAI} disabled={aiLoading}
                    className="inline-flex items-center gap-2 rounded-lg bg-enterprise-accent px-3 py-2 text-sm font-semibold text-white hover:opacity-90 disabled:cursor-wait disabled:opacity-60">
                    {aiLoading ? <LoaderCircle aria-hidden="true" className="h-4 w-4 animate-spin" /> : <Sparkles aria-hidden="true" className="h-4 w-4" />}
                    {aiLoading ? 'Explaining…' : aiExplanation ? 'Explain again' : 'Explain with AI'}
                  </button>
                </div>
                {aiError && <p role="alert" className="mt-3 text-sm text-red-700 dark:text-red-300">{aiError}</p>}
                {aiExplanation && (
                  <div aria-live="polite" className="mt-4 space-y-4 border-t border-enterprise-accent/20 pt-4">
                    {aiExplanation.summary && <p className="text-sm font-semibold">{aiExplanation.summary}</p>}
                    <p className="whitespace-pre-wrap text-sm leading-relaxed text-enterprise-text">{aiExplanation.analysis || aiExplanation.text}</p>
                    {aiExplanation.evidence?.length ? <div><p className="mb-1 text-xs font-semibold text-enterprise-subtext">Evidence used</p><ul className="list-disc space-y-1 pl-5 text-sm text-enterprise-text">{aiExplanation.evidence.map((item, index) => <li key={index}>{item}</li>)}</ul></div> : null}
                    {aiExplanation.recommendations?.length ? <div><p className="mb-1 text-xs font-semibold text-enterprise-subtext">Suggested next steps</p><ol className="list-decimal space-y-1 pl-5 text-sm text-enterprise-text">{aiExplanation.recommendations.map((item, index) => <li key={index}>{item}</li>)}</ol></div> : null}
                    {aiExplanation.limitations?.length ? <p className="text-xs text-enterprise-subtext">Scope: {aiExplanation.limitations.join(' ')}</p> : null}
                    <p className="text-xs text-enterprise-subtext">AI guidance is advisory. Verify the evidence and review changes before applying them.</p>
                  </div>
                )}
              </section>

              <section className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4">
                <h3 className="flex items-center gap-2 text-sm font-semibold text-amber-800 dark:text-amber-300"><AlertTriangle className="h-4 w-4" /> Why this matters</h3>
                <p className="mt-2 text-sm leading-relaxed text-enterprise-text">{readable(selectedFinding.impact || selectedFinding.description || selectedFinding.issue, 'This configuration may expose your AWS environment to risk.')}</p>
              </section>

              <section className="rounded-xl border border-enterprise-border bg-enterprise-bg p-4">
                <h3 className="text-sm font-semibold">How to fix it</h3>
                <p className="mt-2 text-sm font-medium">{readable(selectedFinding.remediation?.title || selectedFinding.recommendation, 'No specific recommendation is available for this finding.')}</p>
                {selectedFinding.remediation?.summary && <p className="mt-2 text-sm text-enterprise-subtext">{selectedFinding.remediation.summary}</p>}
                {Array.isArray(selectedFinding.remediation?.steps) && selectedFinding.remediation.steps.length > 0 && (
                  <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm text-enterprise-text">
                    {selectedFinding.remediation.steps.map((step: string, index: number) => <li key={index}>{step}</li>)}
                  </ol>
                )}
                {Array.isArray(selectedFinding.remediation?.references) && selectedFinding.remediation.references.length > 0 && (
                  <div className="mt-4 border-t border-enterprise-border pt-3">
                    <p className="mb-2 text-xs font-semibold text-enterprise-subtext">AWS guidance</p>
                    <ul className="space-y-2">
                      {selectedFinding.remediation.references.map((url: string, index: number) => <li key={`${url}-${index}`}><a href={url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 break-all text-sm text-enterprise-accent underline-offset-2 hover:underline">Open AWS documentation <ExternalLink aria-hidden="true" className="h-3.5 w-3.5 shrink-0" /></a></li>)}
                    </ul>
                  </div>
                )}
              </section>

              <section className="space-y-3 rounded-xl border border-enterprise-border bg-enterprise-bg p-4">
                <div>
                  <h3 className="text-sm font-semibold">Remediation plan</h3>
                  <p className="mt-1 text-xs text-enterprise-subtext">Assign an owner and target date so this issue has a clear next step.</p>
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <label className="space-y-1 text-sm"><span className="font-medium">Owner</span><input maxLength={128} value={triageDraft.assignedTo} onChange={(event) => setTriageDraft((current) => ({ ...current, assignedTo: event.target.value }))} placeholder="Name or email" className="w-full rounded-lg border border-enterprise-border bg-enterprise-card px-3 py-2 text-enterprise-text placeholder:text-enterprise-subtext focus:border-enterprise-accent focus:outline-none focus:ring-2 focus:ring-enterprise-accent/30" /></label>
                  <label className="space-y-1 text-sm"><span className="font-medium">Target date</span><input type="date" value={triageDraft.dueDate} onChange={(event) => setTriageDraft((current) => ({ ...current, dueDate: event.target.value }))} className="w-full rounded-lg border border-enterprise-border bg-enterprise-card px-3 py-2 text-enterprise-text focus:border-enterprise-accent focus:outline-none focus:ring-2 focus:ring-enterprise-accent/30" /></label>
                </div>
                <label className="block space-y-1 text-sm"><span className="font-medium">Analyst notes</span><textarea maxLength={2000} rows={3} value={triageDraft.analystNotes} onChange={(event) => setTriageDraft((current) => ({ ...current, analystNotes: event.target.value }))} placeholder="Investigation context, blockers, or planned remediation" className="w-full resize-y rounded-lg border border-enterprise-border bg-enterprise-card px-3 py-2 text-enterprise-text placeholder:text-enterprise-subtext focus:border-enterprise-accent focus:outline-none focus:ring-2 focus:ring-enterprise-accent/30" /></label>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p role={triageMessage.includes('Could not') ? 'alert' : 'status'} className="text-sm text-enterprise-subtext">{triageMessage}</p>
                  <button type="button" onClick={handleSaveTriage} disabled={triageLoading} className="rounded-lg bg-enterprise-accent px-4 py-2 text-sm font-semibold text-white hover:opacity-90 disabled:cursor-wait disabled:opacity-60">{triageLoading ? 'Saving…' : 'Save remediation plan'}</button>
                </div>
              </section>

              <section aria-labelledby="finding-history-title" className="rounded-xl border border-enterprise-border bg-enterprise-bg p-4">
                <h3 id="finding-history-title" className="text-sm font-semibold">Status history</h3>
                {isHistoryLoading ? <p role="status" className="mt-2 text-sm text-enterprise-subtext">Loading history…</p> : null}
                {isHistoryError ? <p role="alert" className="mt-2 text-sm text-amber-700 dark:text-amber-300">History is temporarily unavailable.</p> : null}
                {!isHistoryLoading && !isHistoryError && findingHistory.length === 0 ? <p className="mt-2 text-sm text-enterprise-subtext">No status changes have been recorded yet.</p> : null}
                {findingHistory.length > 0 && (
                  <ol className="mt-3 space-y-3 border-l border-enterprise-border pl-4">
                    {findingHistory.map((event) => (
                      <li key={event.event_id} className="relative">
                        <span aria-hidden="true" className="absolute -left-[1.3rem] top-1.5 h-2 w-2 rounded-full bg-enterprise-accent" />
                        <p className="text-sm font-medium">
                          {event.from_status ? `${event.from_status.replaceAll('_', ' ')} → ` : 'Created as '}
                          {event.to_status.replaceAll('_', ' ')}
                        </p>
                        <p className="mt-0.5 text-xs text-enterprise-subtext">
                          {event.actor_id || 'System'} · {event.occurred_at ? new Date(event.occurred_at).toLocaleString() : 'Time unavailable'}
                          {event.reason ? ` · ${event.reason}` : ''}
                        </p>
                      </li>
                    ))}
                  </ol>
                )}
              </section>

              {selectedFinding.evidence && (
                <details className="rounded-xl border border-enterprise-border bg-enterprise-bg">
                  <summary className="flex cursor-pointer list-none items-center justify-between p-4 text-sm font-medium focus:outline-none focus:ring-2 focus:ring-enterprise-accent">
                    Technical evidence <ChevronDown aria-hidden="true" className="h-4 w-4 text-enterprise-subtext" />
                  </summary>
                  <pre className="max-h-64 overflow-auto border-t border-enterprise-border p-4 text-xs text-enterprise-subtext">{JSON.stringify(selectedFinding.evidence, null, 2)}</pre>
                </details>
              )}

              {actionError && <p role="alert" className="text-sm text-red-700 dark:text-red-300">{actionError}</p>}
              <div className="flex flex-wrap gap-2">
                <button type="button" disabled={actionLoading || String(selectedFinding.status).toUpperCase() === 'ACKNOWLEDGED' || String(selectedFinding.status).toUpperCase() === 'RESOLVED'}
                  onClick={() => handleLifecycleAction('acknowledge')} className="rounded-lg border border-enterprise-border px-4 py-2 text-sm font-medium text-enterprise-text hover:bg-enterprise-bg disabled:cursor-not-allowed disabled:opacity-50">
                  {actionLoading ? 'Saving…' : 'Acknowledge'}
                </button>
                <button type="button" disabled={actionLoading || String(selectedFinding.status).toUpperCase() === 'RESOLVED'}
                  onClick={() => handleLifecycleAction('resolve')} className="rounded-lg bg-enterprise-accent px-4 py-2 text-sm font-semibold text-white hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50">
                  Mark resolved
                </button>
              </div>
            </div>
          </section>
        </div>
      )}
    </main>
  );
};
