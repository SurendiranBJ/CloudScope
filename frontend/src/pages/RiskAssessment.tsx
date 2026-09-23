import { useState, useMemo } from 'react';
import { ShieldAlert, Search, ArrowUpDown, ShieldCheck, TrendingUp, TrendingDown, Activity } from 'lucide-react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  getRiskAssessmentFindings,
  getSecurityFindings,
  acknowledgeFinding,
  resolveFinding,
  suppressFinding
} from '../api/risks';
import { getReportsSummary } from '../api/reports';
import { getSimulationState, getSimulationRisk } from '../api/simulation';
import { ScanTrigger } from '../components/ScanTrigger';
import { ScannedRegionBadge } from '../components/ScannedRegionBadge';

function SimulationRiskOverlay() {
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
  return (
    <div className="p-4 rounded-xl border border-amber-500/25 bg-amber-500/5 flex items-center gap-6 flex-wrap">
      <div className="flex items-center gap-2 shrink-0">
        <Activity className="w-4 h-4 text-amber-400" />
        <span className="text-sm font-semibold text-amber-400">Simulation Active</span>
        <span className="text-xs text-amber-500/80">— {simState.pending_changes} pending change{simState.pending_changes !== 1 ? 's' : ''}</span>
      </div>
      {riskData && (
        <div className="flex items-center gap-3 text-sm">
          <div className="text-center">
            <p className="text-[10px] text-enterprise-subtext uppercase">Current</p>
            <p className="font-bold text-white font-mono">{riskData.current_score}<span className="text-xs text-enterprise-subtext">/100</span></p>
          </div>
          <div className={`flex items-center gap-1 font-bold ${delta > 0 ? 'text-red-400' : delta < 0 ? 'text-green-400' : 'text-gray-400'}`}>
            {delta > 0 ? <TrendingUp className="w-4 h-4" /> : delta < 0 ? <TrendingDown className="w-4 h-4" /> : null}
            {delta > 0 ? '+' : ''}{delta}
          </div>
          <div className="text-center">
            <p className="text-[10px] text-enterprise-subtext uppercase">Projected</p>
            <p className={`font-bold font-mono ${delta > 10 ? 'text-red-400' : delta < -5 ? 'text-green-400' : 'text-white'}`}>
              {riskData.desired_score}<span className="text-xs text-enterprise-subtext">/100</span>
            </p>
          </div>
          {riskData.top_reasons && riskData.top_reasons.length > 0 && (
            <div className="hidden lg:flex flex-col gap-0.5 max-w-sm">
              {riskData.top_reasons.slice(0, 2).map((r: string, i: number) => (
                <p key={i} className="text-[10px] text-enterprise-subtext">• {r}</p>
              ))}
            </div>
          )}
        </div>
      )}
      <Link
        to="/changes"
        className="ml-auto shrink-0 text-xs text-amber-400 hover:text-amber-300 font-semibold hover:underline"
      >
        Manage Changes →
      </Link>
    </div>
  );
}

interface RiskAssessmentProps {
  search?: string;
}

export const RiskAssessment: React.FC<RiskAssessmentProps> = ({ search = '' }) => {
  const [localSearch, setLocalSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');
  const [selectedFinding, setSelectedFinding] = useState<any | null>(null);
  const [actionLoading, setActionLoading] = useState<boolean>(false);

  const queryClient = useQueryClient();
  const searchQuery = search || localSearch;

  const { data: findingsData, refetch: refetchFindings } = useQuery({
    queryKey: ['securityFindings'],
    queryFn: () => getSecurityFindings(),
    refetchInterval: 10000
  });

  const { data: risksData } = useQuery({
    queryKey: ['riskAssessmentFindings'],
    queryFn: getRiskAssessmentFindings,
    refetchInterval: 10000,
    enabled: !findingsData || findingsData.length === 0
  });

  const { data: reportsData } = useQuery({
    queryKey: ['reportsSummary'],
    queryFn: getReportsSummary,
    refetchInterval: 10000
  });

  // Use canonical findings if available, else fallback to risks
  const rawList: any[] = (findingsData && findingsData.length > 0) ? findingsData : (risksData || []);

  const complianceCategories = reportsData?.compliance || [
    { name: 'MFA Enforcement Coverage', score: 100, details: 'Evaluating active user accounts' },
    { name: 'IAM Least Privilege Scoping', score: 100, details: 'Evaluating IAM policy ASTs' },
    { name: 'Public Resource Access Block', score: 100, details: 'Evaluating S3 Block Public Access' },
    { name: 'AssumeRole Trust Boundary Control', score: 100, details: 'Evaluating role trust documents' }
  ];

  const handleSortToggle = () => {
    setSortOrder((prev) => (prev === 'desc' ? 'asc' : 'desc'));
  };

  const handleLifecycleAction = async (action: 'acknowledge' | 'resolve' | 'suppress') => {
    if (!selectedFinding) return;
    setActionLoading(true);
    try {
      if (action === 'acknowledge') await acknowledgeFinding(selectedFinding.id);
      else if (action === 'resolve') await resolveFinding(selectedFinding.id);
      else if (action === 'suppress') await suppressFinding(selectedFinding.id);

      await refetchFindings();
      queryClient.invalidateQueries({ queryKey: ['securityFindings'] });
      queryClient.invalidateQueries({ queryKey: ['riskAssessmentFindings'] });

      // Update current selected finding status in modal
      const newStatus = action === 'acknowledge' ? 'ACKNOWLEDGED' : (action === 'resolve' ? 'RESOLVED' : 'SUPPRESSED');
      setSelectedFinding((prev: any) => prev ? { ...prev, status: newStatus } : null);
    } catch (err) {
      console.error(`Failed to perform ${action}:`, err);
    } finally {
      setActionLoading(false);
    }
  };

  const filteredRisks = useMemo(() => {
    return rawList
      .filter((item) => {
        const idText = item.identity || item.principal || item.resource || '';
        const issueText = item.issue || item.description || item.title || '';
        const recText = item.recommendation || item.remediation?.title || '';

        const matchesSearch =
          idText.toLowerCase().includes(searchQuery.toLowerCase()) ||
          issueText.toLowerCase().includes(searchQuery.toLowerCase()) ||
          recText.toLowerCase().includes(searchQuery.toLowerCase());

        const matchesSeverity = severityFilter === 'ALL' || item.severity?.toUpperCase() === severityFilter.toUpperCase();
        const matchesCategory = categoryFilter === 'ALL' || (item.category && item.category.toUpperCase() === categoryFilter.toUpperCase());
        const matchesStatus = statusFilter === 'ALL' || (item.status && item.status.toUpperCase() === statusFilter.toUpperCase());

        return matchesSearch && matchesSeverity && matchesCategory && matchesStatus;
      })
      .sort((a, b) => {
        return sortOrder === 'desc' ? b.riskScore - a.riskScore : a.riskScore - b.riskScore;
      });
  }, [rawList, searchQuery, severityFilter, categoryFilter, statusFilter, sortOrder]);

  const getSeverityClass = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'text-enterprise-critical bg-enterprise-critical/15 border-enterprise-critical/20 font-extrabold animate-pulse';
      case 'high':
        return 'text-enterprise-warning bg-enterprise-warning/15 border-enterprise-warning/20 font-bold';
      case 'medium':
        return 'text-enterprise-accent bg-enterprise-accent/15 border-enterprise-accent/20 font-semibold';
      case 'low':
        return 'text-enterprise-success bg-enterprise-success/15 border-enterprise-success/20 font-medium';
      default:
        return 'text-enterprise-subtext bg-gray-800 border-gray-700';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status?.toUpperCase()) {
      case 'ACKNOWLEDGED':
        return 'bg-blue-900/60 text-blue-300 border-blue-500/40';
      case 'RESOLVED':
        return 'bg-emerald-900/60 text-emerald-300 border-emerald-500/40';
      case 'SUPPRESSED':
        return 'bg-gray-800 text-gray-400 border-gray-600';
      case 'OPEN':
      default:
        return 'bg-red-900/60 text-red-300 border-red-500/40';
    }
  };

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto bg-enterprise-bg select-none">
      {/* Header */}
      <div className="flex justify-between items-center flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-enterprise-critical" />
            <span>Security Risk Assessment</span>
          </h1>
          <p className="text-xs text-enterprise-subtext mt-1">
            Verified security control posture evaluations and active configuration vulnerability findings.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <ScannedRegionBadge />
          <ScanTrigger />
        </div>
      </div>

      {/* Simulation Risk Comparison (only when simulation is active) */}
      <SimulationRiskOverlay />

      {/* Verified Security Control Coverage Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {complianceCategories.map((c: any) => (
          <div
            key={c.name}
            className="p-4 rounded-xl border flex flex-col justify-between bg-enterprise-card border-enterprise-border shadow-lg"
          >
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-gray-200">{c.name}</h3>
              <ShieldCheck className="w-4 h-4 text-enterprise-accent" />
            </div>
            <div className="flex items-baseline justify-between mt-3 mb-1">
              <span className="text-2xl font-black font-mono text-white">{c.score}%</span>
              <span className="text-[10px] text-gray-400 font-semibold uppercase">
                {c.score >= 80 ? 'Verified' : (c.score >= 60 ? 'Warning' : 'Action Required')}
              </span>
            </div>
            <div className="w-full bg-gray-800 h-1.5 rounded-full overflow-hidden mb-2">
              <div
                className={`h-full rounded-full transition-all ${
                  c.score >= 80 ? 'bg-emerald-500' : (c.score >= 60 ? 'bg-amber-500' : 'bg-red-500')
                }`}
                style={{ width: `${c.score}%` }}
              />
            </div>
            <p className="text-[10px] text-enterprise-subtext truncate" title={c.details}>{c.details}</p>
          </div>
        ))}
      </div>

      {/* Table Filters */}
      <div className="space-y-3 bg-enterprise-card border border-enterprise-border p-4 rounded-xl">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Search */}
          <div className="relative">
            <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Search className="h-4 w-4 text-enterprise-subtext" />
            </span>
            <input
              type="text"
              placeholder="Search identity, issue description, or recommendation..."
              value={localSearch}
              onChange={(e) => setLocalSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-gray-900 border border-enterprise-border rounded-lg text-xs text-gray-200 placeholder-enterprise-subtext focus:outline-none focus:border-enterprise-accent focus:ring-1 focus:ring-enterprise-accent"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex gap-2 items-center justify-start md:justify-end flex-wrap">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold uppercase tracking-wider transition-colors ${
                  severityFilter === sev
                    ? 'bg-enterprise-accent text-white shadow-md'
                    : 'bg-gray-900 text-enterprise-subtext border border-enterprise-border hover:border-gray-600 hover:text-gray-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {/* Secondary Category & Status Filters */}
        <div className="flex flex-wrap gap-4 items-center pt-2 border-t border-enterprise-border/50 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-enterprise-subtext text-[11px] font-semibold uppercase tracking-wider">Category:</span>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="bg-gray-900 border border-enterprise-border rounded-lg px-2.5 py-1 text-xs text-gray-200 focus:outline-none focus:border-enterprise-accent"
            >
              <option value="ALL">All Categories</option>
              <option value="IAM">IAM</option>
              <option value="RESOURCE">Resource</option>
              <option value="PRIVILEGE_ESCALATION">Privilege Escalation</option>
              <option value="LATERAL_MOVEMENT">Lateral Movement</option>
              <option value="CREDENTIAL">Credential</option>
              <option value="CONFIGURATION">Configuration</option>
              <option value="DATA_ACCESS">Data Access</option>
              <option value="MONITORING">Monitoring / CloudTrail</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-enterprise-subtext text-[11px] font-semibold uppercase tracking-wider">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-gray-900 border border-enterprise-border rounded-lg px-2.5 py-1 text-xs text-gray-200 focus:outline-none focus:border-enterprise-accent"
            >
              <option value="ALL">All Statuses</option>
              <option value="OPEN">Open Only</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="RESOLVED">Resolved</option>
              <option value="SUPPRESSED">Suppressed</option>
            </select>
          </div>

          <span className="ml-auto text-[11px] text-enterprise-subtext">
            Showing <span className="font-bold text-white">{filteredRisks.length}</span> of {rawList.length} finding{rawList.length !== 1 ? 's' : ''}
          </span>
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-enterprise-card border border-enterprise-border rounded-xl shadow-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-enterprise-border bg-gray-900/50 text-[10px] uppercase tracking-wider text-enterprise-subtext font-bold">
                <th className="py-3 px-4">Entity / Principal</th>
                <th className="py-3 px-4">Category / Type</th>
                <th className="py-3 px-4">Security Issue & Evidence</th>
                <th className="py-3 px-4">Remediation Guidance</th>
                <th className="py-3 px-4 text-center">Status</th>
                <th className="py-3 px-4 text-right cursor-pointer select-none" onClick={handleSortToggle}>
                  <div className="flex items-center justify-end gap-1">
                    <span>Risk Score</span>
                    <ArrowUpDown className="w-3 h-3 text-enterprise-subtext" />
                  </div>
                </th>
                <th className="py-3 px-4 text-center">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-enterprise-border text-xs text-gray-300">
              {filteredRisks.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-enterprise-subtext">
                    No risk findings matched your current filters.
                  </td>
                </tr>
              ) : (
                filteredRisks.map((risk) => (
                  <tr
                    key={risk.id}
                    onClick={() => setSelectedFinding(risk)}
                    className="hover:bg-gray-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="py-3 px-4 font-mono font-bold text-white group-hover:text-blue-400 transition-colors">
                      {risk.identity || risk.principal || risk.resource}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-gray-900 text-gray-300 font-mono text-[10px] border border-gray-700">
                        {risk.category || risk.identityType || 'Security'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-gray-300 max-w-sm leading-relaxed">
                      {risk.issue || risk.description || risk.title}
                    </td>
                    <td className="py-3 px-4 text-enterprise-subtext max-w-sm leading-relaxed">
                      {risk.recommendation || risk.remediation?.title}
                    </td>
                    <td className="py-3 px-4 text-center">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider ${getStatusBadge(risk.status || 'OPEN')}`}>
                        {risk.status || 'OPEN'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right font-mono font-bold">
                      <span className={risk.riskScore >= 80 ? 'text-red-400' : (risk.riskScore >= 60 ? 'text-amber-400' : 'text-blue-400')}>
                        {risk.riskScore}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-center">
                      <span className={`inline-block px-2.5 py-0.5 rounded text-[10px] uppercase tracking-wider border ${getSeverityClass(risk.severity)}`}>
                        {risk.severity}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Canonical Finding Details Modal / Drawer */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fadeIn">
          <div className="bg-enterprise-card border border-enterprise-border rounded-2xl max-w-3xl w-full max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col">
            {/* Modal Header */}
            <div className="p-6 border-b border-enterprise-border flex items-start justify-between gap-4 sticky top-0 bg-enterprise-card z-10">
              <div className="space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`px-2.5 py-0.5 rounded text-[10px] uppercase tracking-wider font-extrabold border ${getSeverityClass(selectedFinding.severity)}`}>
                    {selectedFinding.severity}
                  </span>
                  <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider ${getStatusBadge(selectedFinding.status || 'OPEN')}`}>
                    {selectedFinding.status || 'OPEN'}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-gray-900 text-gray-300 font-mono text-[10px] border border-gray-700">
                    Category: {selectedFinding.category || 'Security'}
                  </span>
                  <span className="font-mono text-xs font-bold text-gray-400">
                    Score: <span className={selectedFinding.riskScore >= 80 ? 'text-red-400' : 'text-amber-400'}>{selectedFinding.riskScore}/100</span>
                  </span>
                </div>
                <h2 className="text-lg font-bold text-white tracking-tight mt-1">
                  {selectedFinding.title || selectedFinding.issue || 'Finding Details'}
                </h2>
                <p className="text-xs text-enterprise-subtext font-mono">
                  ID: {selectedFinding.id}
                </p>
              </div>

              <button
                onClick={() => setSelectedFinding(null)}
                className="text-gray-400 hover:text-white p-1 rounded-lg hover:bg-gray-800 transition-colors"
              >
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-6 text-xs text-gray-300">
              {/* Lifecycle Actions */}
              <div className="p-3 bg-gray-900/60 border border-enterprise-border rounded-xl flex items-center justify-between gap-3 flex-wrap">
                <span className="text-[11px] font-semibold text-gray-300 uppercase tracking-wider">
                  Finding Lifecycle Actions:
                </span>
                <div className="flex items-center gap-2">
                  <button
                    disabled={actionLoading || selectedFinding.status === 'ACKNOWLEDGED'}
                    onClick={() => handleLifecycleAction('acknowledge')}
                    className="px-3 py-1.5 rounded-lg bg-blue-600/80 hover:bg-blue-600 text-white font-semibold transition-colors disabled:opacity-40"
                  >
                    Acknowledge
                  </button>
                  <button
                    disabled={actionLoading || selectedFinding.status === 'RESOLVED'}
                    onClick={() => handleLifecycleAction('resolve')}
                    className="px-3 py-1.5 rounded-lg bg-emerald-600/80 hover:bg-emerald-600 text-white font-semibold transition-colors disabled:opacity-40"
                  >
                    Mark Resolved
                  </button>
                  <button
                    disabled={actionLoading || selectedFinding.status === 'SUPPRESSED'}
                    onClick={() => handleLifecycleAction('suppress')}
                    className="px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 font-semibold border border-gray-700 transition-colors disabled:opacity-40"
                  >
                    Suppress
                  </button>
                </div>
              </div>

              {/* WHY THIS MATTERS (Impact) */}
              <div className="space-y-1.5">
                <h3 className="text-xs font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                  <span>⚡ Why This Matters (Impact)</span>
                </h3>
                <div className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-500/30 text-amber-200/90 leading-relaxed">
                  {selectedFinding.impact || selectedFinding.description || selectedFinding.issue || 'This finding introduces unnecessary exposure or privilege escalation potential in your AWS environment.'}
                </div>
              </div>

              {/* HOW TO FIX IT (Remediation Guidance) */}
              <div className="space-y-2">
                <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                  <span>🛡️ How To Fix It (Remediation Guidance)</span>
                  {selectedFinding.remediation?.priority && (
                    <span className="ml-auto text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/40 text-emerald-300">
                      Priority: {selectedFinding.remediation.priority}
                    </span>
                  )}
                </h3>
                <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 space-y-3">
                  <p className="font-semibold text-white">
                    {selectedFinding.remediation?.title || selectedFinding.recommendation || 'Remediate configuration'}
                  </p>
                  {selectedFinding.remediation?.summary && (
                    <p className="text-gray-300 text-xs">
                      {selectedFinding.remediation.summary}
                    </p>
                  )}
                  {selectedFinding.remediation?.steps && selectedFinding.remediation.steps.length > 0 && (
                    <ol className="list-decimal list-inside space-y-1.5 text-gray-300 pl-1">
                      {selectedFinding.remediation.steps.map((st: string, idx: number) => (
                        <li key={idx} className="leading-relaxed">{st}</li>
                      ))}
                    </ol>
                  )}
                  {selectedFinding.remediation?.references && selectedFinding.remediation.references.length > 0 && (
                    <div className="pt-2 border-t border-emerald-500/20 text-[11px] text-gray-400 flex items-center gap-2 flex-wrap">
                      <span className="font-semibold">AWS Documentation:</span>
                      {selectedFinding.remediation.references.map((ref: string, idx: number) => (
                        <a
                          key={idx}
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-400 hover:underline truncate max-w-sm"
                        >
                          {ref}
                        </a>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* FACTOR EVIDENCE */}
              {selectedFinding.riskFactors && selectedFinding.riskFactors.length > 0 && (
                <div className="space-y-1.5">
                  <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider">
                    Risk Factor Breakdown
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {selectedFinding.riskFactors.map((rf: any, idx: number) => (
                      <div key={idx} className="p-2.5 bg-gray-900 border border-enterprise-border rounded-lg flex items-center justify-between text-xs">
                        <span className="text-gray-300">{rf.reason || rf.code}</span>
                        <span className="font-mono font-bold text-red-400 shrink-0 ml-2">+{rf.points} pts</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TECHNICAL EVIDENCE */}
              {selectedFinding.evidence && (
                <div className="space-y-1.5">
                  <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider">
                    Configuration Evidence Payload
                  </h3>
                  <pre className="p-3 bg-gray-950 border border-enterprise-border rounded-xl font-mono text-[11px] text-gray-300 overflow-x-auto max-h-48">
                    {JSON.stringify(selectedFinding.evidence, null, 2)}
                  </pre>
                </div>
              )}

              {/* METADATA GRID */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 p-4 bg-gray-900/40 border border-enterprise-border rounded-xl text-[11px]">
                <div>
                  <span className="text-enterprise-subtext block uppercase tracking-wider">Principal / Target:</span>
                  <span className="font-mono text-white font-semibold truncate block">
                    {selectedFinding.principal || selectedFinding.resource || selectedFinding.identity || 'N/A'}
                  </span>
                </div>
                <div>
                  <span className="text-enterprise-subtext block uppercase tracking-wider">Region:</span>
                  <span className="font-mono text-white font-semibold block">{selectedFinding.region || 'global'}</span>
                </div>
                <div>
                  <span className="text-enterprise-subtext block uppercase tracking-wider">Source:</span>
                  <span className="font-mono text-white font-semibold block">{selectedFinding.source || 'STATIC_IAM'}</span>
                </div>
                <div>
                  <span className="text-enterprise-subtext block uppercase tracking-wider">First Seen:</span>
                  <span className="font-mono text-gray-300 block">{selectedFinding.firstSeen ? new Date(selectedFinding.firstSeen).toLocaleString() : 'Current Scan'}</span>
                </div>
                <div>
                  <span className="text-enterprise-subtext block uppercase tracking-wider">Last Seen:</span>
                  <span className="font-mono text-gray-300 block">{selectedFinding.lastSeen ? new Date(selectedFinding.lastSeen).toLocaleString() : 'Current Scan'}</span>
                </div>
                {selectedFinding.eventId && (
                  <div>
                    <span className="text-enterprise-subtext block uppercase tracking-wider">CloudTrail Event ID:</span>
                    <span className="font-mono text-blue-400 block truncate">{selectedFinding.eventId}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-enterprise-border flex justify-end sticky bottom-0 bg-enterprise-card z-10">
              <button
                onClick={() => setSelectedFinding(null)}
                className="px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-white font-semibold text-xs transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
