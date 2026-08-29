import { useState, useMemo } from 'react';
import { ShieldAlert, Search, ArrowUpDown, ShieldCheck } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getRiskAssessmentFindings } from '../api/risks';
import { getReportsSummary } from '../api/reports';
import { ScanTrigger } from '../components/ScanTrigger';
import { ScannedRegionBadge } from '../components/ScannedRegionBadge';
import type { RiskFinding } from '../types';

interface RiskAssessmentProps {
  search?: string;
}

export const RiskAssessment: React.FC<RiskAssessmentProps> = ({ search = '' }) => {
  const [localSearch, setLocalSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');

  const searchQuery = search || localSearch;

  const { data: risksData } = useQuery({
    queryKey: ['riskAssessmentFindings'],
    queryFn: getRiskAssessmentFindings,
    refetchInterval: 10000
  });

  const { data: reportsData } = useQuery({
    queryKey: ['reportsSummary'],
    queryFn: getReportsSummary,
    refetchInterval: 10000
  });

  const risks = risksData || [];
  const complianceCategories = reportsData?.compliance || [
    { name: 'MFA Enforcement Coverage', score: 100, details: 'Evaluating active user accounts' },
    { name: 'IAM Least Privilege Scoping', score: 100, details: 'Evaluating IAM policy ASTs' },
    { name: 'Public Resource Access Block', score: 100, details: 'Evaluating S3 Block Public Access' },
    { name: 'AssumeRole Trust Boundary Control', score: 100, details: 'Evaluating role trust documents' }
  ];

  const handleSortToggle = () => {
    setSortOrder((prev) => (prev === 'desc' ? 'asc' : 'desc'));
  };

  const filteredRisks = useMemo(() => {
    return risks
      .filter((risk) => {
        const matchesSearch =
          risk.identity.toLowerCase().includes(searchQuery.toLowerCase()) ||
          risk.issue.toLowerCase().includes(searchQuery.toLowerCase()) ||
          risk.recommendation.toLowerCase().includes(searchQuery.toLowerCase());

        const matchesSeverity = severityFilter === 'ALL' || risk.severity.toUpperCase() === severityFilter.toUpperCase();

        return matchesSearch && matchesSeverity;
      })
      .sort((a, b) => {
        return sortOrder === 'desc' ? b.riskScore - a.riskScore : a.riskScore - b.riskScore;
      });
  }, [risks, searchQuery, severityFilter, sortOrder]);

  const getSeverityClass = (severity: RiskFinding['severity']) => {
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
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-enterprise-card border border-enterprise-border p-4 rounded-xl">
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

      {/* Findings Table */}
      <div className="bg-enterprise-card border border-enterprise-border rounded-xl shadow-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-enterprise-border bg-gray-900/50 text-[10px] uppercase tracking-wider text-enterprise-subtext font-bold">
                <th className="py-3 px-4">Entity / Principal</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Security Issue & Evidence</th>
                <th className="py-3 px-4">Remediation Guidance</th>
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
                  <td colSpan={6} className="py-8 text-center text-enterprise-subtext">
                    No risk findings matched your current filters.
                  </td>
                </tr>
              ) : (
                filteredRisks.map((risk) => (
                  <tr key={risk.id} className="hover:bg-gray-800/40 transition-colors">
                    <td className="py-3 px-4 font-mono font-bold text-white">
                      {risk.identity}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-gray-900 text-gray-300 font-mono text-[10px] border border-gray-700">
                        {risk.identityType}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-gray-300 max-w-sm leading-relaxed">
                      {risk.issue}
                    </td>
                    <td className="py-3 px-4 text-enterprise-subtext max-w-sm leading-relaxed">
                      {risk.recommendation}
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
    </div>
  );
};
