import { useState, useMemo } from 'react';
import { ShieldAlert, Search, ArrowUpDown } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getRiskAssessmentFindings } from '../api/risks';
import { mockRisks } from '../data/risks';
import type { RiskFinding } from '../types';

interface RiskAssessmentProps {
  search?: string;
}

export const RiskAssessment: React.FC<RiskAssessmentProps> = ({ search = '' }) => {
  const [localSearch, setLocalSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');

  const searchQuery = search || localSearch;

  const { data } = useQuery({
    queryKey: ['riskAssessmentFindings'],
    queryFn: getRiskAssessmentFindings,
    refetchInterval: 10000
  });

  const risks = data || mockRisks;

  const complianceScores = [
    { name: 'CIS AWS Foundations', score: 72, color: 'text-enterprise-warning border-enterprise-warning/20 bg-enterprise-warning/5' },
    { name: 'SOC 2 Type II', score: 86, color: 'text-enterprise-success border-enterprise-success/20 bg-enterprise-success/5' },
    { name: 'HIPAA Security Rule', score: 91, color: 'text-enterprise-success border-enterprise-success/20 bg-enterprise-success/5' }
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

        const matchesSeverity = severityFilter === 'ALL' || risk.severity === severityFilter;

        return matchesSearch && matchesSeverity;
      })
      .sort((a, b) => {
        return sortOrder === 'desc' ? b.riskScore - a.riskScore : a.riskScore - b.riskScore;
      });
  }, [risks, searchQuery, severityFilter, sortOrder]);

  const getSeverityClass = (severity: RiskFinding['severity']) => {
    switch (severity) {
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
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
          <ShieldAlert className="w-6 h-6 text-enterprise-critical" />
          <span>Security Risk Assessment</span>
        </h1>
        <p className="text-xs text-enterprise-subtext mt-1">
          Review regulatory audit compliance scores and explore active configuration vulnerability flags.
        </p>
      </div>

      {/* Compliance Scores Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {complianceScores.map((c) => (
          <div
            key={c.name}
            className={`p-4 rounded-xl border flex justify-between items-center bg-enterprise-card border-enterprise-border ${c.color}`}
          >
            <div>
              <h3 className="text-xs font-bold text-gray-200">{c.name}</h3>
              <p className="text-[10px] text-enterprise-subtext mt-1">Compliance Status</p>
            </div>
            <div className="flex flex-col items-end gap-1">
              <span className="text-xl font-black">{c.score}%</span>
              <div className="w-16 bg-gray-800 h-1.5 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${c.score >= 85 ? 'bg-enterprise-success' : 'bg-enterprise-warning'}`}
                  style={{ width: `${c.score}%` }}
                />
              </div>
            </div>
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
            placeholder="Search risk targets, issues, recommendations..."
            value={searchQuery}
            onChange={(e) => setLocalSearch(e.target.value)}
            className="w-full bg-enterprise-bg/60 border border-enterprise-border rounded-lg pl-10 pr-4 py-2 text-xs text-white placeholder-enterprise-subtext focus:outline-none focus:border-enterprise-accent transition-colors"
          />
        </div>

        {/* Severity Filter */}
        <div className="flex items-center gap-2">
          <span className="text-xs font-bold text-enterprise-subtext whitespace-nowrap">Vulnerability Grade:</span>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full bg-enterprise-bg/60 border border-enterprise-border rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-enterprise-accent"
          >
            <option value="ALL" className="bg-enterprise-card">All Risks</option>
            <option value="critical" className="bg-enterprise-card text-enterprise-critical">Critical Severity Only</option>
            <option value="high" className="bg-enterprise-card text-enterprise-warning">High Severity Only</option>
            <option value="medium" className="bg-enterprise-card text-enterprise-accent">Medium Severity Only</option>
            <option value="low" className="bg-enterprise-card text-enterprise-success">Low Severity Only</option>
          </select>
        </div>
      </div>

      {/* Risks Table */}
      <div className="bg-enterprise-card border border-enterprise-border rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-enterprise-bg/40 border-b border-enterprise-border text-xs font-bold text-enterprise-subtext">
                <th className="p-4">Identity / Target</th>
                <th className="p-4">Security Finding & Issue Details</th>
                <th className="p-4">Severity</th>
                <th className="p-4 cursor-pointer hover:text-white transition-colors" onClick={handleSortToggle}>
                  <div className="flex items-center gap-1.5">
                    <span>Risk Score</span>
                    <ArrowUpDown className="w-3.5 h-3.5" />
                  </div>
                </th>
                <th className="p-4">Post-Remediation Recommendation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-enterprise-border text-xs text-gray-200">
              {filteredRisks.length > 0 ? (
                filteredRisks.map((risk) => (
                  <tr key={risk.id} className="hover:bg-gray-800/10 transition-colors">
                    <td className="p-4 font-bold text-white max-w-[120px] truncate" title={risk.identity}>
                      <div className="flex flex-col gap-1">
                        <span>{risk.identity}</span>
                        <span className="text-[9px] text-enterprise-subtext uppercase font-bold tracking-wider">
                          {risk.identityType}
                        </span>
                      </div>
                    </td>
                    <td className="p-4 text-gray-300 leading-relaxed font-medium max-w-[300px] whitespace-normal">
                      {risk.issue}
                    </td>
                    <td className="p-4">
                      <span className={`px-2.5 py-0.5 rounded border text-[10px] uppercase inline-flex ${getSeverityClass(risk.severity)}`}>
                        {risk.severity}
                      </span>
                    </td>
                    <td className="p-4 font-bold text-sm">{risk.riskScore}</td>
                    <td className="p-4 text-enterprise-subtext italic leading-relaxed max-w-[280px]">
                      {risk.recommendation}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="text-center p-8 text-enterprise-subtext font-medium text-xs">
                    No active vulnerabilities found matching your search.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
