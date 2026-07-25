import { useState } from 'react';
import {
  FileBarChart,
  FileText,
  Download,
  CheckCircle,
  RefreshCw,
  ShieldCheck,
  FileJson,
  Network
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useQuery } from '@tanstack/react-query';
import { getReportsSummary } from '../api/reports';

export const Reports: React.FC = () => {
  const [downloading, setDownloading] = useState<string | null>(null);
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);

  const { data } = useQuery({
    queryKey: ['reportsSummary'],
    queryFn: getReportsSummary,
    refetchInterval: 30000
  });

  const reportTypes = [
    { id: 'pdf', title: 'Security Audit Assessment Profile', format: 'PDF Document', desc: 'A complete management-level overview detailing critical attack paths, compliance deviations, and prioritized remediations list.', icon: FileText },
    { id: 'csv', title: 'Asset Configuration Ledger', format: 'CSV spreadsheet', desc: 'Flat tabular manifest of all IAM users, trust documents, EC2 profiles, and credentials status tags.', icon: Download },
    { id: 'json', title: 'Attack Path Diffs Payload', format: 'JSON Dataset', desc: 'Raw graph representation including vertices and assumed relationship metadata edges for external API integrations.', icon: FileJson },
    { id: 'svg', title: 'Identity Graph Architecture', format: 'SVG Graphic', desc: 'Vector drawing exporting the current visual state, groups, and connections in the Explorer canvas.', icon: Network }
  ];

  const handleDownload = (id: string) => {
    setDownloading(id);
    setDownloadSuccess(null);
    setTimeout(() => {
      setDownloading(null);
      setDownloadSuccess(id);
      setTimeout(() => setDownloadSuccess(null), 3000);
    }, 1500); // Simulate export conversion
  };

  const complianceRaw = data?.compliance || [
    { name: 'CIS AWS Foundations Benchmark', score: 72, details: 'Passed: 28 checks | Failed: 11 checks | Ignored: 3' },
    { name: 'SOC 2 Type II Compliance Framework', score: 86, details: 'Passed: 44 checks | Failed: 7 checks | Ignored: 0' },
    { name: 'HIPAA Security Controls Audit', score: 91, details: 'Passed: 19 checks | Failed: 2 checks | Ignored: 1' },
    { name: 'PCI-DSS v4.0 Merchant Standard', score: 65, details: 'Passed: 30 checks | Failed: 16 checks | Ignored: 2' }
  ];

  const getColor = (score: number) => {
    if (score >= 80) return 'border-l-4 border-enterprise-success bg-enterprise-success/5 text-enterprise-success';
    if (score >= 60) return 'border-l-4 border-enterprise-warning bg-enterprise-warning/5 text-enterprise-warning';
    return 'border-l-4 border-enterprise-critical bg-enterprise-critical/5 text-enterprise-critical';
  };

  const complianceStandards = complianceRaw.map(standard => ({
    name: standard.name,
    status: `${standard.score}% Compliant`,
    details: standard.details,
    color: getColor(standard.score)
  }));

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto bg-enterprise-bg select-none">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
          <FileBarChart className="w-6 h-6 text-enterprise-accent" />
          <span>Security Reports & Audits</span>
        </h1>
        <p className="text-xs text-enterprise-subtext mt-1">
          Export system configuration logs and review compliance audits matching federal and industry standard guidelines.
        </p>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Compliance Assessments */}
        <div className="lg:col-span-2 space-y-4">
          <h2 className="text-xs font-bold text-white uppercase tracking-wider">
            Regulatory Compliance Audits
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {complianceStandards.map((std) => (
              <div
                key={std.name}
                className={`p-4 bg-enterprise-card border border-enterprise-border rounded-xl flex flex-col justify-between gap-3 ${std.color}`}
              >
                <div>
                  <h3 className="text-xs font-bold text-gray-200 leading-tight">{std.name}</h3>
                  <p className="text-[10px] text-enterprise-subtext mt-1">{std.details}</p>
                </div>
                <div className="flex justify-between items-center text-xs font-black">
                  <span>Audit Grade:</span>
                  <span>{std.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Security Summary overview */}
        <div className="bg-enterprise-card border border-enterprise-border p-5 rounded-xl space-y-4 flex flex-col justify-between">
          <div className="space-y-4">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider">
              Overall Platform Summary
            </h2>
            <div className="space-y-3">
              <div className="flex justify-between items-center text-xs">
                <span className="text-enterprise-subtext font-medium">AWS Security Score:</span>
                <span className="text-enterprise-success font-bold">84% (Good)</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-enterprise-subtext font-medium">Critical Vulnerabilities:</span>
                <span className="text-enterprise-critical font-bold">5 Open Findings</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-enterprise-subtext font-medium">Tracked Resources:</span>
                <span className="text-white font-bold">126 Assets Total</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-enterprise-subtext font-medium">IAM Policies Audited:</span>
                <span className="text-white font-bold">47 Custom/Managed</span>
              </div>
            </div>
          </div>
          <div className="p-3 bg-enterprise-accent/15 border border-enterprise-accent/30 rounded-lg text-[10px] leading-relaxed text-enterprise-accent font-semibold flex gap-2">
            <ShieldCheck className="w-4 h-4 text-enterprise-accent shrink-0" />
            <span>Platform conforms to CIS AWS Foundations guidelines with 72% compliance.</span>
          </div>
        </div>
      </div>

      {/* Export Downloads List */}
      <div className="space-y-4">
        <h2 className="text-xs font-bold text-white uppercase tracking-wider">
          Generate & Export Report Documents
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {reportTypes.map((report) => {
            const isDownloading = downloading === report.id;
            const isSuccess = downloadSuccess === report.id;

            return (
              <div
                key={report.id}
                className="bg-enterprise-card border border-enterprise-border p-4 rounded-xl flex items-center justify-between gap-4 hover:border-gray-700 transition-colors"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="w-10 h-10 bg-enterprise-bg/60 border border-enterprise-border rounded-lg flex items-center justify-center text-enterprise-accent shrink-0">
                    <report.icon className="w-5 h-5" />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      <h4 className="text-xs font-bold text-white truncate">{report.title}</h4>
                      <span className="text-[8px] bg-gray-800 text-enterprise-subtext font-bold px-1.5 py-0.5 rounded leading-none">
                        {report.format}
                      </span>
                    </div>
                    <p className="text-[10px] text-enterprise-subtext mt-1 line-clamp-2">{report.desc}</p>
                  </div>
                </div>

                {/* Export Action Trigger */}
                <button
                  onClick={() => handleDownload(report.id)}
                  disabled={!!downloading}
                  className="px-3.5 py-2 hover:bg-gray-800 text-enterprise-accent hover:text-white rounded-lg border border-enterprise-border hover:border-gray-700 font-semibold transition-colors flex items-center justify-center shrink-0 w-32"
                >
                  <AnimatePresence mode="wait">
                    {isDownloading ? (
                      <motion.div
                        key="loading"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="flex items-center gap-1.5 text-xs text-enterprise-accent font-bold"
                      >
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Compiling...</span>
                      </motion.div>
                    ) : isSuccess ? (
                      <motion.div
                        key="success"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="flex items-center gap-1 text-xs text-enterprise-success font-bold"
                      >
                        <CheckCircle className="w-3.5 h-3.5" />
                        <span>Downloaded</span>
                      </motion.div>
                    ) : (
                      <motion.div
                        key="idle"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="flex items-center gap-1 text-xs font-bold"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Export Data</span>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
