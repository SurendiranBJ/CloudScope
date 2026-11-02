import { useState } from 'react';
import {
  FileBarChart,
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
import { getGraphElements } from '../api/graph';

export const Reports: React.FC = () => {
  const [downloading, setDownloading] = useState<string | null>(null);
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const { data: reportsData, isLoading: reportsLoading, isError: reportsError } = useQuery({
    queryKey: ['reportsSummary'],
    queryFn: getReportsSummary,
    refetchInterval: 30000
  });

  const { data: graphData, isLoading: graphLoading, isError: graphError } = useQuery({
    queryKey: ['graphElements'],
    queryFn: getGraphElements
  });

  const reportTypes = [
    { id: 'json', title: 'Security Assessment Data', format: 'JSON Dataset', desc: 'Snapshot-scoped findings, severity totals, posture score, and graph relationships.', icon: FileJson },
    { id: 'svg', title: 'Identity Graph Architecture', format: 'SVG Graphic', desc: 'Vector drawing exporting the current visual state, groups, and connections in the Explorer canvas.', icon: Network }
  ];

  const generateSVGGraph = (elements: any[]) => {
    const nodes = elements.filter((e) => !e.data.source);
    const edges = elements.filter((e) => e.data.source);

    const typeColors: Record<string, string> = {
      User: '#3B82F6',
      Role: '#8B5CF6',
      Policy: '#14B8A6',
      S3: '#F59E0B',
      EC2: '#10B981',
      Lambda: '#EC4899',
      Secrets: '#EF4444',
      RDS: '#0EA5E9',
      DynamoDB: '#8B5CF6'
    };

    const width = 1000;
    const height = 700;

    // Layout nodes in a circle
    const nodePositions: Record<string, { x: number; y: number; type: string; label: string }> = {};
    const radius = Math.min(width, height) * 0.38;
    const cx = width / 2;
    const cy = height / 2;

    nodes.forEach((n, idx) => {
      const angle = (2 * Math.PI * idx) / Math.max(nodes.length, 1);
      const x = cx + radius * Math.cos(angle);
      const y = cy + radius * Math.sin(angle);
      nodePositions[n.data.id] = {
        x: Math.round(x),
        y: Math.round(y),
        type: n.data.type || 'Resource',
        label: n.data.label || n.data.id
      };
    });

    const escapeXml = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[char]!);
    let svgContent = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">\n`;
    svgContent += `  <rect width="100%" height="100%" fill="#0B1120"/>\n`;
    svgContent += `  <text x="30" y="40" fill="#FFFFFF" font-family="sans-serif" font-size="20" font-weight="bold">CloudScope - Identity Graph Architecture</text>\n`;
    svgContent += `  <text x="30" y="62" fill="#9CA3AF" font-family="sans-serif" font-size="12">Generated on ${new Date().toISOString().split('T')[0]}</text>\n`;

    // Draw Edges
    svgContent += `  <g id="edges" stroke="#475569" stroke-width="1.5" stroke-dasharray="4,4">\n`;
    edges.forEach((e) => {
      const src = nodePositions[e.data.source];
      const tgt = nodePositions[e.data.target];
      if (src && tgt) {
        svgContent += `    <line x1="${src.x}" y1="${src.y}" x2="${tgt.x}" y2="${tgt.y}" />\n`;
      }
    });
    svgContent += `  </g>\n`;

    // Draw Nodes
    svgContent += `  <g id="nodes">\n`;
    Object.entries(nodePositions).forEach(([_, n]) => {
      const color = typeColors[n.type] || '#3B82F6';
      svgContent += `    <g transform="translate(${n.x}, ${n.y})">\n`;
      svgContent += `      <circle r="18" fill="${color}" stroke="#FFFFFF" stroke-width="2"/>\n`;
      svgContent += `      <text y="32" fill="#E5E7EB" font-family="sans-serif" font-size="11" font-weight="bold" text-anchor="middle">${escapeXml(n.label)}</text>\n`;
      svgContent += `      <text y="44" fill="#9CA3AF" font-family="sans-serif" font-size="9" text-anchor="middle">${escapeXml(n.type)}</text>\n`;
      svgContent += `    </g>\n`;
    });
    svgContent += `  </g>\n`;
    svgContent += `</svg>`;

    return svgContent;
  };

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    link.remove();
    // Keep the object URL alive through the browser's download handoff.
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const handleDownload = async (id: string) => {
    if (reportsLoading || reportsError || ((id === 'json' || id === 'svg') && (graphLoading || graphError))) {
      setDownloadError('Report data is still loading or unavailable. Retry after the report summary and graph finish loading.');
      return;
    }
    setDownloading(id);
    setDownloadSuccess(null);
    setDownloadError(null);

    try {
      if (id === 'json') {
        const content = JSON.stringify({
          exportedAt: new Date().toISOString(),
          platform: 'CloudScope AWS IAM Security Analysis',
          hasData: reportsData?.has_data ?? Boolean(reportsData?.summary),
          securityScore: reportsData?.summary?.score ?? null,
          grade: reportsData?.summary?.grade ?? 'No scan data available',
          findingsCount: reportsData?.summary?.findings_count ?? 0,
          findingsBySeverity: reportsData?.findings_by_severity || {},
          findingsByCategory: reportsData?.findings_by_category || {},
          canonicalFindings: reportsData?.findings || [],
          graph: {
            nodes: (graphData || []).filter(e => !e.data.source),
            relationships: (graphData || []).filter(e => !!e.data.source)
          }
        }, null, 2);
        downloadBlob(new Blob([content], { type: 'application/json;charset=utf-8' }), 'cloudscope-security-assessment.json');
      } else if (id === 'svg') {
        const svgString = generateSVGGraph(graphData || []);
        downloadBlob(new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' }), 'cloudscope-identity-graph.svg');
      }

      setDownloading(null);
      setDownloadSuccess(id);
      setTimeout(() => setDownloadSuccess(null), 3000);
    } catch (err) {
      console.error(`Export failed for ${id}:`, err);
      setDownloadError(`Could not export ${id.toUpperCase()} report. Please retry.`);
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto bg-enterprise-bg">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
          <FileBarChart className="w-6 h-6 text-enterprise-accent" />
          <span>Security Assessment</span>
        </h1>
        <p className="text-xs text-enterprise-subtext mt-1">
          Review the selected snapshot’s posture, findings, and graph evidence, then export the assessment data.
        </p>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Security Summary overview */}
        <div className="bg-enterprise-card border border-enterprise-border p-5 rounded-xl space-y-4 flex flex-col justify-between">
          <div className="space-y-4">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider">
              Overall Platform Summary
            </h2>
            <div className="space-y-3">
              <div className="flex justify-between items-center text-xs">
                <span className="text-enterprise-subtext font-medium">AWS Security Score:</span>
                <span className="text-enterprise-success font-bold font-mono">
                  {reportsData?.summary?.score !== null && reportsData?.summary?.score !== undefined
                    ? `${reportsData.summary.score}% (${reportsData.summary.grade || 'Evaluated'})`
                    : 'No scan data available'}
                </span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-enterprise-subtext font-medium">Active Findings:</span>
                <span className="text-enterprise-critical font-bold font-mono">
                  {reportsData?.summary?.findings_count !== undefined
                    ? `${reportsData.summary.findings_count} Open Findings`
                    : 'Not available'}
                </span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-enterprise-subtext font-medium">Tracked Resources:</span>
                <span className="text-white font-bold font-mono">
                  {graphData ? `${(graphData || []).filter(e => !e.data.source).length} Assets Discovered` : 'Not available'}
                </span>
              </div>
            </div>
          </div>
          <div className="p-3 bg-enterprise-accent/15 border border-enterprise-accent/30 rounded-lg text-[10px] leading-relaxed text-enterprise-accent font-semibold flex gap-2">
            <ShieldCheck className="w-4 h-4 text-enterprise-accent shrink-0" />
            <span>Scores reflect verified evidence from current inventory and IAM AST evaluation.</span>
          </div>
        </div>
      </div>

      {/* Export Downloads List */}
      <div className="space-y-4">
        <h2 className="text-xs font-bold text-white uppercase tracking-wider">
          Generate & Export Report Documents
        </h2>
        {downloadError && <p role="alert" className="text-xs text-enterprise-critical">{downloadError}</p>}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
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
                  disabled={!!downloading || reportsLoading || reportsError || ((report.id === 'json' || report.id === 'svg') && (graphLoading || graphError))}
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
