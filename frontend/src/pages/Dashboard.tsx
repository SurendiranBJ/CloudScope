import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend
} from 'recharts';
import {
  ShieldAlert,
  GitMerge,
  Cloud,
  FileText,
  Key,
  ShieldCheck,
  Activity,
  ArrowRight,
  Download,
  ChevronRight,
  CheckCircle2,
  Sparkles,
  Server,
  Database
} from 'lucide-react';
import { NodeDetailsPanel } from '../components/NodeDetailsPanel';
import { RegionSelector } from '../components/RegionSelector';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getDashboardSummary } from '../api/dashboard';
import { getReportsSummary } from '../api/reports';
import { getAttackPaths } from '../api/attack';
import { getSecurityFindings } from '../api/risks';
import { getConsolidatedAttackPathCount } from '../utils/attackPathGrouping';
import { summarizeDashboardFindings } from '../utils/dashboardMetrics';
import { ScanTrigger } from '../components/ScanTrigger';
import { ScannedRegionBadge } from '../components/ScannedRegionBadge';
import { LastScannedBadge } from '../components/LastScannedBadge';
import { GlobalScanStatus } from '../components/GlobalScanStatus';
import { apiClient } from '../api/client';
import { useScanLifecycle } from '../hooks/useScanLifecycle';
import { useSnapshotView } from '../context/SnapshotViewContext';

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const queryClient = useQueryClient();
  const { isScanning, hasCompletedSnapshot } = useScanLifecycle();
  const { snapshotId } = useSnapshotView();

  // Health data for active region and scan mode
  const { data: healthData } = useQuery({
    queryKey: ['scanHealth'],
    queryFn: async () => {
      const res = await apiClient.get('/health');
      return res.data?.success ? res.data.data : null;
    },
    refetchInterval: 5000,
    staleTime: 2000,
  });
  const handleRegionChanged = () => {
    void queryClient.invalidateQueries({ queryKey: ['scanHealth'] });
  };

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['dashboardSummary'],
    queryFn: getDashboardSummary,
    refetchInterval: 5000
  });

  const { data: reportsData } = useQuery({
    queryKey: ['reportsSummary'],
    queryFn: getReportsSummary,
    refetchInterval: 10000
  });

  const { data: attackPaths } = useQuery({
    queryKey: ['attackPaths'],
    queryFn: getAttackPaths,
    refetchInterval: 10000,
  });

  const { data: securityFindings } = useQuery({
    queryKey: ['securityFindings'],
    queryFn: () => getSecurityFindings(),
    refetchInterval: 10000,
  });

  if (isLoading || !data) {
    if (isError) {
      return (
        <div className="flex-1 flex items-center justify-center bg-enterprise-bg p-6">
          <div className="max-w-md rounded-2xl border border-enterprise-border bg-enterprise-card p-8 text-center shadow-2xl">
            <div className="w-12 h-12 rounded-xl bg-enterprise-warning/15 flex items-center justify-center mx-auto text-enterprise-warning mb-4">
              <ShieldAlert className="h-6 w-6" />
            </div>
            <h2 className="text-base font-bold text-white">Dashboard data is temporarily unavailable</h2>
            <p className="mt-2 text-xs text-enterprise-subtext leading-relaxed">
              The security control posture summary could not be retrieved. Active snapshot state is preserved.
            </p>
            <button
              onClick={() => refetch()}
              className="mt-5 inline-flex items-center gap-2 rounded-xl bg-enterprise-accent px-5 py-2.5 text-xs font-semibold text-white hover:bg-blue-600 transition-colors shadow-lg shadow-blue-500/20"
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Retry Connection</span>
            </button>
          </div>
        </div>
      );
    }
    return (
      <div className="flex-1 flex items-center justify-center bg-enterprise-bg">
        <div className="flex flex-col items-center gap-4">
          <div className="relative flex items-center justify-center">
            <div className="w-12 h-12 rounded-full border-2 border-enterprise-accent/20 border-t-enterprise-accent animate-spin" />
            <Cloud className="w-5 h-5 text-enterprise-accent absolute" />
          </div>
          <p className="text-enterprise-subtext font-medium text-xs tracking-wide">
            Loading CloudScope Security Control Center...
          </p>
        </div>
      </div>
    );
  }

  const stats = data.stats || { users: 0, roles: 0, policies: 0, risks: 0, paths: 0, resources: 0 };
  const scoreText = String(data.securityScore ?? '').match(/-?\d+(?:\.\d+)?/);
  const parsedScore = scoreText ? Number(scoreText[0]) : Number.NaN;
  const reportScore = Number(reportsData?.summary?.score);
  const scoreNum = Number.isFinite(parsedScore) ? parsedScore : Number.isFinite(reportScore) ? reportScore : 0;
  const riskDistribution = data?.riskDistribution || [];
  const findingSummary = summarizeDashboardFindings(securityFindings);
  const dashboardRiskDistribution = securityFindings ? findingSummary.riskDistribution : riskDistribution;
  const totalRiskFindings = dashboardRiskDistribution.reduce((total, item) => total + (Number.isFinite(Number(item.value)) ? Math.max(0, Number(item.value)) : 0), 0);
  const activeFindingCount = securityFindings ? findingSummary.activeFindingCount : (totalRiskFindings || Number(stats.risks || 0));
  const consolidatedAttackPathCount = getConsolidatedAttackPathCount(attackPaths || []);
  const rawAttackPathCount = attackPaths ? attackPaths.length : Number(stats.paths || 0);

  const getScoreTheme = (score: number) => {
    if (score >= 80) return { text: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', label: 'Healthy Posture', grade: 'Grade A' };
    if (score >= 60) return { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30', label: 'Moderate Risk', grade: 'Grade B' };
    return { text: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/30', label: 'Action Required', grade: 'Grade F' };
  };

  const scoreTheme = getScoreTheme(scoreNum);

  // Statistics KPI Cards (strictly live backend numbers)
  const kpis = [
    {
      title: 'Security Posture',
      value: `${scoreNum}/100`,
      badge: scoreTheme.grade,
      subtext: scoreTheme.label,
      color: 'border-l-4 border-enterprise-accent',
      icon: ShieldCheck,
      iconColor: scoreTheme.text,
      link: '/reports'
    },
    {
      title: 'Total Cloud Assets',
      value: String(stats.resources + stats.users + stats.roles),
      badge: 'Live',
      subtext: `${stats.resources} Resources · ${stats.users + stats.roles} IAM`,
      color: 'border-l-4 border-blue-500',
      icon: Cloud,
      iconColor: 'text-blue-400',
      link: '/resources'
    },
    {
      title: 'Active Findings',
      value: String(activeFindingCount),
      badge: `${activeFindingCount > 0 ? 'Needs Action' : 'Resolved'}`,
      subtext: 'Canonical Security Findings',
      color: 'border-l-4 border-rose-500',
      icon: ShieldAlert,
      iconColor: 'text-rose-400',
      link: '/risks'
    },
    {
      title: 'Attack Paths',
      value: String(attackPaths ? consolidatedAttackPathCount : stats.paths),
      badge: `${rawAttackPathCount} raw path${rawAttackPathCount === 1 ? '' : 's'}`,
      subtext: 'Consolidated privilege vectors',
      color: 'border-l-4 border-amber-500',
      icon: GitMerge,
      iconColor: 'text-amber-400',
      link: '/attack-paths'
    },
    {
      title: 'CloudTrail Events',
      value: String(data?.activityMetrics?.observedSecurityEvents ?? (data?.recentAlerts?.length || 0)),
      badge: 'Runtime',
      subtext: 'Monitored Audit Records',
      color: 'border-l-4 border-purple-500',
      icon: Activity,
      iconColor: 'text-purple-400',
      link: '/alerts'
    },
    {
      title: 'Evaluated Policies',
      value: String(stats.policies),
      badge: 'AST Verified',
      subtext: 'IAM & Trust Documents',
      color: 'border-l-4 border-teal-500',
      icon: FileText,
      iconColor: 'text-teal-400',
      link: '/policies'
    }
  ];

  const paths = data.criticalPaths || [];
  const topRisky = data.topRiskyIdentities || [];
  const resourceBreakdown = data.resourceBreakdown || [];

  return (
    <div className="flex-1 min-h-0 p-6 space-y-6 overflow-y-auto bg-enterprise-bg select-none">
      
      {/* Executive Header & Quick Actions */}
      <div className="flex flex-col gap-4 pb-4 border-b border-enterprise-border/60">
        <div className="flex items-start gap-3 min-w-0">
            <div className="w-10 h-10 rounded-xl bg-enterprise-accent/15 border border-enterprise-accent/30 flex items-center justify-center glow-blue text-enterprise-accent">
              <Cloud className="w-5 h-5" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-xl font-bold text-white tracking-tight leading-tight">
                  CloudScope Security Control Center
                </h1>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  Live CSPM Engine
                </span>
              </div>
              <p className="text-xs text-enterprise-subtext mt-0.5">
                Unified cloud security posture management, multi-hop identity graph intelligence, and lateral attack vector defense.
              </p>
            </div>
        </div>
        
        {/* Keep scan controls and actions in a dedicated toolbar so they wrap cleanly. */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            {healthData && !snapshotId && (
              <RegionSelector
                currentMode={healthData.scan_mode || 'single'}
                currentRegion={healthData.selected_region || null}
                onRegionChanged={handleRegionChanged}
                disabled={isScanning}
              />
            )}
            <ScannedRegionBadge />
            <LastScannedBadge />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {!snapshotId && <ScanTrigger />}
            <button
              onClick={() => navigate('/reports')}
              className="px-3 py-1.5 rounded-lg bg-gray-800/80 hover:bg-gray-700/80 border border-enterprise-border text-xs font-medium text-gray-200 hover:text-white transition-all flex items-center gap-1.5 shadow-sm"
              title="View full compliance and export executive report"
            >
              <Download className="w-3.5 h-3.5 text-enterprise-accent" />
              <span>Export Report</span>
            </button>
            <button
              onClick={() => navigate('/attack-paths')}
              className="px-3 py-1.5 rounded-lg bg-enterprise-accent/15 hover:bg-enterprise-accent/25 border border-enterprise-accent/30 text-xs font-medium text-enterprise-accent transition-all flex items-center gap-1.5 shadow-sm"
              title="Explore lateral attack path graph"
            >
              <GitMerge className="w-3.5 h-3.5" />
              <span>Attack Graph</span>
            </button>
          </div>
        </div>
      </div>

      {/* Dedicated Full-Width Scan Progress & Status Banner */}
      {!snapshotId && <GlobalScanStatus />}

      {/* Initial Empty State / Running State */}
      {!snapshotId && !hasCompletedSnapshot && isScanning && stats.resources === 0 && (
        <div className="p-6 bg-blue-950/20 border border-blue-500/30 rounded-2xl flex items-center gap-4 shadow-xl">
          <Cloud className="w-6 h-6 text-blue-400 animate-pulse shrink-0" />
          <div>
            <h2 className="text-base font-bold text-white">AWS Security Discovery Scan in Progress</h2>
            <p className="text-xs text-gray-300 mt-1">Collecting asset inventory, evaluating policy ASTs, and computing lateral attack paths...</p>
          </div>
        </div>
      )}

      {/* Top Executive KPI Metric Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {kpis.map((kpi, idx) => {
          const Icon = kpi.icon;
          return (
            <motion.div
              key={kpi.title}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.04 }}
              onClick={() => navigate(kpi.link)}
              className={`bg-enterprise-card p-4 rounded-xl border border-enterprise-border flex flex-col justify-between ${kpi.color} shadow-lg hover:border-gray-700 hover:bg-gray-850/50 cursor-pointer transition-all group`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-enterprise-subtext uppercase tracking-wider">{kpi.title}</span>
                <Icon className={`w-4 h-4 ${kpi.iconColor} group-hover:scale-110 transition-transform`} />
              </div>
              <div className="my-2.5 flex items-baseline justify-between">
                <span className="text-2xl font-black text-white font-mono tracking-tight">{kpi.value}</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-300 font-semibold border border-gray-700/50">
                  {kpi.badge}
                </span>
              </div>
              <div className="flex items-center justify-between text-[10px] text-gray-400 pt-1 border-t border-enterprise-border/50">
                <span className="truncate">{kpi.subtext}</span>
                <ChevronRight className="w-3 h-3 text-gray-500 opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Visual Analytics Grid: Severity Distribution, Inventory, High-Risk Identities */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Risk Distribution Donut Chart */}
        <div className="bg-enterprise-card p-5 rounded-2xl border border-enterprise-border shadow-xl flex flex-col">
          <div className="flex justify-between items-center mb-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <span>Finding Severity Breakdown</span>
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-mono font-bold">
              Total: {totalRiskFindings}
            </span>
          </div>

          <div className="h-60 w-full relative flex items-center justify-center">
            {totalRiskFindings === 0 ? (
              <div className="flex h-full flex-col items-center justify-center gap-2 text-center">
                <CheckCircle2 className="h-8 w-8 text-emerald-400" />
                <p className="text-xs font-semibold text-gray-200">Zero Open Vulnerabilities</p>
                <p className="text-[10px] text-enterprise-subtext">No open findings detected across monitored cloud assets.</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={dashboardRiskDistribution.filter((entry) => Number.isFinite(entry.value) && entry.value > 0)}
                    cx="50%"
                    cy="45%"
                    innerRadius={54}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                    nameKey="name"
                  >
                    {dashboardRiskDistribution.filter((entry) => Number.isFinite(entry.value) && entry.value > 0).map((entry) => (
                      <Cell key={`severity-${entry.name}`} fill={entry.color} stroke="#0B1220" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip
                    formatter={(value, name) => {
                      const count = Number(value ?? 0);
                      const pct = totalRiskFindings > 0 ? Math.round((count / totalRiskFindings) * 100) : 0;
                      return [`${count} finding${count === 1 ? '' : 's'} (${pct}%)`, String(name)];
                    }}
                    contentStyle={{ backgroundColor: '#111827', borderColor: '#1F2937', borderRadius: '10px', fontSize: '11px', color: '#F8FAFC' }}
                    itemStyle={{ color: '#F8FAFC' }}
                  />
                  <Legend
                    verticalAlign="bottom"
                    height={36}
                    iconType="circle"
                    iconSize={8}
                    formatter={(val: string) => <span className="text-xs text-gray-300 ml-1 font-medium">{val}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Cloud Resource Inventory Breakdown */}
        <div className="bg-enterprise-card p-5 rounded-2xl border border-enterprise-border shadow-xl flex flex-col">
          <div className="flex justify-between items-center mb-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Server className="w-4 h-4 text-enterprise-accent" />
              <span>Discovered Cloud Assets</span>
            </h3>
            <button
              onClick={() => navigate('/resources')}
              className="text-xs text-enterprise-accent hover:underline font-semibold"
            >
              All Assets →
            </button>
          </div>

          <div className="space-y-2 flex-1 overflow-y-auto max-h-60 pr-1">
            {resourceBreakdown.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-gray-500">
                No resources recorded. Trigger a scan to discover cloud inventory.
              </div>
            ) : (
              resourceBreakdown.map((res: any) => (
                <div
                  key={res.type}
                  onClick={() => navigate('/resources')}
                  className="flex justify-between items-center p-2.5 rounded-xl bg-enterprise-bg/60 border border-enterprise-border/80 hover:border-gray-700 cursor-pointer text-xs transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <Database className="w-3.5 h-3.5 text-enterprise-accent/70" />
                    <span className="text-gray-200 font-medium">{res.type}</span>
                  </div>
                  <span className="font-mono font-bold text-white bg-gray-800 px-2.5 py-0.5 rounded-lg border border-gray-700/60">
                    {res.count}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Highest Risk IAM Identities */}
        <div className="bg-enterprise-card p-5 rounded-2xl border border-enterprise-border shadow-xl flex flex-col">
          <div className="flex justify-between items-center mb-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Key className="w-4 h-4 text-purple-400" />
              <span>High-Risk IAM Identities</span>
            </h3>
          </div>

          <div className="space-y-2 flex-1 overflow-y-auto max-h-60 pr-1">
            {topRisky.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-gray-500">
                No elevated risk identities detected in current inventory.
              </div>
            ) : (
              topRisky.slice(0, 5).map((id: any) => (
                <div
                  key={id.name}
                  onClick={() => setSelectedNode({ id: id.name, label: id.name, type: id.type, riskScore: id.riskScore, arn: id.arn })}
                  className="flex justify-between items-center p-2.5 rounded-xl bg-enterprise-bg/60 border border-enterprise-border/80 hover:border-purple-500/40 cursor-pointer text-xs transition-all group"
                  title="Click to view full blast radius & attached permissions"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className={`w-2 h-2 rounded-full shrink-0 ${id.riskScore >= 80 ? 'bg-rose-500 shadow-sm shadow-rose-500' : 'bg-amber-500'}`} />
                    <span className="font-mono text-gray-200 font-semibold truncate group-hover:text-purple-300 transition-colors">
                      {id.name}
                    </span>
                    <span className="text-[9px] text-gray-400 uppercase font-semibold px-1.5 py-0.2 bg-gray-800/80 rounded">
                      {id.type}
                    </span>
                  </div>
                  <span className={`font-mono font-bold px-2 py-0.5 rounded-md text-[10px] shrink-0 ${
                    id.riskScore >= 80 ? 'text-rose-300 bg-rose-950/60 border border-rose-500/40' : 'text-amber-300 bg-amber-950/60 border border-amber-500/40'
                  }`}>
                    Risk {id.riskScore}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

      </div>

      {/* Critical Lateral Vectors & Actionable Remediation Guidance */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Critical Lateral Attack Vectors */}
        <div className="bg-enterprise-card p-5 rounded-2xl border border-enterprise-border shadow-xl">
          <div className="flex justify-between items-center mb-4">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <GitMerge className="w-4 h-4 text-orange-400" />
                <span>Active Lateral Attack Vectors</span>
              </h3>
              <p className="text-xs text-enterprise-subtext mt-0.5">
                Multi-hop privilege escalation paths computed across the cloud identity graph.
              </p>
            </div>
            <button
              onClick={() => navigate('/attack-paths')}
              className="text-xs text-enterprise-accent hover:underline font-semibold flex items-center gap-1"
            >
              <span>View All Vectors ({paths.length})</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {paths.length === 0 ? (
              <div className="p-6 text-center text-xs text-gray-400 bg-enterprise-bg/40 rounded-xl border border-enterprise-border/60">
                <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-2" />
                <span>No lateral attack paths identified in the evaluated snapshot.</span>
              </div>
            ) : (
              paths.slice(0, 3).map((p: any) => (
                <div
                  key={p.id}
                  onClick={() => navigate('/attack-paths')}
                  className="p-3.5 bg-enterprise-bg/60 border border-enterprise-border/80 hover:border-orange-500/50 rounded-xl cursor-pointer transition-all space-y-2 group shadow-sm"
                >
                  <div className="flex justify-between items-center gap-2">
                    <span className="text-xs font-bold text-white font-mono group-hover:text-orange-300 transition-colors truncate">
                      {p.name}
                    </span>
                    <span className="text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-rose-950/70 text-rose-300 border border-rose-500/40 shrink-0">
                      {p.severity || 'Critical'}
                    </span>
                  </div>
                  <p className="text-[11px] text-gray-400 leading-relaxed line-clamp-2">
                    {p.description}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Actionable Remediation Guidance */}
        <div className="bg-enterprise-card p-5 rounded-2xl border border-enterprise-border shadow-xl">
          <div className="flex justify-between items-center mb-4">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-emerald-400" />
                <span>Actionable Remediation Guidance</span>
              </h3>
              <p className="text-xs text-enterprise-subtext mt-0.5">
                Prioritized mitigation playbooks to resolve critical risk factors immediately.
              </p>
            </div>
            <button
              onClick={() => navigate('/risks')}
              className="text-xs text-emerald-400 hover:underline font-semibold flex items-center gap-1"
            >
              <span>All Findings</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {(data.recommendations || []).slice(0, 3).map((rec: any, index: number) => (
              <div
                key={index}
                className="p-3.5 bg-enterprise-bg/60 border border-enterprise-border/80 rounded-xl space-y-1.5 hover:border-emerald-500/40 transition-colors shadow-sm"
              >
                <div className="flex items-center justify-between gap-2">
                  <p className="text-xs font-bold text-gray-200">{rec.title}</p>
                  <span className="text-[9px] font-semibold uppercase px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 shrink-0">
                    Priority Playbook
                  </span>
                </div>
                <p className="text-[11px] text-enterprise-subtext leading-relaxed">
                  {rec.desc}
                </p>
              </div>
            ))}
          </div>
        </div>

      </div>

      {/* Node Details Slide-Out Drawer */}
      {selectedNode && (
        <NodeDetailsPanel
          nodeData={selectedNode}
          onClose={() => setSelectedNode(null)}
        />
      )}

    </div>
  );
};
