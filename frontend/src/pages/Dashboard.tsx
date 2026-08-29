import { useState, useEffect } from 'react';
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
  Users,
  ShieldAlert,
  GitMerge,
  Cloud,
  FileText,
  Key,
  ShieldCheck
} from 'lucide-react';
import { NodeDetailsPanel } from '../components/NodeDetailsPanel';
import { RegionSelector } from '../components/RegionSelector';
import { useQuery } from '@tanstack/react-query';
import { getDashboardSummary } from '../api/dashboard';
import { ScanTrigger, useScanTrigger } from '../components/ScanTrigger';
import { ScannedRegionBadge } from '../components/ScannedRegionBadge';
import { apiClient } from '../api/client';

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const { handleScanClick } = useScanTrigger();

  // Health data for the active region / scan mode (used to seed the RegionSelector)
  const [healthData, setHealthData] = useState<{
    scan_mode?: string;
    selected_region?: string | null;
    scan_regions?: string[];
  } | null>(null);

  useEffect(() => {
    apiClient.get('/health')
      .then(res => {
        if (res.data?.success) setHealthData(res.data.data);
      })
      .catch(() => {});
  }, []);

  const { data, isLoading } = useQuery({
    queryKey: ['dashboardSummary'],
    queryFn: getDashboardSummary,
    refetchInterval: 5000
  });

  if (isLoading || !data) {
    return (
      <div className="flex-1 flex items-center justify-center bg-enterprise-bg">
        <div className="flex flex-col items-center gap-4">
          <svg className="animate-spin w-8 h-8 text-blue-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
          <p className="text-enterprise-subtext font-medium text-sm">Loading Dashboard...</p>
        </div>
      </div>
    );
  }

  const stats = data.stats || { users: 0, roles: 0, policies: 0, risks: 0, paths: 0, resources: 0 };

  // Statistics KPI Cards (strictly live backend numbers, no fabricated trends)
  const kpis = [
    {
      title: 'Security Score',
      value: data?.securityScore || 'N/A',
      status: 'Verified Posture',
      color: 'border-l-4 border-enterprise-success',
      icon: ShieldCheck,
      iconColor: 'text-enterprise-success'
    },
    {
      title: 'IAM Users',
      value: String(stats.users),
      status: 'Live Inventory',
      color: 'border-l-4 border-enterprise-accent',
      icon: Users,
      iconColor: 'text-enterprise-accent'
    },
    {
      title: 'IAM Roles',
      value: String(stats.roles),
      status: 'Assumable & Service',
      color: 'border-l-4 border-purple-500',
      icon: Key,
      iconColor: 'text-purple-500'
    },
    {
      title: 'Policies',
      value: String(stats.policies),
      status: 'Evaluated AST Documents',
      color: 'border-l-4 border-teal-500',
      icon: FileText,
      iconColor: 'text-teal-500'
    },
    {
      title: 'Findings & Risks',
      value: String(stats.risks),
      status: 'Active Findings',
      color: 'border-l-4 border-enterprise-critical',
      icon: ShieldAlert,
      iconColor: 'text-enterprise-critical'
    },
    {
      title: 'Attack Paths',
      value: String(stats.paths),
      status: 'Lateral Movement Trees',
      color: 'border-l-4 border-orange-500',
      icon: GitMerge,
      iconColor: 'text-orange-500'
    }
  ];

  const riskDistribution = data?.riskDistribution || [
    { name: 'Critical', value: 0, color: '#EF4444' },
    { name: 'High', value: 0, color: '#F59E0B' },
    { name: 'Medium', value: 0, color: '#3B82F6' },
    { name: 'Low', value: 0, color: '#10B981' }
  ];

  const paths = data.criticalPaths || [];
  const topRisky = data.topRiskyIdentities || [];
  const resourceBreakdown = data.resourceBreakdown || [];

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto bg-enterprise-bg select-none">
      
      {/* Header */}
      <div className="flex justify-between items-center flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Cloud className="w-6 h-6 text-enterprise-accent" />
            <span>AWS Security Control Center</span>
          </h1>
          <p className="text-xs text-enterprise-subtext mt-1">
            Near-real-time CloudTrail security monitoring, IAM identity graph, and lateral attack vector intelligence.
          </p>
        </div>
        
        {/* Region Selector & Scan Controls */}
        <div className="flex items-center gap-3 flex-wrap">
          {healthData && (
            <RegionSelector
              currentMode={healthData.scan_mode || 'single'}
              currentRegion={healthData.selected_region || null}
              onRegionChanged={handleScanClick}
            />
          )}
          <ScannedRegionBadge />
          <ScanTrigger />
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {kpis.map((kpi, idx) => {
          const Icon = kpi.icon;
          return (
            <motion.div
              key={kpi.title}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.05 }}
              className={`bg-enterprise-card p-4 rounded-xl border border-enterprise-border flex flex-col justify-between ${kpi.color} shadow-lg hover:border-gray-700 transition-all`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-enterprise-subtext uppercase tracking-wider">{kpi.title}</span>
                <Icon className={`w-4 h-4 ${kpi.iconColor}`} />
              </div>
              <div className="my-2">
                <span className="text-2xl font-black text-white font-mono">{kpi.value}</span>
              </div>
              <div className="flex items-center justify-between text-[10px] text-gray-400">
                <span>{kpi.status}</span>
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Main Charts & Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Risk Distribution Donut Chart */}
        <div className="bg-enterprise-card p-5 rounded-xl border border-enterprise-border shadow-lg flex flex-col">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-enterprise-critical" />
              <span>Risk Finding Severity</span>
            </h3>
            <span className="text-[10px] text-enterprise-subtext font-mono">
              Total: {riskDistribution.reduce((a, b) => a + (b.value || 0), 0)}
            </span>
          </div>

          <div className="h-56 w-full relative flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {riskDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="#0F172A" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#1E293B', borderColor: '#334155', borderRadius: '8px', fontSize: '11px', color: '#F8FAFC' }}
                  itemStyle={{ color: '#F8FAFC' }}
                />
                <Legend
                  verticalAlign="bottom"
                  height={36}
                  iconType="circle"
                  iconSize={8}
                  formatter={(val: string) => <span className="text-xs text-gray-300 ml-1">{val}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Resource Breakdown Table */}
        <div className="bg-enterprise-card p-5 rounded-xl border border-enterprise-border shadow-lg flex flex-col">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2 mb-4">
            <Cloud className="w-4 h-4 text-enterprise-accent" />
            <span>Discovered Cloud Inventory</span>
          </h3>

          <div className="space-y-2 flex-1 overflow-y-auto max-h-56 pr-1">
            {resourceBreakdown.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-gray-500">
                No resources recorded. Trigger a scan to discover assets.
              </div>
            ) : (
              resourceBreakdown.map((res: any) => (
                <div key={res.type} className="flex justify-between items-center p-2 rounded-lg bg-gray-900/50 border border-gray-800 text-xs">
                  <span className="text-gray-300 font-medium">{res.type}</span>
                  <span className="font-mono font-bold text-white bg-gray-800 px-2 py-0.5 rounded">{res.count}</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Top Risky IAM Identities */}
        <div className="bg-enterprise-card p-5 rounded-xl border border-enterprise-border shadow-lg flex flex-col">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2 mb-4">
            <Key className="w-4 h-4 text-purple-400" />
            <span>Highest Risk Identities</span>
          </h3>

          <div className="space-y-2 flex-1 overflow-y-auto max-h-56 pr-1">
            {topRisky.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-gray-500">
                No elevated risk identities detected.
              </div>
            ) : (
              topRisky.map((id: any) => (
                <div
                  key={id.name}
                  onClick={() => setSelectedNode({ id: id.name, label: id.name, type: id.type, riskScore: id.riskScore, arn: id.arn })}
                  className="flex justify-between items-center p-2 rounded-lg bg-gray-900/50 border border-gray-800 hover:border-gray-700 cursor-pointer text-xs transition-colors"
                >
                  <div className="flex items-center gap-2 truncate">
                    <span className={`w-2 h-2 rounded-full ${id.riskScore >= 80 ? 'bg-red-500' : 'bg-amber-500'}`} />
                    <span className="font-mono text-gray-200 font-medium truncate">{id.name}</span>
                    <span className="text-[9px] text-gray-500 uppercase font-semibold">{id.type}</span>
                  </div>
                  <span className="font-mono font-bold text-red-400 bg-red-950/40 border border-red-500/30 px-2 py-0.5 rounded text-[10px]">
                    Risk {id.riskScore}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

      </div>

      {/* Critical Attack Paths & Recommendations Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Critical Lateral Vectors */}
        <div className="bg-enterprise-card p-5 rounded-xl border border-enterprise-border shadow-lg">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <GitMerge className="w-4 h-4 text-orange-400" />
              <span>Active Lateral Attack Vectors</span>
            </h3>
            <button
              onClick={() => navigate('/attack-paths')}
              className="text-xs text-enterprise-accent hover:underline font-medium"
            >
              View All Trees →
            </button>
          </div>

          <div className="space-y-3">
            {paths.length === 0 ? (
              <p className="text-xs text-gray-500 py-4 text-center">No multi-hop lateral attack paths discovered.</p>
            ) : (
              paths.slice(0, 3).map((p: any) => (
                <div
                  key={p.id}
                  onClick={() => navigate('/attack-paths')}
                  className="p-3 bg-gray-900/60 border border-gray-800 hover:border-orange-500/50 rounded-xl cursor-pointer transition-all space-y-1.5"
                >
                  <div className="flex justify-between items-center">
                    <span className="text-xs font-bold text-white font-mono">{p.name}</span>
                    <span className="text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-red-950/60 text-red-400 border border-red-500/40">
                      {p.severity}
                    </span>
                  </div>
                  <p className="text-[11px] text-gray-400 leading-relaxed">{p.description}</p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Security Recommendations */}
        <div className="bg-enterprise-card p-5 rounded-xl border border-enterprise-border shadow-lg">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2 mb-4">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Actionable Remediation Guidance</span>
          </h3>

          <div className="space-y-3">
            {(data.recommendations || []).slice(0, 3).map((rec: any, index: number) => (
              <div key={index} className="p-3 bg-gray-900/60 border border-gray-800 rounded-xl space-y-1">
                <p className="text-xs font-bold text-gray-200">{rec.title}</p>
                <p className="text-[11px] text-enterprise-subtext leading-relaxed">{rec.desc}</p>
              </div>
            ))}
          </div>
        </div>

      </div>

      {/* Node Details Flyout Modal */}
      {selectedNode && (
        <NodeDetailsPanel
          nodeData={selectedNode}
          onClose={() => setSelectedNode(null)}
        />
      )}

    </div>
  );
};
