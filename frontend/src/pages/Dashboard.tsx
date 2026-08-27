import { useState, useEffect, useCallback, useRef } from 'react';
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
  ShieldCheck,
  Bot,
  Sparkles
} from 'lucide-react';
import { NodeDetailsPanel } from '../components/NodeDetailsPanel';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getDashboardSummary } from '../api/dashboard';
import { rebuildGraph, getScanStatus } from '../api/graph';
import type { SecurityAlert, AttackPath } from '../types';

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [isScanning, setIsScanning] = useState(false);
  const [scanSuccess, setScanSuccess] = useState(false);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['dashboardSummary'],
    queryFn: getDashboardSummary,
    refetchInterval: 5000
  });

  // On first mount, check if a scan is already running (e.g. auto-scan or startup scan)
  useEffect(() => {
    getScanStatus().then((status) => {
      if (status.is_scanning) {
        setIsScanning(true);
        startPolling();
      }
    }).catch(() => {});
    return () => stopPolling();
  }, []);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const startPolling = useCallback(() => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      try {
        const status = await getScanStatus();
        if (!status.is_scanning) {
          // Scan finished!
          stopPolling();
          setIsScanning(false);
          setScanSuccess(true);
          // Refresh all dashboard data
          queryClient.invalidateQueries({ queryKey: ['dashboardSummary'] });
          queryClient.invalidateQueries({ queryKey: ['graphElements'] });
          queryClient.invalidateQueries({ queryKey: ['cloudResources'] });
          setTimeout(() => setScanSuccess(false), 4000);
        }
      } catch {
        // Ignore network blips during polling
      }
    }, 2000); // Poll every 2 seconds
  }, [queryClient, stopPolling]);

  const handleScanClick = useCallback(async () => {
    if (isScanning) return;
    setIsScanning(true);
    setScanSuccess(false);
    try {
      await rebuildGraph(); // Returns immediately (async on backend)
      startPolling(); // Start polling for completion
    } catch (err) {
      console.error('Failed to trigger scan:', err);
      setIsScanning(false);
    }
  }, [isScanning, startPolling]);

  // Show loading spinner when initial data is loading OR a scan is in progress
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

  const stats = data.stats;

  // Statistics KPI Cards configurations
  const kpis = [
    {
      title: 'Security Score',
      value: data?.securityScore || '84 / 100',
      status: 'Good',
      trend: '↑ +6% this month',
      color: 'border-l-4 border-enterprise-success',
      icon: ShieldCheck,
      iconColor: 'text-enterprise-success'
    },
    {
      title: 'IAM Users',
      value: String(stats.users),
      status: '2 Inactive',
      trend: '↑ +1 today',
      color: 'border-l-4 border-enterprise-accent',
      icon: Users,
      iconColor: 'text-enterprise-accent'
    },
    {
      title: 'IAM Roles',
      value: String(stats.roles),
      status: '6 Over-privileged',
      trend: '→ Stable',
      color: 'border-l-4 border-purple-500',
      icon: Key,
      iconColor: 'text-purple-500'
    },
    {
      title: 'Policies',
      value: String(stats.policies),
      status: '12 Custom',
      trend: '↑ +3 new policies',
      color: 'border-l-4 border-teal-500',
      icon: FileText,
      iconColor: 'text-teal-500'
    },
    {
      title: 'Critical Risks',
      value: String(stats.risks),
      status: 'Immediate action',
      trend: '↓ -2 resolved',
      color: 'border-l-4 border-enterprise-critical',
      icon: ShieldAlert,
      iconColor: 'text-enterprise-critical'
    },
    {
      title: 'Attack Paths',
      value: String(stats.paths),
      status: '3 Active vectors',
      trend: '↑ +1 simulated',
      color: 'border-l-4 border-orange-500',
      icon: GitMerge,
      iconColor: 'text-orange-500'
    }
  ];

  // Recharts Pie Chart configuration
  const riskDistribution = data?.riskDistribution || [
    { name: 'Critical', value: 5, color: '#EF4444' },
    { name: 'High', value: 12, color: '#F59E0B' },
    { name: 'Medium', value: 18, color: '#3B82F6' },
    { name: 'Low', value: 25, color: '#10B981' }
  ];

  const alerts = data.recentAlerts || [];
  const paths = data.criticalPaths || [];
  const recommendations = data.recommendations || [];

  return (
    <div className="flex-1 flex overflow-hidden bg-enterprise-bg">
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Welcome Banner */}
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Security Posture Dashboard</h1>
            <p className="text-xs text-enterprise-subtext mt-1">
              Live identity-centric attack path mappings and permissions configurations.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <div className="text-xs text-enterprise-subtext flex items-center gap-2 bg-enterprise-card border border-enterprise-border px-3 py-1.5 rounded-lg">
              <span className={`w-2 h-2 rounded-full ${isScanning ? 'bg-blue-500 animate-pulse' : 'bg-enterprise-success animate-ping'}`} />
              <span>
                {isScanning
                  ? 'Scanning AWS...'
                  : data?.lastScan
                    ? `Last scan: ${new Date(data.lastScan.timestamp).toLocaleTimeString()}`
                    : 'Live'}
              </span>
            </div>
            <button
              disabled={isScanning}
              onClick={handleScanClick}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                scanSuccess
                  ? 'bg-enterprise-success/20 text-enterprise-success border border-enterprise-success/30'
                  : isScanning
                    ? 'bg-blue-600/10 text-blue-400/50 border border-blue-500/10 cursor-not-allowed'
                    : 'bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 border border-blue-500/30'
              }`}
            >
              {scanSuccess ? (
                <ShieldCheck className="w-3.5 h-3.5" />
              ) : (
                <svg className={isScanning ? "animate-spin" : ""} xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 21v-5h5"/></svg>
              )}
              {scanSuccess ? 'Scan Complete!' : isScanning ? 'Scanning AWS...' : 'Scan Again'}
            </button>
          </div>
        </div>

        {/* Scanning overlay banner */}
        {isScanning && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4 flex items-center gap-3"
          >
            <svg className="animate-spin w-5 h-5 text-blue-400 shrink-0" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
            <div>
              <p className="text-sm font-bold text-blue-300">Scanning your AWS environment...</p>
              <p className="text-xs text-blue-400/70 mt-0.5">Collecting IAM, EC2, S3, Lambda, RDS, DynamoDB, Secrets, and CloudTrail data across all regions. The dashboard will refresh automatically when complete.</p>
            </div>
          </motion.div>
        )}

        {/* KPI Cards Row */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
          {kpis.map((kpi, idx) => {
            const Icon = kpi.icon;
            return (
              <motion.div
                key={kpi.title}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: idx * 0.05 }}
                className={`bg-enterprise-card p-4 rounded-xl border border-enterprise-border hover:border-gray-800 transition-colors flex flex-col justify-between h-28 cursor-pointer ${kpi.color}`}
              >
                <div className="flex justify-between items-start">
                  <span className="text-[10px] font-bold text-enterprise-subtext uppercase tracking-wider">
                    {kpi.title}
                  </span>
                  <Icon className={`w-4 h-4 ${kpi.iconColor}`} />
                </div>
                <div className="mt-2">
                  <h3 className="text-xl font-bold text-white tracking-tight">{kpi.value}</h3>
                  <div className="flex justify-between items-center mt-1">
                    <span className="text-[9px] font-semibold text-gray-400">{kpi.status}</span>
                    <span className="text-[9px] font-bold text-enterprise-accent">{kpi.trend}</span>
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>

        {/* Real-time Insights Section: Top Risky Identities & Resource Breakdown */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Panel 1: Top Risky Identities */}
          <div className="h-[450px] bg-enterprise-card border border-enterprise-border rounded-xl p-5 flex flex-col justify-between">
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Users className="w-4 h-4 text-enterprise-accent" />
                <span>Top Risky Identities</span>
              </h2>
              <p className="text-[11px] text-enterprise-subtext mb-4">
                Identities with the highest vulnerability levels, calculated from IAM mappings and wildcard permissions.
              </p>
            </div>

            {(!data.topRiskyIdentities || data.topRiskyIdentities.length === 0) ? (
              <div className="flex-1 flex flex-col items-center justify-center text-enterprise-subtext italic text-xs">
                <Users className="w-8 h-8 mb-2 text-gray-600 animate-pulse" />
                <span>Scanning AWS environment...</span>
              </div>
            ) : (
              <div className="flex-1 space-y-2 overflow-y-auto pr-1.5 max-h-[300px]">
                {data.topRiskyIdentities.map((identity: any, i: number) => {
                  const getRiskColor = (score: number) => {
                    if (score >= 80) return 'text-enterprise-critical bg-enterprise-critical/15 border border-enterprise-critical/30';
                    if (score >= 60) return 'text-enterprise-warning bg-enterprise-warning/15 border border-enterprise-warning/30';
                    if (score >= 40) return 'text-enterprise-accent bg-enterprise-accent/15 border border-enterprise-accent/30';
                    return 'text-enterprise-success bg-enterprise-success/15 border border-enterprise-success/30';
                  };
                  return (
                    <div
                      key={i}
                      onClick={() => navigate('/risks')}
                      className="p-3 bg-enterprise-bg/40 border border-enterprise-border rounded-lg flex items-center justify-between hover:border-enterprise-accent hover:bg-enterprise-accent/5 transition-all duration-150 cursor-pointer"
                    >
                      <div className="flex items-center gap-3">
                        <div className="text-xs font-bold text-white max-w-[200px] truncate">{identity.name}</div>
                        <span className={`text-[9px] px-2 py-0.5 rounded font-semibold ${
                          identity.type === 'User' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' : 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                        }`}>
                          {identity.type}
                        </span>
                      </div>
                      <span className={`text-xs font-black px-2 py-0.5 rounded ${getRiskColor(identity.riskScore)}`}>
                        {identity.riskScore}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Panel 2: Resource Inventory Breakdown */}
          <div className="h-[450px] bg-enterprise-card border border-enterprise-border rounded-xl p-5 flex flex-col justify-between">
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Cloud className="w-4 h-4 text-enterprise-accent" />
                <span>Resource Inventory Breakdown</span>
              </h2>
              <p className="text-[11px] text-enterprise-subtext mb-4">
                Total monitored resources across storage, database, compute, and credentials services.
              </p>
            </div>

            {(() => {
              const resourceColors: Record<string, string> = {
                S3: '#F59E0B',      // Amber
                EC2: '#10B981',     // Green
                Lambda: '#EC4899',  // Pink
                RDS: '#0EA5E9',     // Sky Blue
                DynamoDB: '#8B5CF6',// Purple
                Secrets: '#EF4444'  // Red
              };
              const chartData = (data.resourceBreakdown || []).map((item: any) => ({
                name: item.type,
                value: item.count,
                color: resourceColors[item.type] || '#3B82F6'
              }));
              const hasData = chartData.length > 0 && chartData.some((c: any) => c.value > 0);

              if (!hasData) {
                return (
                  <div className="flex-1 flex flex-col items-center justify-center text-enterprise-subtext italic text-xs">
                    <Cloud className="w-8 h-8 mb-2 text-gray-600 animate-pulse" />
                    <span>Calculating resource inventory breakdown...</span>
                  </div>
                );
              }

              return (
                <div className="flex-1 h-64 w-full flex items-center justify-center">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={chartData}
                        cx="40%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={80}
                        paddingAngle={3}
                        dataKey="value"
                      >
                        {chartData.map((entry: any, index: number) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#111827',
                          borderColor: '#1F2937',
                          color: '#FFF',
                          fontSize: '11px'
                        }}
                      />
                      <Legend
                        layout="vertical"
                        align="right"
                        verticalAlign="middle"
                        iconSize={10}
                        iconType="circle"
                        formatter={(value) => <span className="text-xs text-gray-300 font-medium">{value}</span>}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              );
            })()}
          </div>
        </div>

        {/* Analytics & Logs Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Risk Pie Chart */}
          <div className="bg-enterprise-card border border-enterprise-border p-5 rounded-xl flex flex-col justify-between min-h-[300px]">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-enterprise-critical" />
              <span>Risk Severity Distribution</span>
            </h2>
            <div className="h-44 w-full flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={riskDistribution}
                    cx="40%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {riskDistribution.map((entry: any, index: number) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#111827',
                      borderColor: '#1F2937',
                      color: '#FFF',
                      fontSize: '11px'
                    }}
                  />
                  <Legend
                    layout="vertical"
                    align="right"
                    verticalAlign="middle"
                    iconSize={10}
                    iconType="circle"
                    formatter={(value) => <span className="text-xs text-gray-300 font-medium">{value}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Recent Alerts Scroll */}
          <div className="bg-enterprise-card border border-enterprise-border p-5 rounded-xl flex flex-col justify-between min-h-[300px]">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-enterprise-warning" />
                <span>Recent Threat Alerts</span>
              </div>
              <span
                onClick={() => navigate('/alerts')}
                className="text-xs text-enterprise-accent hover:underline cursor-pointer"
              >
                View All Alerts
              </span>
            </h2>
            <div className="space-y-3.5 grow overflow-y-auto max-h-60 pr-1.5">
              {alerts.slice(0, 3).map((alert: SecurityAlert) => (
                <div
                  key={alert.id}
                  className="p-3 bg-enterprise-bg/40 border border-enterprise-border rounded-lg flex items-start gap-3 hover:border-gray-800 transition-colors"
                >
                  <div
                    className={`w-2.5 h-2.5 rounded-full mt-1 shrink-0 ${
                      alert.severity === 'critical' ? 'bg-enterprise-critical animate-pulse' : 'bg-enterprise-warning'
                    }`}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex justify-between items-start gap-2">
                      <h4 className="text-xs font-bold text-white truncate">{alert.description}</h4>
                      <span className="text-[9px] text-enterprise-subtext shrink-0">
                        {alert.timestamp.split('T')[0]}
                      </span>
                    </div>
                    <p className="text-[10px] text-enterprise-subtext mt-1">Resource: {alert.resource}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Attack Paths & AI Recommendations */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Critical Attack Paths list */}
          <div className="bg-enterprise-card border border-enterprise-border p-5 rounded-xl lg:col-span-2 space-y-4">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
              <GitMerge className="w-4 h-4 text-enterprise-accent" />
              <span>Critical Attack Paths Mapped</span>
            </h2>
            <div className="space-y-3.5">
              {paths.slice(0, 2).map((path: AttackPath) => (
                <div
                  key={path.id}
                  className="p-4 bg-enterprise-bg/60 border border-enterprise-border rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-enterprise-critical/20 text-enterprise-critical capitalize">
                        {path.severity}
                      </span>
                      <h4 className="text-xs font-bold text-white">{path.name}</h4>
                    </div>
                    <p className="text-[10px] text-enterprise-subtext">{path.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* AI Security Recommendations */}
          <div className="bg-enterprise-card border border-enterprise-border p-5 rounded-xl space-y-4">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
              <Sparkles className="w-4 h-4 text-enterprise-accent" />
              <span>AI Recommendations</span>
            </h2>
            <div className="space-y-3 text-xs leading-relaxed text-enterprise-subtext">
              {recommendations.map((rec: any, i: number) => (
                <div key={i} className="bg-enterprise-accent/5 p-3 rounded-lg border border-enterprise-accent/10">
                  <h4 className="font-bold text-white text-xs flex items-center gap-1.5">
                    <Bot className="w-4 h-4 text-enterprise-accent" /> {rec.title}
                  </h4>
                  <p className="mt-1.5 text-[10px]">
                    {rec.desc}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Slide-out details drawer */}
      {selectedNode && (
        <NodeDetailsPanel nodeData={selectedNode} onClose={() => setSelectedNode(null)} />
      )}
    </div>
  );
};
