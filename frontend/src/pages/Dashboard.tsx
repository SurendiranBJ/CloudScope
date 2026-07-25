import { useState } from 'react';
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
  ArrowRight,
  Sparkles
} from 'lucide-react';
import { IdentityGraph } from '../components/IdentityGraph';
import { NodeDetailsPanel } from '../components/NodeDetailsPanel';
import { useQuery } from '@tanstack/react-query';
import { getDashboardSummary } from '../api/dashboard';
import { mockAlerts } from '../data/alerts';
import { mockAttackPaths } from '../data/attackPaths';
import type { SecurityAlert, AttackPath } from '../types';

export const Dashboard: React.FC = () => {
  const [selectedNode, setSelectedNode] = useState<any>(null);

  const { data } = useQuery({
    queryKey: ['dashboardSummary'],
    queryFn: getDashboardSummary,
    refetchInterval: 10000 // keep stats synchronized
  });

  const stats = data?.stats || {
    users: 32,
    roles: 18,
    policies: 47,
    risks: 5,
    paths: 11,
    resources: 126
  };

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

  const alerts = data?.recentAlerts || mockAlerts;
  const paths = data?.criticalPaths || mockAttackPaths;
  const recommendations = data?.recommendations || [
    { title: 'Enforce MFA Scope', desc: 'Enabling MFA on developer-session blocks downstream privilege assumptions.' },
    { title: 'Upgrade IMDSv2', desc: 'Restrict EC2 app server metadata queries to IMDSv2 tokens.' }
  ];

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
          <div className="text-xs text-enterprise-subtext flex items-center gap-2 bg-enterprise-card border border-enterprise-border px-3 py-1.5 rounded-lg">
            <span className="w-2 h-2 rounded-full bg-enterprise-success animate-ping" />
            <span>AWS Scan: {data?.lastScan ? `${new Date(data.lastScan.timestamp).toLocaleTimeString()}` : 'Live'}</span>
          </div>
        </div>

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

        {/* Interactive Graph Section */}
        <div className="h-[450px] bg-enterprise-card border border-enterprise-border rounded-xl overflow-hidden flex flex-col">
          <div className="border-b border-enterprise-border px-5 py-3.5 flex justify-between items-center bg-enterprise-card/50">
            <div className="flex items-center gap-2">
              <Cloud className="w-4 h-4 text-enterprise-accent" />
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">AWS Active Identity Scope</h2>
            </div>
            <span className="text-[10px] text-enterprise-subtext font-medium">
              Interact with nodes to inspect trust paths and configurations
            </span>
          </div>
          <div className="flex-1 relative">
            <IdentityGraph onNodeSelect={(node: any) => setSelectedNode(node)} />
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
              <span className="text-xs text-enterprise-accent hover:underline cursor-pointer">
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
                  <button className="flex items-center gap-1.5 px-3 py-1.5 bg-enterprise-accent/15 hover:bg-enterprise-accent/25 text-enterprise-accent font-semibold rounded-lg text-xs transition-colors shrink-0">
                    <span>Audit Vector</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
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
