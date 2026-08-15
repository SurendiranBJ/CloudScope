import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Play,
  RotateCcw,
  Zap,
  ArrowRight,
  Bot,
  Terminal,
  User,
  Key,
  Database,
  RefreshCw,
  Sparkles
} from 'lucide-react';

export const AttackSimulation: React.FC = () => {
  const [startIdentity, setStartIdentity] = useState('usr-002');
  const [escalationStep, setEscalationStep] = useState('sts:AssumeRole');
  const [targetResource, setTargetResource] = useState('res-002');
  const [isRunning, setIsRunning] = useState(false);
  const [showResult, setShowResult] = useState(false);

  const startOptions = [
    { id: 'usr-002', name: 'developer-session (User)', type: 'User' },
    { id: 'usr-004', name: 'ci-cd-runner (User)', type: 'User' },
    { id: 'rol-001', name: 'EC2InstanceProfileRole (Role)', type: 'Role' }
  ];

  const targetOptions = [
    { id: 'res-002', name: 'S3-Customer-PII-DB (S3)', type: 'S3' },
    { id: 'res-004', name: 'Secrets-RDS-MasterCredentials (Secrets)', type: 'Secrets' }
  ];

  const runSimulation = () => {
    setIsRunning(true);
    setShowResult(false);
    setTimeout(() => {
      setIsRunning(false);
      setShowResult(true);
    }, 1800);
  };

  const resetSimulation = () => {
    setIsRunning(false);
    setShowResult(false);
  };

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto bg-enterprise-bg select-none">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Zap className="w-6 h-6 text-enterprise-warning animate-pulse" />
            <span>Attack Simulation Sandbox</span>
          </h1>
          <p className="text-xs text-enterprise-subtext mt-1">
            Perform simulated lateral privilege threat assessments. Select starting access points and targets to calculate path risks.
          </p>
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-400 text-xs font-bold">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Interactive Sandbox (Custom Graph Engine Coming Soon)</span>
        </div>
      </div>

      {/* Simulator Inputs Config */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 bg-enterprise-card border border-enterprise-border p-5 rounded-xl">
        {/* Step 1: Starting Access */}
        <div className="space-y-2">
          <label className="text-xs font-bold text-white uppercase tracking-wider block">
            1. Starting Identity Point
          </label>
          <select
            value={startIdentity}
            onChange={(e) => setStartIdentity(e.target.value)}
            disabled={isRunning || showResult}
            className="w-full bg-enterprise-bg/60 border border-enterprise-border rounded-lg px-3 py-2.5 text-xs text-white focus:outline-none focus:border-enterprise-accent disabled:opacity-50"
          >
            {startOptions.map((opt) => (
              <option key={opt.id} value={opt.id} className="bg-enterprise-card">
                {opt.name}
              </option>
            ))}
          </select>
        </div>

        {/* Step 2: Privilege Escalation Method */}
        <div className="space-y-2">
          <label className="text-xs font-bold text-white uppercase tracking-wider block">
            2. Exploitation / Permission Vector
          </label>
          <select
            value={escalationStep}
            onChange={(e) => setEscalationStep(e.target.value)}
            disabled={isRunning || showResult}
            className="w-full bg-enterprise-bg/60 border border-enterprise-border rounded-lg px-3 py-2.5 text-xs text-white focus:outline-none focus:border-enterprise-accent disabled:opacity-50"
          >
            <option value="sts:AssumeRole" className="bg-enterprise-card">Abuse sts:AssumeRole Privilege</option>
            <option value="imds_ssrf" className="bg-enterprise-card">Exploit Server SSRF via IMDSv1 Metadata</option>
          </select>
        </div>

        {/* Step 3: Target Resource */}
        <div className="space-y-2">
          <label className="text-xs font-bold text-white uppercase tracking-wider block">
            3. Final Goal Target
          </label>
          <select
            value={targetResource}
            onChange={(e) => setTargetResource(e.target.value)}
            disabled={isRunning || showResult}
            className="w-full bg-enterprise-bg/60 border border-enterprise-border rounded-lg px-3 py-2.5 text-xs text-white focus:outline-none focus:border-enterprise-accent disabled:opacity-50"
          >
            {targetOptions.map((opt) => (
              <option key={opt.id} value={opt.id} className="bg-enterprise-card">
                {opt.name}
              </option>
            ))}
          </select>
        </div>

        {/* Actions Button Center span */}
        <div className="md:col-span-3 flex items-center gap-3 justify-end border-t border-enterprise-border pt-4">
          {showResult ? (
            <button
              onClick={resetSimulation}
              className="flex items-center gap-1.5 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-white font-semibold rounded-lg text-xs transition-colors border border-enterprise-border"
            >
              <RotateCcw className="w-4 h-4" />
              <span>Reset Sandbox</span>
            </button>
          ) : (
            <button
              onClick={runSimulation}
              disabled={isRunning}
              className="flex items-center gap-1.5 px-6 py-2 bg-enterprise-warning hover:bg-amber-600 disabled:bg-gray-800 text-enterprise-bg font-extrabold rounded-lg text-xs transition-colors shadow-lg glow-blue"
            >
              {isRunning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Computing Vectors...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-enterprise-bg" />
                  <span>Launch Threat Simulator</span>
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Visual Simulation Results */}
      <AnimatePresence>
        {showResult && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            className="space-y-6"
          >
            {/* Visual hop chain */}
            <div className="bg-enterprise-card border border-enterprise-border p-6 rounded-xl space-y-4">
              <h2 className="text-xs font-bold text-white uppercase tracking-wider">
                Simulated Attack Pathway Hops
              </h2>
              <div className="flex flex-wrap items-center justify-center gap-4 bg-enterprise-bg/60 p-6 rounded-xl border border-enterprise-border">
                {/* Hop 1 */}
                <div className="flex items-center gap-3 px-4 py-2 bg-enterprise-card border border-enterprise-border rounded-xl">
                  <User className="w-5 h-5 text-enterprise-accent" />
                  <div className="text-xs">
                    <p className="font-bold text-white">developer-session</p>
                    <p className="text-[9px] text-enterprise-subtext uppercase">Entry compromised</p>
                  </div>
                </div>

                <ArrowRight className="w-5 h-5 text-enterprise-critical animate-pulse" />

                {/* Hop 2 */}
                <div className="flex items-center gap-3 px-4 py-2 bg-enterprise-card border border-enterprise-border rounded-xl">
                  <Key className="w-5 h-5 text-purple-500" />
                  <div className="text-xs">
                    <p className="font-bold text-white">AWSAdminRole</p>
                    <p className="text-[9px] text-enterprise-subtext uppercase">Assumed admin role</p>
                  </div>
                </div>

                <ArrowRight className="w-5 h-5 text-enterprise-critical animate-pulse" />

                {/* Hop 3 */}
                <div className="flex items-center gap-3 px-4 py-2 bg-enterprise-card border border-enterprise-border rounded-xl">
                  <Database className="w-5 h-5 text-enterprise-warning" />
                  <div className="text-xs">
                    <p className="font-bold text-white">S3-Customer-PII-DB</p>
                    <p className="text-[9px] text-enterprise-subtext uppercase">Target database compromised</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Calculations and AI Explanation row */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Metrics */}
              <div className="bg-enterprise-card border border-enterprise-border p-5 rounded-xl flex flex-col justify-between gap-4">
                <h3 className="text-xs font-bold text-white uppercase tracking-wider">Simulated Path Metrics</h3>
                <div className="space-y-4 grow flex flex-col justify-center">
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-enterprise-subtext">Estimated Path Risk:</span>
                    <span className="text-enterprise-critical font-bold">92 / 100 (Critical)</span>
                  </div>
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-enterprise-subtext">Blast Radius:</span>
                    <span className="text-white font-bold text-right max-w-[150px]">Customer Data Leaked</span>
                  </div>
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-enterprise-subtext">Privilege Hops:</span>
                    <span className="text-white font-bold">2 Permission Hops</span>
                  </div>
                </div>
              </div>

              {/* Copilot Analysis */}
              <div className="bg-enterprise-card border border-enterprise-border p-5 rounded-xl lg:col-span-2 flex gap-3 text-xs leading-relaxed text-gray-200">
                <Bot className="w-6 h-6 text-enterprise-accent shrink-0 mt-0.5" />
                <div className="space-y-3 w-full">
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider">Simulated AI Path Assessment</h3>
                  <p className="text-[11px] text-enterprise-subtext">
                    Exploitation occurred because the trust relationship policy of the
                    <strong className="text-white"> AWSAdminRole </strong> permits assumption without verifying the principal session state. The developer credential can elevate directly to master administrator privileges and scan database secrets.
                  </p>
                  <div className="space-y-1.5">
                    <span className="font-semibold text-white text-[10px] flex items-center gap-1">
                      <Terminal className="w-3.5 h-3.5 text-enterprise-accent" />
                      <span>Mitigation Guide</span>
                    </span>
                    <pre className="p-3 bg-gray-900 border border-enterprise-border rounded-lg text-[9px] font-mono text-gray-300 overflow-x-auto">
{`# Inject Condition clause restricting role assumption to authorized source IPs:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:user/developer-session" },
      "Action": "sts:AssumeRole",
      "Condition": { "NotIpAddress": { "aws:SourceIp": "203.0.113.42" } }
    }
  ]
}`}
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
