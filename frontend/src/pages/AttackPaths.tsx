import { useState, Fragment } from 'react';
import type { FC } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  GitMerge,
  ArrowRight,
  Sparkles,
  RefreshCw,
  Bot,
  Terminal,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getAttackPaths } from '../api/attack';
import { mockAttackPaths } from '../data/attackPaths';
import type { AttackPath } from '../types';

export const AttackPaths: FC = () => {
  const navigate = useNavigate();
  const [selectedPathForAI, setSelectedPathForAI] = useState<string | null>(null);
  const [loadingAI, setLoadingAI] = useState<string | null>(null);

  const { data } = useQuery({
    queryKey: ['attackPaths'],
    queryFn: getAttackPaths,
    refetchInterval: 10000
  });

  const attackPaths = data || [];

  const handleHighlightInGraph = (path: AttackPath) => {
    const nodeIds = path.nodes.map((n) => n.id).join(',');
    navigate(`/graph?highlight=${nodeIds}`);
  };

  const handleExplainAI = (pathId: string) => {
    if (selectedPathForAI === pathId) {
      setSelectedPathForAI(null);
      return;
    }

    setLoadingAI(pathId);
    setTimeout(() => {
      setLoadingAI(null);
      setSelectedPathForAI(pathId);
    }, 1200); // Simulate mock AI computation
  };

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto bg-enterprise-bg select-none">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
          <GitMerge className="w-6 h-6 text-enterprise-accent" />
          <span>Identity-Centric Attack Paths</span>
        </h1>
        <p className="text-xs text-enterprise-subtext mt-1">
          Explore lateral movement vectors mapped by permissions analysis from compromised users to core database objects.
        </p>
      </div>

      {/* Pathways List */}
      <div className="space-y-6">
        {attackPaths.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-12 border border-dashed border-enterprise-border rounded-xl bg-enterprise-card/50">
            <Sparkles className="w-12 h-12 text-enterprise-subtext mb-4" />
            <h3 className="text-lg font-bold text-white mb-2">No Attack Paths Detected</h3>
            <p className="text-sm text-enterprise-subtext text-center max-w-md">
              IdentityScope scanned your AWS environment and found no critical lateral movement paths from identities to core resources based on current permissions.
            </p>
          </div>
        ) : (
          attackPaths.map((path) => {
            const isAIExpanded = selectedPathForAI === path.id;
            const isAILoading = loadingAI === path.id;


          return (
            <div
              key={path.id}
              className="bg-enterprise-card border border-enterprise-border rounded-xl p-5 hover:border-gray-800 transition-colors shadow-lg flex flex-col gap-5"
            >
              {/* Path Header */}
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-enterprise-border pb-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className={`text-[9px] font-bold px-2 py-0.5 rounded border capitalize ${
                        path.severity === 'critical'
                          ? 'bg-enterprise-critical/20 text-enterprise-critical border-enterprise-critical/30'
                          : 'bg-enterprise-warning/20 text-enterprise-warning border-enterprise-warning/30'
                      }`}
                    >
                      {path.severity} Risk
                    </span>
                    <span className="text-[10px] text-enterprise-accent bg-enterprise-accent/10 border border-enterprise-accent/20 px-2 py-0.5 rounded font-bold">
                      {path.likelihood}% Likelihood
                    </span>
                    <h3 className="text-sm font-bold text-white ml-2">{path.name}</h3>
                  </div>
                  <p className="text-xs text-enterprise-subtext">{path.description}</p>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleHighlightInGraph(path)}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-enterprise-accent hover:bg-blue-600 active:bg-blue-700 text-white font-semibold rounded-lg text-xs transition-colors glow-blue"
                  >
                    <GitMerge className="w-3.5 h-3.5" />
                    <span>Highlight In Graph</span>
                  </button>
                  <button
                    onClick={() => handleExplainAI(path.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-white border border-enterprise-border font-semibold rounded-lg text-xs transition-colors"
                  >
                    {isAILoading ? (
                      <RefreshCw className="w-3.5 h-3.5 animate-spin text-enterprise-accent" />
                    ) : (
                      <Sparkles className="w-3.5 h-3.5 text-enterprise-accent" />
                    )}
                    <span>Explain with AI</span>
                    {isAIExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              {/* Node Sequence Visualizer */}
              <div className="flex items-center flex-wrap gap-2.5 bg-enterprise-bg/40 p-4 rounded-xl border border-enterprise-border">
                {path.nodes.map((node, index) => (
                  <Fragment key={node.id}>
                    {/* Node card */}
                    <div className="flex items-center gap-2 px-3 py-1.5 bg-enterprise-card border border-enterprise-border rounded-lg shadow-sm">
                      <span
                        className={`w-2 h-2 rounded-full ${
                          node.type === 'User'
                            ? 'bg-enterprise-accent'
                            : node.type === 'Role'
                            ? 'bg-purple-500'
                            : node.type === 'Policy'
                            ? 'bg-teal-500'
                            : 'bg-enterprise-warning'
                        }`}
                      />
                      <div className="text-[10px]">
                        <p className="font-bold text-white leading-none">{node.name}</p>
                        <p className="text-[8px] text-enterprise-subtext mt-0.5 leading-none">{node.type}</p>
                      </div>
                    </div>
                    {/* Hops Arrow */}
                    {index < path.nodes.length - 1 && <ArrowRight className="w-4 h-4 text-enterprise-subtext" />}
                  </Fragment>
                ))}
              </div>

              {/* MITRE Details Panel */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="space-y-1">
                  <span className="font-bold text-enterprise-subtext">Blast Radius:</span>
                  <p className="text-gray-300 text-xs font-semibold">{path.blastRadius}</p>
                </div>
                <div className="space-y-1">
                  <span className="font-bold text-enterprise-subtext">MITRE ATT&CK Techniques:</span>
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {path.mitreTechniques.map((tech) => (
                      <span key={tech} className="px-2 py-0.5 bg-gray-800 text-[9px] text-gray-300 rounded font-semibold font-mono border border-gray-700">
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Mock AI Response Block */}
              {isAIExpanded && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  className="bg-enterprise-accent/5 p-4 rounded-xl border border-enterprise-accent/20 flex gap-3 text-xs leading-relaxed text-gray-200 mt-2"
                >
                  <Bot className="w-5 h-5 text-enterprise-accent shrink-0 mt-0.5" />
                  <div className="space-y-3 w-full">
                    <h4 className="font-extrabold text-white text-xs flex items-center gap-1.5">
                      <span>Copilot Security Explanation</span>
                    </h4>
                    <p className="text-[11px] text-enterprise-subtext">
                      This lateral pathway leverages transitive privileges. An attacker gaining access to the
                      <strong className="text-white font-semibold"> {path.nodes[0].name} </strong> identity could inherit the attached custom policy, execute
                      <code className="text-enterprise-accent px-1.5 py-0.5 bg-gray-900 rounded font-mono">sts:AssumeRole</code>, and elevate to the root admin permission tier.
                    </p>
                    <div className="space-y-1.5">
                      <span className="font-semibold text-white text-[10px] flex items-center gap-1">
                        <Terminal className="w-3.5 h-3.5 text-enterprise-accent" />
                        <span>Recommended Remediation (AWS Policy Fix)</span>
                      </span>
                      <pre className="p-3 bg-gray-900 border border-enterprise-border rounded-lg text-[9px] font-mono text-gray-300 overflow-x-auto">
{`# 1. Modify the trust relationships document to enforce MFA restriction:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:user/developer-session" },
      "Action": "sts:AssumeRole",
      "Condition": { "Bool": { "aws:MultiFactorAuthPresent": "true" } }
    }
  ]
}`}
                      </pre>
                    </div>
                  </div>
                </motion.div>
              )}
            </div>
          );
        })
        )}
      </div>
    </div>
  );
};
