import { useState } from 'react';
import type { FC } from 'react';
import { X, Copy, Check, ShieldAlert, Key, FileText } from 'lucide-react';

interface NodeDetailsPanelProps {
  nodeData: {
    id: string;
    label?: string;
    type?: 'User' | 'Role' | 'S3' | 'EC2' | 'Lambda' | 'Secrets' | 'RDS' | 'Policy';
    riskScore?: number;
    arn?: string;
    description?: string;
    policyType?: string;
  } | null;
  onClose: () => void;
}

export const NodeDetailsPanel: FC<NodeDetailsPanelProps> = ({ nodeData, onClose }) => {
  const [copied, setCopied] = useState(false);

  if (!nodeData) return null;

  const handleCopy = () => {
    if (nodeData.arn) {
      navigator.clipboard.writeText(nodeData.arn);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return 'text-enterprise-critical border-enterprise-critical/30 bg-enterprise-critical/10';
    if (score >= 50) return 'text-enterprise-warning border-enterprise-warning/30 bg-enterprise-warning/10';
    return 'text-enterprise-success border-enterprise-success/30 bg-enterprise-success/10';
  };

  const getRiskProgressColor = (score: number) => {
    if (score >= 80) return 'bg-enterprise-critical shadow-[0_0_10px_#EF4444]';
    if (score >= 50) return 'bg-enterprise-warning';
    return 'bg-enterprise-success';
  };

  return (
    <div className="w-80 border-l border-enterprise-border bg-enterprise-card h-full flex flex-col justify-between select-none relative z-30 overflow-y-auto shrink-0 shadow-2xl animate-in slide-in-from-right duration-200">
      {/* Header */}
      <div className="p-4 border-b border-enterprise-border flex items-center justify-between bg-enterprise-bg/25">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-enterprise-accent" />
          <span className="font-bold text-sm text-white">Identity Details</span>
        </div>
        <button
          onClick={onClose}
          className="p-1 text-enterprise-subtext hover:text-white rounded-md hover:bg-gray-800 transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Content */}
      <div className="p-5 flex-1 space-y-6">
        {/* Name and Type */}
        <div>
          <span className="text-[10px] uppercase font-bold tracking-wider text-enterprise-subtext bg-gray-800 px-2 py-0.5 rounded">
            {nodeData.type}
          </span>
          <h2 className="text-lg font-bold text-white mt-2 truncate" title={nodeData.label}>
            {nodeData.label}
          </h2>
          <p className="text-xs text-enterprise-subtext mt-1.5 leading-relaxed">
            {nodeData.description || 'No operational description registered for this identity.'}
          </p>
        </div>

        {/* Risk Score Card */}
        <div className={`p-4 rounded-xl border ${getRiskColor(nodeData.riskScore || 0)}`}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-200">Identity Risk Score</span>
            <span className="text-lg font-black">{nodeData.riskScore || 0} / 100</span>
          </div>
          {/* Progress Bar */}
          <div className="w-full bg-gray-800 h-2 rounded-full mt-3 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-300 ${getRiskProgressColor(nodeData.riskScore || 0)}`}
              style={{ width: `${nodeData.riskScore || 0}%` }}
            />
          </div>
        </div>

        {/* Resource ARN Details */}
        {nodeData.arn && (
          <div className="space-y-1.5">
            <span className="text-xs font-semibold text-enterprise-subtext">Resource ARN</span>
            <div className="bg-enterprise-bg/60 border border-enterprise-border rounded-lg p-2.5 flex items-center justify-between gap-2">
              <span className="text-[10px] text-gray-300 font-mono select-text truncate break-all max-w-[200px]">
                {nodeData.arn}
              </span>
              <button
                onClick={handleCopy}
                className="p-1 hover:bg-gray-800 text-enterprise-subtext hover:text-white rounded transition-colors"
                title="Copy ARN"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-enterprise-success" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        )}

        {/* Conditional Policy Viewers */}
        {nodeData.type === 'Role' && (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-enterprise-subtext">
              <FileText className="w-4 h-4 text-enterprise-accent" />
              <span>Trust Relationship Policy</span>
            </div>
            <pre className="p-3 bg-enterprise-bg/85 border border-enterprise-border rounded-lg text-[10px] font-mono text-gray-300 overflow-x-auto max-h-48 scrollbar-thin">
{`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}`}
            </pre>
          </div>
        )}

        {nodeData.type === 'User' && (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-enterprise-subtext">
              <Key className="w-4 h-4 text-enterprise-accent" />
              <span>Directly Attached Policies</span>
            </div>
            <div className="space-y-1.5">
              <div className="flex justify-between items-center bg-enterprise-bg/40 p-2 rounded border border-enterprise-border text-xs">
                <span className="font-semibold text-gray-200">AdministratorAccess</span>
                <span className="text-[10px] text-enterprise-critical font-bold">Admin Privs</span>
              </div>
              <div className="flex justify-between items-center bg-enterprise-bg/40 p-2 rounded border border-enterprise-border text-xs">
                <span className="font-semibold text-gray-200">SystemAdminAccess</span>
                <span className="text-[10px] text-enterprise-warning font-bold">Write Scope</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Footer Controls */}
      <div className="p-4 border-t border-enterprise-border bg-enterprise-bg/25">
        <button
          onClick={onClose}
          className="w-full py-2 bg-enterprise-accent hover:bg-blue-600 active:bg-blue-700 text-white font-semibold rounded-lg text-xs transition-colors glow-blue"
        >
          Audit History Logs
        </button>
      </div>
    </div>
  );
};
