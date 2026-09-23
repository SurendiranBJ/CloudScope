import { useState } from 'react';
import type { FC } from 'react';
import { 
  X, Copy, Check, ShieldAlert, Key, FileText, MapPin, 
  Users, ArrowRight, Activity, Search,
  Database, Layers
} from 'lucide-react';
import { formatRegion } from '../utils/regionNames';

export interface NodeData {
  id: string;
  label?: string;
  type?: string;
  riskScore?: number;
  arn?: string;
  region?: string;
  description?: string;
  policyType?: string;
  trustPolicy?: string;
  policies?: string[];
  groups?: string[];
  members?: string[];
  actions?: string[];
  mfaEnabled?: boolean;
  subtitle?: string;
  effectiveAccess?: Array<{
    target: string;
    targetType: string;
    category: string;
    actions: string[];
    policies: string[];
  }>;
}

export interface EdgeData {
  source: string;
  target: string;
  sourceType?: string;
  targetType?: string;
  sourceArn?: string;
  targetArn?: string;
  label: string;
  edge_type?: string;
  access_category?: string;
  actions?: string[];
  action?: string;
  policy_names?: string[];
  policy_name?: string;
  policy_arn?: string;
  statement_sid?: string;
  statement_sids?: string[];
  effect?: string;
  decision?: string;
  region?: string;
  why?: string;
  isActivity?: boolean;
  evidence?: any;
}

interface NodeDetailsPanelProps {
  nodeData?: NodeData | null;
  edgeData?: EdgeData | null;
  onClose: () => void;
}

export const NodeDetailsPanel: FC<NodeDetailsPanelProps> = ({ nodeData, edgeData, onClose }) => {
  const [copiedArn, setCopiedArn] = useState<string | null>(null);
  const [actionSearch, setActionSearch] = useState('');

  if (!nodeData && !edgeData) return null;

  const handleCopy = (text?: string) => {
    if (text) {
      navigator.clipboard.writeText(text);
      setCopiedArn(text);
      setTimeout(() => setCopiedArn(null), 2000);
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return 'text-red-400 border-red-500/30 bg-red-950/20';
    if (score >= 50) return 'text-amber-400 border-amber-500/30 bg-amber-950/20';
    return 'text-emerald-400 border-emerald-500/30 bg-emerald-950/20';
  };

  const getRiskProgressColor = (score: number) => {
    if (score >= 80) return 'bg-red-500 shadow-[0_0_10px_#EF4444]';
    if (score >= 50) return 'bg-amber-500';
    return 'bg-emerald-500';
  };

  const formatTrustPolicy = (raw?: string): string => {
    if (!raw) return '';
    try {
      return JSON.stringify(JSON.parse(raw), null, 2);
    } catch {
      return raw;
    }
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // RENDER EDGE DETAILS
  // ─────────────────────────────────────────────────────────────────────────────
  if (edgeData) {
    const rawActions = edgeData.actions && edgeData.actions.length > 0 
      ? edgeData.actions 
      : edgeData.action 
        ? [edgeData.action] 
        : [];
    
    const distinctActions = Array.from(new Set(rawActions));
    const filteredActions = distinctActions.filter(a => 
      !actionSearch || a.toLowerCase().includes(actionSearch.toLowerCase())
    );

    const rawPolicies = edgeData.policy_names && edgeData.policy_names.length > 0
      ? edgeData.policy_names
      : edgeData.policy_name
        ? [edgeData.policy_name]
        : [];
    const distinctPolicies = Array.from(new Set(rawPolicies));

    const sids = edgeData.statement_sids && edgeData.statement_sids.length > 0
      ? edgeData.statement_sids
      : edgeData.statement_sid
        ? [edgeData.statement_sid]
        : [];

    return (
      <div className="w-96 border-l border-gray-800 bg-[#0F172A] h-full flex flex-col justify-between select-none relative z-30 overflow-y-auto shrink-0 shadow-2xl animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="p-4 border-b border-gray-800 flex items-center justify-between bg-gray-900/50">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <span className="font-bold text-sm text-white">Relationship Evidence</span>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-gray-400 hover:text-white rounded-md hover:bg-gray-800 transition-colors"
            title="Close panel"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 flex-1 space-y-5">
          {/* Source -> Target Pathway Cards */}
          <div className="space-y-2">
            <div className="p-3 bg-gray-900/80 border border-gray-800 rounded-lg space-y-2">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-gray-400 uppercase font-mono tracking-wider">Source Principal</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-950 text-blue-400 border border-blue-800">
                  {edgeData.sourceType || 'Identity'}
                </span>
              </div>
              <div className="font-bold text-white text-sm truncate" title={edgeData.source}>
                {edgeData.source}
              </div>
            </div>

            <div className="flex justify-center">
              <div className="p-1.5 rounded-full bg-gray-800 text-cyan-400 border border-gray-700">
                <ArrowRight className="w-3.5 h-3.5" />
              </div>
            </div>

            <div className="p-3 bg-gray-900/80 border border-gray-800 rounded-lg space-y-2">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-gray-400 uppercase font-mono tracking-wider">Target Resource</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                  {edgeData.targetType || 'Resource'}
                </span>
              </div>
              <div className="font-bold text-white text-sm truncate" title={edgeData.target}>
                {edgeData.target}
              </div>
            </div>
          </div>

          {/* Access Category & Decision Status */}
          <div className="grid grid-cols-2 gap-2">
            <div className="p-2.5 bg-gray-900/60 border border-gray-800 rounded-lg">
              <span className="text-[10px] uppercase font-bold text-gray-400 block mb-1">Access Level</span>
              <span className="px-2 py-1 rounded text-xs font-bold bg-cyan-950 text-cyan-300 border border-cyan-800 block text-center truncate">
                {edgeData.access_category || edgeData.label || 'EFFECTIVE ACCESS'}
              </span>
            </div>
            <div className="p-2.5 bg-gray-900/60 border border-gray-800 rounded-lg">
              <span className="text-[10px] uppercase font-bold text-gray-400 block mb-1">Policy Decision</span>
              <span className={`px-2 py-1 rounded text-xs font-bold block text-center truncate ${
                edgeData.decision === 'ALLOWED' || !edgeData.decision
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  : 'bg-red-950 text-red-300 border border-red-800'
              }`}>
                {edgeData.decision || 'ALLOWED'}
              </span>
            </div>
          </div>

          {/* CloudTrail Verified Badge */}
          {edgeData.isActivity && (
            <div className="flex items-center gap-2 p-2.5 rounded-lg bg-amber-950/30 border border-amber-700/50 text-amber-300 text-xs">
              <Activity className="w-4 h-4 shrink-0 text-amber-400 animate-pulse" />
              <div>
                <span className="font-semibold block">Observed in CloudTrail</span>
                <span className="text-[10px] text-amber-400/80">Active API invocation correlated to this relationship.</span>
              </div>
            </div>
          )}

          {/* Explanation / Why this exists */}
          <div>
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block mb-1.5">
              Authorization Provenance
            </span>
            <div className="p-3 bg-gray-900 border border-gray-800 rounded-lg text-xs text-gray-300 leading-relaxed">
              {edgeData.why || `Authoritative relationship connecting '${edgeData.source}' to '${edgeData.target}'.`}
            </div>
          </div>

          {/* Policy Sources */}
          {distinctPolicies.length > 0 && (
            <div className="space-y-2">
              <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5 text-teal-400" />
                <span>Granting Policy Sources ({distinctPolicies.length})</span>
              </span>
              <div className="space-y-1.5">
                {distinctPolicies.map((pol) => (
                  <div key={pol} className="p-2.5 bg-gray-900/90 border border-gray-800 rounded-lg flex items-center justify-between text-xs">
                    <span className="font-mono text-teal-300 truncate" title={pol}>{pol}</span>
                    <span className="text-[10px] text-gray-500 font-mono">IAM Policy</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Statement SIDs */}
          {sids.length > 0 && (
            <div className="space-y-1.5">
              <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">
                Statement SIDs:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {sids.map(sid => (
                  <span key={sid} className="px-2 py-0.5 rounded bg-gray-800 border border-gray-700 font-mono text-[10px] text-gray-300">
                    {sid}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* IAM Actions Granted */}
          {distinctActions.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Key className="w-3.5 h-3.5 text-amber-400" />
                  <span>Exact IAM Actions ({distinctActions.length})</span>
                </span>
              </div>

              {distinctActions.length > 5 && (
                <div className="relative">
                  <Search className="w-3 h-3 absolute left-2.5 top-2 text-gray-500" />
                  <input
                    type="text"
                    placeholder="Filter actions..."
                    value={actionSearch}
                    onChange={(e) => setActionSearch(e.target.value)}
                    className="w-full bg-gray-900 border border-gray-800 text-xs rounded-md pl-7 pr-2.5 py-1 text-gray-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              )}

              <div className="max-h-48 overflow-y-auto space-y-1 pr-1 custom-scrollbar">
                {filteredActions.map((act) => (
                  <div key={act} className="px-2.5 py-1 bg-gray-900 border border-gray-800 rounded font-mono text-[11px] text-amber-300 truncate" title={act}>
                    {act}
                  </div>
                ))}
                {filteredActions.length === 0 && (
                  <p className="text-xs text-gray-500 italic py-1">No matching actions</p>
                )}
              </div>
            </div>
          )}

          {/* Region */}
          {edgeData.region && (
            <div className="flex items-center gap-2 py-1.5 px-2.5 bg-gray-900 border border-gray-800 rounded-lg text-xs">
              <MapPin className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span className="text-gray-400 font-semibold">Region:</span>
              <span className="ml-auto text-[11px] text-gray-300 font-mono">{formatRegion(edgeData.region)}</span>
            </div>
          )}
        </div>
      </div>
    );
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // RENDER NODE DETAILS
  // ─────────────────────────────────────────────────────────────────────────────
  const type = (nodeData?.type || '').toLowerCase();

  return (
    <div className="w-96 border-l border-gray-800 bg-[#0F172A] h-full flex flex-col justify-between select-none relative z-30 overflow-y-auto shrink-0 shadow-2xl animate-in slide-in-from-right duration-200">
      {/* Header */}
      <div className="p-4 border-b border-gray-800 flex items-center justify-between bg-gray-900/50">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-blue-400" />
          <span className="font-bold text-sm text-white">Entity Security Details</span>
        </div>
        <button
          onClick={onClose}
          className="p-1 text-gray-400 hover:text-white rounded-md hover:bg-gray-800 transition-colors"
          title="Close panel"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Content */}
      <div className="p-5 flex-1 space-y-6">
        {/* Name and Type */}
        <div>
          <span className="text-[10px] uppercase font-bold tracking-wider text-blue-400 bg-blue-950/80 border border-blue-800 px-2 py-0.5 rounded">
            {nodeData?.type}
          </span>
          <h2 className="text-lg font-bold text-white mt-2 truncate" title={nodeData?.label || nodeData?.id}>
            {nodeData?.label || nodeData?.id}
          </h2>
          {nodeData?.subtitle && (
            <p className="text-xs text-blue-400 font-medium mt-1">{nodeData.subtitle}</p>
          )}
          <p className="text-xs text-gray-400 mt-1.5 leading-relaxed">
            {nodeData?.description || 'Verified AWS infrastructure identity analyzed by CloudScope.'}
          </p>
        </div>

        {/* Risk Score Card */}
        <div className={`p-4 rounded-xl border ${getRiskColor(nodeData?.riskScore || 0)}`}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-200">Security Risk Score</span>
            <span className="text-lg font-black">{nodeData?.riskScore || 0} / 100</span>
          </div>
          <div className="w-full bg-gray-800 h-2 rounded-full mt-3 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-300 ${getRiskProgressColor(nodeData?.riskScore || 0)}`}
              style={{ width: `${nodeData?.riskScore || 0}%` }}
            />
          </div>
        </div>

        {/* Resource ARN Details with 1-Click Copy */}
        {nodeData?.arn && (
          <div className="space-y-1.5">
            <span className="text-xs font-semibold text-gray-400">Resource ARN</span>
            <div className="bg-gray-900/90 border border-gray-800 rounded-lg p-2.5 flex items-center justify-between gap-2">
              <span className="text-[11px] text-gray-300 font-mono select-text truncate break-all max-w-[240px]" title={nodeData.arn}>
                {nodeData.arn}
              </span>
              <button
                onClick={() => handleCopy(nodeData.arn)}
                className="p-1 hover:bg-gray-800 text-gray-400 hover:text-white rounded transition-colors shrink-0"
                title="Copy ARN"
              >
                {copiedArn === nodeData.arn ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        )}

        {/* AWS Region */}
        {nodeData?.region && (
          <div className="flex items-center gap-2 py-2 px-3 bg-gray-900 border border-gray-800 rounded-lg">
            <MapPin className="w-4 h-4 text-blue-400 shrink-0" />
            <span className="text-xs text-gray-400 font-semibold">Region</span>
            <span className="ml-auto text-xs text-gray-300 font-mono">{formatRegion(nodeData.region)}</span>
          </div>
        )}

        {/* Effective Cloud Resource Access List */}
        {nodeData?.effectiveAccess && nodeData.effectiveAccess.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-gray-400">
              <Database className="w-4 h-4 text-emerald-400" />
              <span>Effective Resource Access ({nodeData.effectiveAccess.length})</span>
            </div>
            <div className="space-y-2 max-h-56 overflow-y-auto pr-1 custom-scrollbar">
              {nodeData.effectiveAccess.map((ea, idx) => (
                <div key={idx} className="p-2.5 bg-gray-900 border border-gray-800 rounded-lg text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white truncate max-w-[170px]" title={ea.target}>{ea.target}</span>
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                      {ea.category}
                    </span>
                  </div>
                  <div className="text-[10px] text-gray-400 truncate">
                    {ea.targetType} • {ea.policies.join(', ') || 'Direct / Assumed'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Group Details */}
        {type === 'group' && (
          <div className="space-y-3">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-gray-400">
              <Users className="w-4 h-4 text-indigo-400" />
              <span>IAM Group Membership</span>
            </div>
            <div className="p-3 bg-gray-900 border border-gray-800 rounded-lg text-xs space-y-1.5">
              <span className="text-gray-400">Contextual Membership:</span>
              <p className="text-gray-300 text-[11px] leading-relaxed">
                Clicking this group activates <strong>Neighborhood Focus</strong>, spotlighting its direct members, attached policies, and target resources.
              </p>
            </div>
          </div>
        )}

        {/* Role: Trust Relationship Policy */}
        {type === 'role' && (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-gray-400">
              <FileText className="w-4 h-4 text-purple-400" />
              <span>Trust Relationship Policy</span>
            </div>
            <pre className="p-3 bg-gray-900/90 border border-gray-800 rounded-lg text-[10px] font-mono text-gray-300 overflow-x-auto max-h-48 scrollbar-thin">
              {nodeData?.trustPolicy
                ? formatTrustPolicy(nodeData.trustPolicy)
                : '// Trust policy registered in AWS IAM.'}
            </pre>
          </div>
        )}

        {/* User: Attached Policies */}
        {type === 'user' && (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-gray-400">
              <Key className="w-4 h-4 text-blue-400" />
              <span>Attached / Inherited Policies</span>
            </div>
            <div className="space-y-1.5">
              {nodeData?.policies && nodeData.policies.length > 0 ? (
                nodeData.policies.map((policy) => {
                  const isAdmin = /admin/i.test(policy) || /\*/.test(policy);
                  return (
                    <div
                      key={policy}
                      className="flex justify-between items-center bg-gray-900/90 p-2 rounded border border-gray-800 text-xs"
                    >
                      <span className="font-semibold text-gray-200 truncate max-w-[180px]" title={policy}>
                        {policy}
                      </span>
                      {isAdmin && (
                        <span className="text-[9px] text-red-400 font-bold px-1.5 py-0.5 rounded bg-red-950 border border-red-800 ml-2 shrink-0">
                          Admin
                        </span>
                      )}
                    </div>
                  );
                })
              ) : (
                <p className="text-[11px] text-gray-500 italic">Group-inherited or direct policies apply.</p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
