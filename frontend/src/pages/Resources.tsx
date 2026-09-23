import { useState, useMemo } from 'react';
import {
  User,
  Key,
  Server,
  Database,
  Zap,
  Lock,
  FileText,
  Search,
  X,
  Copy,
  Check,
  AlertTriangle,
  Layers,
  Cloud,
  Shield
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getCloudResources } from '../api/resources';
import { getScanStatus } from '../api/graph';
import { formatRegion } from '../utils/regionNames';
import { ScannedRegionBadge } from '../components/ScannedRegionBadge';
import type { CloudResource } from '../types';

interface ResourcesProps {
  search?: string;
}

const CLOUD_TYPES = new Set(['S3', 'EC2', 'Lambda', 'Secrets', 'RDS', 'DynamoDB']);
const IDENTITY_TYPES = new Set(['User', 'Role', 'Policy']);

export const Resources: React.FC<ResourcesProps> = ({ search = '' }) => {
  const [localSearch, setLocalSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<'ALL' | 'CLOUD' | 'IDENTITY'>('ALL');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [selectedRegion, setSelectedRegion] = useState<string>('ALL');
  // JSON config modal state
  const [inspectResource, setInspectResource] = useState<CloudResource | null>(null);
  const [copied, setCopied] = useState(false);

  const searchQuery = search || localSearch;

  const { data } = useQuery({
    queryKey: ['cloudResources'],
    queryFn: getCloudResources,
    refetchInterval: 10000
  });

  const { data: scanStatus } = useQuery({
    queryKey: ['scanStatus'],
    queryFn: getScanStatus,
    refetchInterval: 5000
  });

  const resources = data || [];

  // Map types to colored icons
  const typeIcons: Record<CloudResource['type'], any> = {
    User: { icon: User, color: 'text-enterprise-accent bg-enterprise-accent/15 border-enterprise-accent/30' },
    Role: { icon: Key, color: 'text-purple-500 bg-purple-500/15 border-purple-500/30' },
    S3: { icon: Database, color: 'text-enterprise-warning bg-enterprise-warning/15 border-enterprise-warning/30' },
    EC2: { icon: Server, color: 'text-enterprise-success bg-enterprise-success/15 border-enterprise-success/30' },
    Lambda: { icon: Zap, color: 'text-pink-500 bg-pink-500/15 border-pink-500/30' },
    Secrets: { icon: Lock, color: 'text-enterprise-critical bg-enterprise-critical/15 border-enterprise-critical/30' },
    RDS: { icon: Server, color: 'text-indigo-500 bg-indigo-500/15 border-indigo-500/30' },
    DynamoDB: { icon: Database, color: 'text-purple-500 bg-purple-500/15 border-purple-500/30' },
    Policy: { icon: FileText, color: 'text-teal-500 bg-teal-500/15 border-teal-500/30' }
  };

  const getStatusBadgeClass = (status: CloudResource['status']) => {
    switch (status) {
      case 'active':
      case 'configured':
        return 'bg-enterprise-success/15 text-enterprise-success border-enterprise-success/20';
      case 'stopped':
        return 'bg-gray-800 text-enterprise-subtext border-gray-700';
      case 'warning':
        return 'bg-enterprise-warning/15 text-enterprise-warning border-enterprise-warning/20';
      case 'critical':
        return 'bg-enterprise-critical/15 text-enterprise-critical border-enterprise-critical/20 animate-pulse';
      default:
        return 'bg-gray-800 text-enterprise-subtext border-gray-700';
    }
  };

  // Filter resources based on category, query inputs, and running EC2 condition
  const filteredResources = useMemo(() => {
    return resources.filter((res) => {
      // Security filter: EC2 must be running only
      if (res.type === 'EC2') {
        const state = (res.state || res.details?.state || res.status || '').toLowerCase();
        if (state !== 'running' && state !== 'active') {
          return false;
        }
      }

      // Category filter
      if (selectedCategory === 'CLOUD' && !CLOUD_TYPES.has(res.type)) {
        return false;
      }
      if (selectedCategory === 'IDENTITY' && !IDENTITY_TYPES.has(res.type)) {
        return false;
      }

      const matchesSearch =
        res.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        res.arn.toLowerCase().includes(searchQuery.toLowerCase()) ||
        res.owner.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesType = selectedType === 'ALL' || res.type === selectedType;
      const matchesRegion = selectedRegion === 'ALL' || res.region === selectedRegion;

      return matchesSearch && matchesType && matchesRegion;
    });
  }, [resources, searchQuery, selectedCategory, selectedType, selectedRegion]);

  const uniqueRegions = useMemo(() => {
    return ['ALL', ...new Set(resources.map((r) => r.region))];
  }, [resources]);

  const runningEc2Count = useMemo(() => {
    return resources.filter((r) => {
      if (r.type !== 'EC2') return false;
      const state = (r.state || r.details?.state || r.status || '').toLowerCase();
      return state === 'running' || state === 'active';
    }).length;
  }, [resources]);

  const lambdaCount = useMemo(() => {
    return resources.filter((r) => r.type === 'Lambda').length;
  }, [resources]);

  const resourceTypes = ['ALL', 'User', 'Role', 'S3', 'EC2', 'Lambda', 'Secrets', 'RDS', 'DynamoDB'];

  const failedRegions = scanStatus?.failed_regions || [];

  const handleCopy = () => {
    if (inspectResource) {
      navigator.clipboard.writeText(JSON.stringify(inspectResource, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto bg-enterprise-bg select-none">
      {/* Header */}
      <div className="flex justify-between items-center flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Cloud Resources Ledger</h1>
          <p className="text-xs text-enterprise-subtext mt-1">
            Browse and search all tracked AWS IAM policies and database storage entities.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <ScannedRegionBadge />
        </div>
      </div>

      {/* Regional Failure Warning */}
      {failedRegions.length > 0 && (
        <div className="flex items-center gap-3 p-3.5 bg-amber-500/10 border border-amber-500/30 rounded-xl text-xs text-amber-300 shadow-sm animate-pulse">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
          <div>
            <span className="font-semibold text-amber-200">Regional Collection Warning:</span> AWS collection failed for region(s):{' '}
            <span className="font-mono font-bold text-white bg-amber-950/60 px-1.5 py-0.5 rounded border border-amber-500/40">
              {failedRegions.join(', ')}
            </span>
            . Prior cached inventory was preserved for failed regions. Scan status marked as PARTIAL.
          </div>
        </div>
      )}

      {/* Category Tabs */}
      <div className="flex items-center gap-2 border-b border-enterprise-border pb-3">
        <button
          onClick={() => { setSelectedCategory('ALL'); setSelectedType('ALL'); }}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
            selectedCategory === 'ALL'
              ? 'bg-enterprise-accent text-white shadow'
              : 'bg-enterprise-card text-enterprise-subtext hover:text-white border border-enterprise-border'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>All Assets</span>
          <span className="ml-1 text-[10px] px-1.5 py-0.2 bg-black/20 rounded-full">{resources.length}</span>
        </button>

        <button
          onClick={() => { setSelectedCategory('CLOUD'); setSelectedType('ALL'); }}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
            selectedCategory === 'CLOUD'
              ? 'bg-enterprise-accent text-white shadow'
              : 'bg-enterprise-card text-enterprise-subtext hover:text-white border border-enterprise-border'
          }`}
        >
          <Cloud className="w-3.5 h-3.5" />
          <span>Cloud Workloads</span>
          <span className="ml-1 text-[10px] px-1.5 py-0.2 bg-black/20 rounded-full">
            {resources.filter(r => CLOUD_TYPES.has(r.type)).length}
          </span>
        </button>

        <button
          onClick={() => { setSelectedCategory('IDENTITY'); setSelectedType('ALL'); }}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
            selectedCategory === 'IDENTITY'
              ? 'bg-enterprise-accent text-white shadow'
              : 'bg-enterprise-card text-enterprise-subtext hover:text-white border border-enterprise-border'
          }`}
        >
          <Shield className="w-3.5 h-3.5" />
          <span>IAM & Identity</span>
          <span className="ml-1 text-[10px] px-1.5 py-0.2 bg-black/20 rounded-full">
            {resources.filter(r => IDENTITY_TYPES.has(r.type)).length}
          </span>
        </button>

        <div className="ml-auto text-[11px] text-enterprise-subtext font-mono">
          Running EC2: <span className="text-white font-bold">{runningEc2Count}</span> | Lambda: <span className="text-white font-bold">{lambdaCount}</span>
        </div>
      </div>

      {/* Filter and Search controls */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 bg-enterprise-card border border-enterprise-border p-4 rounded-xl">
        {/* Search */}
        <div className="relative">
          <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <Search className="h-4 w-4 text-enterprise-subtext" />
          </span>
          <input
            type="text"
            placeholder="Search resources, owners, credentials..."
            value={searchQuery}
            onChange={(e) => setLocalSearch(e.target.value)}
            className="w-full bg-enterprise-bg/60 border border-enterprise-border rounded-lg pl-10 pr-4 py-2 text-xs text-white placeholder-enterprise-subtext focus:outline-none focus:border-enterprise-accent transition-colors"
          />
        </div>

        {/* Type Filter */}
        <div className="flex items-center gap-2">
          <span className="text-xs font-bold text-enterprise-subtext whitespace-nowrap">Asset Type:</span>
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="w-full bg-enterprise-bg/60 border border-enterprise-border rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-enterprise-accent"
          >
            {resourceTypes
              .filter((t) => {
                if (t === 'ALL') return true;
                if (selectedCategory === 'CLOUD') return CLOUD_TYPES.has(t);
                if (selectedCategory === 'IDENTITY') return IDENTITY_TYPES.has(t);
                return true;
              })
              .map((t) => (
                <option key={t} value={t} className="bg-enterprise-card">
                  {t === 'ALL' ? 'All Types' : `${t}s`}
                </option>
              ))}
          </select>
        </div>

        {/* Region Filter */}
        <div className="flex items-center gap-2">
          <span className="text-xs font-bold text-enterprise-subtext whitespace-nowrap">AWS Region:</span>
          <select
            value={selectedRegion}
            onChange={(e) => setSelectedRegion(e.target.value)}
            className="w-full bg-enterprise-bg/60 border border-enterprise-border rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-enterprise-accent"
          >
            {uniqueRegions.map((reg) => (
              <option key={reg} value={reg} className="bg-enterprise-card">
                {reg === 'ALL' ? 'All Regions' : formatRegion(reg)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Ledger Table */}
      <div className="bg-enterprise-card border border-enterprise-border rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-enterprise-bg/40 border-b border-enterprise-border text-xs font-bold text-enterprise-subtext">
                <th className="p-4">Resource Name</th>
                <th className="p-4">Type</th>
                <th className="p-4">AWS Region</th>
                <th className="p-4">Risk Rating</th>
                <th className="p-4">Status</th>
                <th className="p-4">Owner</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-enterprise-border text-xs text-gray-200">
              {filteredResources.length > 0 ? (
                filteredResources.map((res) => {
                  const typeCfg = typeIcons[res.type] || { icon: FileText, color: 'text-white' };
                  return (
                    <tr key={res.arn} className="hover:bg-gray-800/10 transition-colors">
                      <td className="p-4">
                        <div className="flex flex-col gap-1 min-w-[200px]">
                          <span className="font-bold text-white text-xs">{res.name}</span>
                          <span className="text-[10px] text-enterprise-subtext font-mono truncate max-w-[300px]">
                            {res.arn}
                          </span>
                        </div>
                      </td>
                      <td className="p-4">
                        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-bold border inline-flex ${typeCfg.color}`}>
                          <typeCfg.icon className="w-3.5 h-3.5" />
                          <span>{res.type}</span>
                        </div>
                      </td>
                      <td className="p-4 font-mono text-[10px] text-gray-300">{formatRegion(res.region)}</td>
                      <td className="p-4">
                        <div className="flex items-center gap-2">
                          <span className="font-bold">{res.riskScore}</span>
                          <div className="w-16 bg-gray-800 h-1.5 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                res.riskScore >= 80
                                  ? 'bg-enterprise-critical'
                                  : res.riskScore >= 50
                                  ? 'bg-enterprise-warning'
                                  : 'bg-enterprise-success'
                              }`}
                              style={{ width: `${res.riskScore}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="p-4">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${getStatusBadgeClass(res.status)}`}>
                          {res.status}
                        </span>
                      </td>
                      <td className="p-4 text-enterprise-subtext font-medium">{res.owner}</td>
                      <td className="p-4 text-right">
                        <button
                          onClick={() => { setInspectResource(res); setCopied(false); }}
                          className="px-2.5 py-1.5 hover:bg-gray-800 hover:text-white text-enterprise-accent font-semibold rounded transition-colors text-[10px]"
                        >
                          View JSON Configuration
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="text-center p-8 text-enterprise-subtext font-medium text-xs">
                    {selectedType === 'EC2' ? (
                      <div>
                        <p className="text-white font-semibold">No running EC2 instances discovered.</p>
                        <p className="text-[11px] text-enterprise-subtext mt-1">
                          Only instances in the <code className="text-enterprise-success bg-enterprise-bg px-1 py-0.5 rounded">running</code> state are tracked in the security ledger. Stopped and terminated instances are excluded.
                        </p>
                      </div>
                    ) : (
                      'No resources matched the active filters.'
                    )}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* JSON Configuration Modal */}
      {inspectResource && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={() => setInspectResource(null)}
        >
          <div
            className="relative w-full max-w-2xl mx-4 bg-enterprise-card border border-enterprise-border rounded-2xl shadow-2xl flex flex-col max-h-[80vh] overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-enterprise-border bg-enterprise-bg/40">
              <div>
                <h3 className="text-sm font-bold text-white">{inspectResource.name}</h3>
                <p className="text-[10px] text-enterprise-subtext mt-0.5 font-mono">{inspectResource.arn}</p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopy}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 hover:bg-gray-800 text-enterprise-subtext hover:text-white rounded-lg transition-colors text-xs"
                  title="Copy JSON"
                >
                  {copied
                    ? <Check className="w-3.5 h-3.5 text-enterprise-success" />
                    : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
                <button
                  onClick={() => setInspectResource(null)}
                  className="p-1.5 hover:bg-gray-800 text-enterprise-subtext hover:text-white rounded-lg transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
            {/* Modal Body */}
            <div className="overflow-y-auto flex-1 p-5">
              <pre className="text-[11px] font-mono text-gray-300 leading-relaxed select-text whitespace-pre-wrap">
                {JSON.stringify(inspectResource, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
