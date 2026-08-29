import { useState, useRef, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { IdentityGraph } from '../components/IdentityGraph';
import { NodeDetailsPanel } from '../components/NodeDetailsPanel';
import { 
  Network, Search, Maximize, RefreshCw, 
  AlertTriangle, Info, ChevronDown, ChevronRight, ShieldAlert, Filter, 
  Target, ChevronLeft
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getGraphElements } from '../api/graph';
import { getRiskAssessmentFindings } from '../api/risks';
import { ScannedRegionBadge } from '../components/ScannedRegionBadge';

export const IdentityGraphPage: React.FC = () => {
  const location = useLocation();
  const searchParams = new URLSearchParams(location.search);
  const highlightParam = searchParams.get('highlight');
  const highlightedNodeIds = highlightParam ? highlightParam.split(',') : [];

  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [securityFilter, setSecurityFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low' | 'attack_paths_only'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [showLabels, setShowLabels] = useState(true);
  const [showEdgeLabels, setShowEdgeLabels] = useState(false);
  const [highlightRisky, setHighlightRisky] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false); // Collapsed by default to maximize graph space
  
  const pageRef = useRef<HTMLDivElement>(null);

  const { data: elements } = useQuery({ queryKey: ['graphElements'], queryFn: getGraphElements });
  const { data: risks } = useQuery({ queryKey: ['risk-assessment'], queryFn: getRiskAssessmentFindings });

  // Compute stats
  const nodes = elements?.filter(e => !e.data.source) || [];
  const edges = elements?.filter(e => e.data.source) || [];
  const totalNodes = nodes.length;
  const totalEdges = edges.length;
  
  const counts = {
    User: 0,
    Group: 0,
    Role: 0,
    Policy: 0,
    S3: 0,
    EC2: 0,
    Lambda: 0,
    RDS: 0,
    DynamoDB: 0,
    Secrets: 0
  };
  
  nodes.forEach((n: any) => {
    const t = n.data.type || 'Resource';
    if (counts[t as keyof typeof counts] !== undefined) {
      counts[t as keyof typeof counts]++;
    } else if (t === 'Secret') {
      counts.Secrets++;
    }
  });

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      pageRef.current?.requestFullscreen().catch(err => {
        console.error(`Error attempting to enable fullscreen mode: ${err.message}`);
      });
    } else {
      document.exitFullscreen();
    }
  };

  useEffect(() => {
    const handleFsChange = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', handleFsChange);
    return () => document.removeEventListener('fullscreenchange', handleFsChange);
  }, []);

  return (
    <div ref={pageRef} className="flex flex-col h-full min-h-screen bg-[#0B1120] text-gray-200 font-sans overflow-hidden">
      
      {/* HEADER BAR */}
      {!isFullscreen && (
        <header className="flex items-center justify-between px-6 py-3.5 border-b border-gray-800 bg-[#0F172A] shrink-0">
          <div>
            <h1 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
              <Network className="w-5 h-5 text-blue-500" />
              <span>Identity Graph</span>
            </h1>
            <p className="text-[11px] text-gray-400">Security Architecture (Users → Groups → Policies → Roles → Resources → Sensitive Assets)</p>
          </div>
          
          <div className="flex items-center gap-3">
            <ScannedRegionBadge />

            {/* Attack Path Quick Filter Button */}
            <button
              onClick={() => setSecurityFilter(prev => prev === 'attack_paths_only' ? 'all' : 'attack_paths_only')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
                securityFilter === 'attack_paths_only'
                  ? 'bg-red-600 text-white border-red-500 shadow-lg shadow-red-500/20'
                  : 'bg-gray-900 hover:bg-gray-800 text-gray-300 border-gray-700'
              }`}
            >
              <Target className="w-3.5 h-3.5 text-red-400" />
              <span>Attack Paths</span>
            </button>

            {/* Search Input */}
            <div className="relative hidden md:flex items-center">
              <Search className="w-4 h-4 absolute left-3 text-gray-500" />
              <input 
                type="text" 
                placeholder="Search user, group, role, resource, ARN..." 
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-gray-900 border border-gray-700 text-xs rounded-lg pl-9 pr-3 py-1.5 focus:outline-none focus:border-blue-500 w-64 transition-colors text-white placeholder-gray-500"
              />
            </div>

            {/* Security Severity Filter */}
            <div className="relative group">
              <button className="flex items-center gap-2 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-xs font-medium transition-colors">
                <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                <span className="capitalize">{securityFilter.replace('_', ' ')}</span>
                <ChevronDown className="w-3 h-3 text-gray-400" />
              </button>
              <div className="absolute right-0 mt-2 w-48 bg-gray-900 border border-gray-700 rounded-lg shadow-xl opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-50">
                <div className="p-1">
                  <button onClick={() => setSecurityFilter('all')} className={`w-full text-left px-3 py-2 text-xs rounded-md hover:bg-gray-800 ${securityFilter === 'all' ? 'text-blue-400 font-semibold' : 'text-gray-300'}`}>All Severities</button>
                  <button onClick={() => setSecurityFilter('critical')} className={`w-full text-left px-3 py-2 text-xs rounded-md hover:bg-gray-800 ${securityFilter === 'critical' ? 'text-red-400 font-semibold' : 'text-gray-300'}`}>Critical (≥80)</button>
                  <button onClick={() => setSecurityFilter('high')} className={`w-full text-left px-3 py-2 text-xs rounded-md hover:bg-gray-800 ${securityFilter === 'high' ? 'text-amber-400 font-semibold' : 'text-gray-300'}`}>High (≥60)</button>
                  <button onClick={() => setSecurityFilter('medium')} className={`w-full text-left px-3 py-2 text-xs rounded-md hover:bg-gray-800 ${securityFilter === 'medium' ? 'text-yellow-400 font-semibold' : 'text-gray-300'}`}>Medium (40-59)</button>
                  <button onClick={() => setSecurityFilter('low')} className={`w-full text-left px-3 py-2 text-xs rounded-md hover:bg-gray-800 ${securityFilter === 'low' ? 'text-green-400 font-semibold' : 'text-gray-300'}`}>Low (&lt;40)</button>
                  <button onClick={() => setSecurityFilter('attack_paths_only')} className={`w-full text-left px-3 py-2 text-xs rounded-md hover:bg-gray-800 ${securityFilter === 'attack_paths_only' ? 'text-red-500 font-bold' : 'text-gray-300'}`}>Attack Paths Only</button>
                </div>
              </div>
            </div>
            
            <button onClick={() => window.dispatchEvent(new CustomEvent('graph:reset'))} className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-xs font-medium transition-colors">
              <RefreshCw className="w-3.5 h-3.5" /> Reset View
            </button>
            
            <button onClick={toggleFullscreen} className="flex items-center justify-center p-1.5 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-sm font-medium transition-colors" title="Toggle Fullscreen">
              <Maximize className="w-4 h-4" />
            </button>
          </div>
        </header>
      )}

      {/* Attack Path Prominent Summary Banner */}
      {highlightedNodeIds.length > 0 && (
        <div className="bg-red-950/90 border-b border-red-800 px-6 py-2.5 flex items-center justify-between z-20 backdrop-blur-md shadow-lg">
          <div className="flex items-center gap-3">
            <Target className="w-4 h-4 text-red-400 shrink-0" />
            <div className="flex items-center gap-2 text-xs">
              <span className="font-bold text-red-200 tracking-wide uppercase text-[10px]">Identified Lateral Attack Path:</span>
              <span className="font-mono text-white font-bold">{highlightedNodeIds[0]}</span>
              <span className="text-red-400 font-bold">→</span>
              <span className="font-mono text-red-200 font-bold">{highlightedNodeIds[highlightedNodeIds.length - 1]}</span>
              <span className="text-gray-400 text-[11px]">({highlightedNodeIds.length} hops)</span>
            </div>
          </div>
          <span className="px-2.5 py-0.5 rounded text-[10px] font-black bg-red-600 text-white uppercase tracking-wider shadow">HIGH RISK</span>
        </div>
      )}

      {/* MAIN CONTENT */}
      <main className="flex-1 flex overflow-hidden min-h-0 relative">
        
        {/* GRAPH CANVAS AREA */}
        <div className="flex-1 relative flex flex-col min-w-0">
          <IdentityGraph 
            onNodeSelect={setSelectedNode} 
            highlightedNodeIds={highlightedNodeIds}
            searchQuery={searchQuery}
            showLabels={showLabels}
            showEdgeLabels={showEdgeLabels}
            highlightRisky={highlightRisky}
            securityFilter={securityFilter}
          />

          {/* Node Details Overlay */}
          {selectedNode && (
            <div className="absolute top-4 right-4 z-20 shadow-2xl h-[calc(100%-2rem)] w-96 rounded-xl border border-gray-700 bg-gray-900/95 backdrop-blur-xl flex flex-col overflow-hidden">
              <NodeDetailsPanel nodeData={selectedNode} onClose={() => setSelectedNode(null)} />
            </div>
          )}

          {/* Toggle Button for Collapsible Sidebar */}
          {!isFullscreen && (
            <button
              onClick={() => setIsSidebarOpen(prev => !prev)}
              className="absolute top-4 right-4 z-10 p-2 bg-[#0F172A]/90 hover:bg-gray-800 text-gray-400 hover:text-white border border-gray-700 rounded-lg shadow-xl backdrop-blur-md transition-colors"
              title={isSidebarOpen ? "Hide Security Sidebar" : "Show Security Sidebar"}
            >
              {isSidebarOpen ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
            </button>
          )}
        </div>

        {/* COLLAPSIBLE RIGHT SIDEBAR */}
        {!isFullscreen && isSidebarOpen && (
          <aside className="w-80 bg-[#111827] border-l border-gray-800 flex flex-col overflow-y-auto shrink-0 custom-scrollbar z-10 animate-in slide-in-from-right duration-200">
          
          {/* Recommended Fixes */}
          <div className="p-5 border-b border-gray-800">
            <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-500" />
              <span>Recommended Fixes</span>
            </h3>
            <div className="space-y-3">
              {risks?.map((risk: any, i: number) => (
                <div key={i} className="p-3 bg-gray-900 border border-gray-800 rounded-lg">
                  <div className="flex items-start gap-2">
                    {risk.severity === 'Critical' || risk.severity === 'High' ? (
                      <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                    ) : (
                      <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                    )}
                    <div>
                      <h4 className="text-xs font-semibold text-gray-200">{risk.title || risk.identity || 'Security Finding'}</h4>
                      <p className="text-[10px] text-gray-400 mt-1 leading-snug">{risk.description || risk.recommendation || risk.issue}</p>
                    </div>
                  </div>
                </div>
              ))}
              {(!risks || risks.length === 0) && (
                <p className="text-xs text-gray-500 italic">No critical risks detected.</p>
              )}
            </div>
          </div>

          {/* Graph Display Settings */}
          <div className="p-5">
            <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
              <Filter className="w-4 h-4 text-blue-400" />
              <span>Graph Display Settings</span>
            </h3>
            
            <div className="space-y-4">
              <div className="space-y-2.5">
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input type="checkbox" checked={showLabels} onChange={(e) => setShowLabels(e.target.checked)} className="rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-blue-600 focus:ring-offset-gray-900" />
                  <span className="text-xs text-gray-300">Show Node Labels</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input type="checkbox" checked={showEdgeLabels} onChange={(e) => setShowEdgeLabels(e.target.checked)} className="rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-blue-600 focus:ring-offset-gray-900" />
                  <span className="text-xs text-gray-300">Show Relationship Labels</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input type="checkbox" checked={highlightRisky} onChange={(e) => setHighlightRisky(e.target.checked)} className="rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-blue-600 focus:ring-offset-gray-900" />
                  <span className="text-xs text-gray-300">Highlight Risky Paths</span>
                </label>
              </div>
            </div>
          </div>
        </aside>
        )}
      </main>

      {/* FOOTER STATS BAR */}
      <footer className="flex items-center px-6 py-3 border-t border-gray-800 bg-[#0F172A] shrink-0 text-xs text-gray-400 gap-8 overflow-x-auto z-10">
        <div className="flex flex-col">
          <span className="text-gray-500 mb-0.5 text-[10px] uppercase font-bold tracking-wider">Total Nodes</span>
          <span className="text-white font-mono text-sm">{totalNodes}</span>
        </div>
        <div className="flex flex-col">
          <span className="text-gray-500 mb-0.5 text-[10px] uppercase font-bold tracking-wider">Total Relationships</span>
          <span className="text-white font-mono text-sm">{totalEdges}</span>
        </div>
        <div className="w-px h-8 bg-gray-800 mx-2" />
        <div className="flex items-center gap-6 font-medium">
          <div className="flex gap-1.5 items-baseline">
            <span className="text-blue-400">Users:</span>
            <span className="text-white font-mono">{counts.User}</span>
          </div>
          <div className="flex gap-1.5 items-baseline">
            <span className="text-indigo-400">Groups:</span>
            <span className="text-white font-mono">{counts.Group}</span>
          </div>
          <div className="flex gap-1.5 items-baseline">
            <span className="text-teal-400">Policies:</span>
            <span className="text-white font-mono">{counts.Policy}</span>
          </div>
          <div className="flex gap-1.5 items-baseline">
            <span className="text-purple-400">Roles:</span>
            <span className="text-white font-mono">{counts.Role}</span>
          </div>
          <div className="flex gap-1.5 items-baseline">
            <span className="text-amber-400">S3:</span>
            <span className="text-white font-mono">{counts.S3}</span>
          </div>
          <div className="flex gap-1.5 items-baseline">
            <span className="text-emerald-400">EC2:</span>
            <span className="text-white font-mono">{counts.EC2}</span>
          </div>
          <div className="flex gap-1.5 items-baseline">
            <span className="text-pink-400">Lambda:</span>
            <span className="text-white font-mono">{counts.Lambda}</span>
          </div>
          <div className="flex gap-1.5 items-baseline">
            <span className="text-sky-400">RDS:</span>
            <span className="text-white font-mono">{counts.RDS}</span>
          </div>
          <div className="flex gap-1.5 items-baseline">
            <span className="text-violet-400">DynamoDB:</span>
            <span className="text-white font-mono">{counts.DynamoDB}</span>
          </div>
          <div className="flex gap-1.5 items-baseline">
            <span className="text-red-400">Secrets:</span>
            <span className="text-white font-mono">{counts.Secrets}</span>
          </div>
        </div>
        <div className="w-px h-8 bg-gray-800 mx-2" />
        <div className="flex flex-col">
          <span className="text-red-500/70 mb-0.5 text-[10px] uppercase font-bold tracking-wider">Risky Findings</span>
          <span className="text-red-400 font-mono text-sm">{risks?.length || 0}</span>
        </div>
      </footer>
    </div>
  );
};
