import { useState, useRef, useEffect, useMemo, useCallback } from 'react';
import type { FC } from 'react';
import { useLocation } from 'react-router-dom';
import { IdentityGraph } from '../components/IdentityGraph';
import type { AnalystMode } from '../components/IdentityGraph';
import { NodeDetailsPanel } from '../components/NodeDetailsPanel';
import type { NodeData, EdgeData } from '../components/NodeDetailsPanel';
import { 
  Network, Search, Maximize, RefreshCw, 
  AlertTriangle, Info, ChevronRight, Filter, 
  Target, ChevronLeft, Key, Sparkles, GitCompare, Database,
  Compass
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getGraphElements } from '../api/graph';
import { getRiskAssessmentFindings } from '../api/risks';
import { getSimulationDiff } from '../api/simulation';
import { getAttackPaths } from '../api/attack';
import { ScannedRegionBadge } from '../components/ScannedRegionBadge';
import type { AttackPath } from '../types';

export const IdentityGraphPage: FC = () => {
  const location = useLocation();
  const searchParams = new URLSearchParams(location.search);
  const highlightParam = searchParams.get('highlight');
  const highlightedNodeIds = useMemo(() => highlightParam ? highlightParam.split(',').map(id => id.trim()).filter(Boolean) : [], [highlightParam]);

  // Selections
  const [selectedNode, setSelectedNode] = useState<NodeData | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<EdgeData | null>(null);

  // Modes & Controls
  const [analystMode, setAnalystMode] = useState<AnalystMode>(
    highlightedNodeIds.length > 0 ? 'attack_path' : 'identity_overview'
  );
  const [selectedIdentityId, setSelectedIdentityId] = useState<string | null>(null);
  const [selectedResourceId, setSelectedResourceId] = useState<string | null>(null);
  const [showPolicies, setShowPolicies] = useState(false);
  const [activeAttackPathIndex, setActiveAttackPathIndex] = useState(0);

  // General display settings
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [showLabels, setShowLabels] = useState(true);
  const [showEdgeLabels, setShowEdgeLabels] = useState(true);
  const [highlightRisky, setHighlightRisky] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [graphMode, setGraphMode] = useState<'current' | 'desired' | 'diff'>('diff');

  const pageRef = useRef<HTMLDivElement>(null);

  // Data queries
  const { data: elements } = useQuery({ queryKey: ['graphElements'], queryFn: getGraphElements });
  const { data: risks } = useQuery({ queryKey: ['risk-assessment'], queryFn: getRiskAssessmentFindings });
  const { data: attackPaths, isLoading: attackPathsLoading, isError: attackPathsError } = useQuery<AttackPath[]>({ queryKey: ['attackPaths'], queryFn: getAttackPaths });
  const { data: simDiff } = useQuery({
    queryKey: ['simulation-diff'],
    queryFn: getSimulationDiff,
    refetchInterval: 5000,
  });

  const isSimActive = Boolean(simDiff?.simulation_active && (simDiff?.pending_changes ?? 0) > 0);
  const safeAttackPathIndex = attackPaths?.length ? Math.min(activeAttackPathIndex, attackPaths.length - 1) : 0;

  // Extract IAM identities for Quick-Focus picker
  const identityOptions = useMemo(() => {
    if (!elements) return [];
    return elements
      .filter((el: any) => {
        if (el.data.source) return false;
        const t = (el.data.type || '').toLowerCase();
        return t === 'user' || t === 'group' || t === 'role';
      })
      .map((el: any) => ({
        id: el.data.id,
        label: el.data.label || el.data.id,
        type: el.data.type || 'Identity'
      }))
      .sort((a, b) => a.label.localeCompare(b.label));
  }, [elements]);

  // Extract all cloud resources for Resource Detail mode picker
  const resourceOptions = useMemo(() => {
    if (!elements) return [];
    return elements
      .filter((el: any) => {
        if (el.data.source) return false;
        const t = (el.data.type || '').toLowerCase();
        return t !== 'user' && t !== 'group' && t !== 'role' && t !== 'policy';
      })
      .map((el: any) => ({
        id: el.data.id,
        label: el.data.label || el.data.id,
        type: el.data.type || 'Resource'
      }))
      .sort((a, b) => a.label.localeCompare(b.label));
  }, [elements]);

  const activeFocusedEntity = useMemo(() => {
    const focusId = selectedIdentityId || selectedResourceId || selectedNode?.id;
    if (!focusId || !elements) return null;
    const n = elements.find((el: any) => !el.data.source && el.data.id === focusId);
    if (!n) return null;
    const t = n.data.type || 'Resource';
    const isIdentity = t === 'User' || t === 'Group' || t === 'Role' || t === 'Policy';
    return {
      id: focusId,
      label: n.data.label || focusId,
      type: t,
      isIdentity
    };
  }, [selectedIdentityId, selectedResourceId, selectedNode, elements]);

  const handleClearFocus = useCallback(() => {
    setSelectedIdentityId(null);
    setSelectedResourceId(null);
    setSelectedNode(null);
    setSelectedEdge(null);
    window.dispatchEvent(new CustomEvent('graph:reset'));
  }, []);

  const handleNodeSelect = useCallback((node: NodeData | null) => {
    setSelectedNode(node);
    if (node) {
      setSelectedEdge(null);
      setSelectedIdentityId(null);
      setSelectedResourceId(null);
    }
  }, []);

  const handleEdgeSelect = useCallback((edge: EdgeData | null) => {
    setSelectedEdge(edge);
    if (edge) {
      setSelectedNode(null);
      setSelectedIdentityId(null);
      setSelectedResourceId(null);
    }
  }, []);

  // Compute diff elements combining baseline current with graph diff
  const diffElements = useMemo(() => {
    if (!elements || !simDiff?.graph_diff) return elements || [];

    const graphDiff = simDiff.graph_diff;
    const removedNodeIds = new Set((graphDiff.removed_nodes || []).map((n: any) => n.id));
    const removedEdgeKeys = new Set(
      (graphDiff.removed_edges || []).map((e: any) => `${e.source}|${e.target}|${e.label || ''}`)
    );

    const result: any[] = [];
    const seenNodeIds = new Set<string>();

    (elements || []).forEach((el: any) => {
      if (!el.data.source) {
        seenNodeIds.add(el.data.id);
        const isRemoved = removedNodeIds.has(el.data.id);
        result.push({
          ...el,
          data: {
            ...el.data,
            diffStatus: isRemoved ? 'removed' : undefined,
          },
          classes: isRemoved ? `${el.classes || ''} diff-removed`.trim() : el.classes,
        });
      } else {
        const key = `${el.data.source}|${el.data.target}|${el.data.label || ''}`;
        const isRemoved = removedEdgeKeys.has(key);
        result.push({
          ...el,
          data: {
            ...el.data,
            diffStatus: isRemoved ? 'removed' : undefined,
          },
          classes: isRemoved ? `${el.classes || ''} diff-removed`.trim() : el.classes,
        });
      }
    });

    (graphDiff.added_nodes || []).forEach((n: any) => {
      if (!seenNodeIds.has(n.id)) {
        seenNodeIds.add(n.id);
        const desiredNode = (simDiff.desired_elements || []).find((de: any) => !de.data.source && de.data.id === n.id);
        result.push({
          data: {
            ...(desiredNode?.data || {}),
            id: n.id,
            label: n.label || n.id,
            type: n.type || 'Resource',
            diffStatus: 'added',
          },
          classes: 'diff-added',
        });
      }
    });

    (graphDiff.added_edges || []).forEach((e: any) => {
      result.push({
        data: {
          id: `diff-edge-${e.source}-${e.target}-${e.label || 'edge'}`,
          source: e.source,
          target: e.target,
          label: e.label || '',
          diffStatus: 'added',
        },
        classes: 'diff-added',
      });
    });

    return result;
  }, [elements, simDiff]);

  const activeElements = useMemo(() => {
    if (!isSimActive) return elements;
    if (graphMode === 'current') return elements;
    if (graphMode === 'desired') return simDiff?.desired_elements || elements;
    if (graphMode === 'diff') return diffElements;
    return elements;
  }, [isSimActive, graphMode, elements, simDiff, diffElements]);

  // Active attack path node list
  const activeAttackPathNodes = useMemo(() => {
    if (highlightedNodeIds.length > 0) return highlightedNodeIds;
    if (!attackPaths || attackPaths.length === 0) return [];
    const p = attackPaths[safeAttackPathIndex] || attackPaths[0];
    return p?.nodes?.map(n => n.id) || [];
  }, [highlightedNodeIds, attackPaths, safeAttackPathIndex]);

  const selectedAttackPath = useMemo(() => {
    if (!attackPaths?.length) return null;
    if (highlightedNodeIds.length > 0) {
      return attackPaths.find(path => path.nodes?.length === highlightedNodeIds.length && path.nodes.every((node, index) => node.id === highlightedNodeIds[index])) || null;
    }
    return attackPaths[safeAttackPathIndex] || null;
  }, [attackPaths, highlightedNodeIds, safeAttackPathIndex]);
  const pathGraphIncomplete = useMemo(() => {
    if (!activeAttackPathNodes.length || !elements) return false;
    const graphNodes = new Set(elements.filter((element: any) => !element.data.source).map((element: any) => element.data.id));
    const graphEdges = elements.filter((element: any) => element.data.source);
    return activeAttackPathNodes.some(id => !graphNodes.has(id)) || activeAttackPathNodes.some((id, index) =>
      index < activeAttackPathNodes.length - 1 && !graphEdges.some((edge: any) => edge.data.source === id && edge.data.target === activeAttackPathNodes[index + 1])
    );
  }, [activeAttackPathNodes, elements]);

  // Compute node stats
  const nodes = (activeElements || elements)?.filter((e: any) => !e.data.source) || [];
  const edges = (activeElements || elements)?.filter((e: any) => e.data.source) || [];
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
    <div ref={pageRef} className="flex flex-col flex-1 min-h-0 bg-[#0B1120] text-gray-200 font-sans overflow-hidden">
      
      {/* HEADER BAR */}
      {!isFullscreen && (
        <header className="flex flex-wrap items-center justify-between px-6 py-3 border-b border-gray-800 bg-[#0F172A] shrink-0 gap-3 z-30">
          <div className="flex items-center gap-4">
            <div>
              <h1 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                <Network className="w-5 h-5 text-blue-500" />
                <span>Identity Graph</span>
              </h1>
              <p className="text-[11px] text-gray-400">
                Analyst-Centric Cloud Authorization Architecture (Users / Groups → Roles → Resources)
              </p>
            </div>

            {/* THREE GRAPH MODES SELECTOR */}
            <div className="hidden lg:flex items-center bg-gray-900 border border-gray-700/80 p-0.5 rounded-lg shadow-inner">
              <button
                onClick={() => {
                  setAnalystMode('identity_overview');
                  setSelectedResourceId(null);
                }}
                className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold transition-all ${
                  analystMode === 'identity_overview'
                    ? 'bg-blue-600 text-white shadow-md'
                    : 'text-gray-400 hover:text-white hover:bg-gray-800'
                }`}
              >
                <Compass className="w-3.5 h-3.5" />
                <span>Identity Overview</span>
              </button>

              <button
                onClick={() => {
                  setAnalystMode('resource_detail');
                  if (!selectedResourceId && resourceOptions.length > 0) {
                    setSelectedResourceId(resourceOptions[0].id);
                  }
                }}
                className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold transition-all ${
                  analystMode === 'resource_detail'
                    ? 'bg-emerald-600 text-white shadow-md'
                    : 'text-gray-400 hover:text-white hover:bg-gray-800'
                }`}
              >
                <Database className="w-3.5 h-3.5" />
                <span>Resource Detail</span>
              </button>

              <button
                onClick={() => setAnalystMode('attack_path')}
                className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold transition-all ${
                  analystMode === 'attack_path'
                    ? 'bg-red-600 text-white shadow-md'
                    : 'text-gray-400 hover:text-white hover:bg-gray-800'
                }`}
              >
                <Target className="w-3.5 h-3.5" />
                <span>Attack Path</span>
              </button>
            </div>
          </div>
          
          <div className="flex flex-wrap items-center gap-2.5">
            <ScannedRegionBadge />

            {/* Simulation State Toggle */}
            {isSimActive && (
              <div className="flex items-center bg-gray-900 border border-indigo-500/50 p-0.5 rounded-lg text-xs">
                <div className="flex items-center gap-1 px-1.5 py-0.5 text-[11px] font-semibold text-indigo-400">
                  <Sparkles className="w-3 h-3 text-indigo-400 animate-pulse" />
                  <span className="hidden sm:inline">Sim</span>
                </div>
                <button
                  onClick={() => setGraphMode('current')}
                  className={`px-2 py-0.5 rounded ${graphMode === 'current' ? 'bg-blue-600 text-white font-bold' : 'text-gray-400 hover:text-white'}`}
                >
                  Current
                </button>
                <button
                  onClick={() => setGraphMode('desired')}
                  className={`px-2 py-0.5 rounded ${graphMode === 'desired' ? 'bg-purple-600 text-white font-bold' : 'text-gray-400 hover:text-white'}`}
                >
                  Desired
                </button>
                <button
                  onClick={() => setGraphMode('diff')}
                  className={`flex items-center gap-1 px-2 py-0.5 rounded ${graphMode === 'diff' ? 'bg-emerald-600 text-white font-bold' : 'text-gray-400 hover:text-white'}`}
                >
                  <GitCompare className="w-3 h-3" />
                  Diff
                </button>
              </div>
            )}

            {/* Mode Specific Controls */}
            {analystMode === 'identity_overview' && identityOptions.length > 0 && (
              <div className="flex items-center gap-1.5 bg-gray-900 border border-blue-500/50 px-2 py-1 rounded-lg">
                <span className="text-[10px] uppercase font-bold text-blue-400">Identity:</span>
                <select
                  value={selectedIdentityId || ''}
                  onChange={(e) => setSelectedIdentityId(e.target.value || null)}
                  className="bg-transparent text-xs text-white focus:outline-none max-w-[180px] font-mono"
                >
                  <option value="" className="bg-gray-900 text-gray-400">All (Complete Graph)</option>
                  {identityOptions.map(i => (
                    <option key={i.id} value={i.id} className="bg-gray-900 text-white">
                      {i.label} ({i.type})
                    </option>
                  ))}
                </select>
              </div>
            )}

            {analystMode === 'resource_detail' && (
              <div className="flex items-center gap-1.5 bg-gray-900 border border-emerald-500/50 px-2 py-1 rounded-lg">
                <span className="text-[10px] uppercase font-bold text-emerald-400">Asset:</span>
                <select
                  value={selectedResourceId || ''}
                  onChange={(e) => setSelectedResourceId(e.target.value || null)}
                  className="bg-transparent text-xs text-white focus:outline-none max-w-[180px] font-mono"
                >
                  <option value="" className="bg-gray-900 text-gray-400">All (Complete Graph)</option>
                  {resourceOptions.map(r => (
                    <option key={r.id} value={r.id} className="bg-gray-900 text-white">
                      {r.label} ({r.type})
                    </option>
                  ))}
                </select>
              </div>
            )}

            {analystMode === 'attack_path' && (
              <div className="flex items-center gap-1.5 bg-gray-900 border border-red-500/50 px-2 py-1 rounded-lg">
                <span className="text-[10px] uppercase font-bold text-red-400">Path:</span>
                <select
                  value={safeAttackPathIndex}
                  onChange={(e) => setActiveAttackPathIndex(Number(e.target.value))}
                  disabled={!attackPaths?.length || attackPathsLoading || attackPathsError}
                  className="bg-transparent text-xs text-white focus:outline-none max-w-[200px] disabled:opacity-50"
                >
                  {attackPaths?.map((p, idx) => (
                    <option key={idx} value={idx} className="bg-gray-900 text-white">
                      Path {idx + 1}: {p.nodes?.[0]?.name || p.nodes?.[0]?.id || 'Source'} → {p.nodes?.[p.nodes.length - 1]?.name || p.nodes?.[p.nodes.length - 1]?.id || 'Target'}
                    </option>
                  ))}
                  {!attackPaths?.length && <option value={0}>{attackPathsLoading ? 'Loading verified paths…' : attackPathsError ? 'Path data unavailable' : 'No verified paths'}</option>}
                </select>
              </div>
            )}



            {/* Policy Diamonds Toggle Button */}
            <button
              onClick={() => setShowPolicies(prev => !prev)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
                showPolicies
                  ? 'bg-teal-600 text-white border-teal-500 shadow-md shadow-teal-500/20'
                  : 'bg-gray-900 hover:bg-gray-800 text-teal-400 border-gray-700'
              }`}
              title={showPolicies ? "Displaying raw intermediate IAM policy nodes" : "Using clean aggregated effective-access relationships"}
            >
              <Key className="w-3.5 h-3.5 text-teal-400" />
              <span>{showPolicies ? 'Policies: Diamonds Visible' : 'Policies: Aggregated'}</span>
            </button>

            {/* Search Input */}
            <div className="relative hidden md:flex items-center">
              <Search className="w-4 h-4 absolute left-3 text-gray-500" />
              <input 
                type="text" 
                placeholder="Search principal, role, asset..." 
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-gray-900 border border-gray-700 text-xs rounded-lg pl-9 pr-3 py-1.5 focus:outline-none focus:border-blue-500 w-52 text-white placeholder-gray-500"
              />
            </div>


            
            <button 
              onClick={handleClearFocus}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-xs font-medium transition-colors"
              title="Show complete cloud graph and clear focus dimming"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Show All
            </button>
            
            <button onClick={toggleFullscreen} className="flex items-center justify-center p-1.5 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-sm font-medium transition-colors" title="Toggle Fullscreen">
              <Maximize className="w-4 h-4" />
            </button>
          </div>
        </header>
      )}

      {/* Attack Path Prominent Summary Banner */}
      {analystMode === 'attack_path' && activeAttackPathNodes.length > 0 && (
        <div className="bg-red-950/90 border-b border-red-800 px-6 py-2.5 flex items-center justify-between z-20 backdrop-blur-md shadow-lg">
          <div className="flex items-center gap-3">
            <Target className="w-4 h-4 text-red-400 shrink-0" />
            <div className="flex items-center gap-2 text-xs">
              <span className="font-bold text-red-200 tracking-wide uppercase text-[10px]">Verified Attack Path:</span>
              <span className="font-mono text-white font-bold">{selectedAttackPath?.nodes?.[0]?.name || activeAttackPathNodes[0]}</span>
              <span className="text-red-400 font-bold">→</span>
              <span className="font-mono text-red-200 font-bold">{selectedAttackPath?.nodes?.[activeAttackPathNodes.length - 1]?.name || activeAttackPathNodes[activeAttackPathNodes.length - 1]}</span>
              <span className="text-gray-400 text-[11px]">({Math.max(0, activeAttackPathNodes.length - 1)} transitions)</span>
              {pathGraphIncomplete && <span className="text-amber-300 text-[10px]">Some path transitions are not visible in this graph view.</span>}
            </div>
          </div>
          <span className={`px-2.5 py-0.5 rounded text-[10px] font-black uppercase tracking-wider shadow ${selectedAttackPath?.severity === 'critical' ? 'bg-red-600 text-white' : selectedAttackPath?.severity === 'high' ? 'bg-orange-600 text-white' : selectedAttackPath?.severity === 'medium' ? 'bg-amber-500 text-black' : selectedAttackPath?.severity === 'low' ? 'bg-emerald-700 text-white' : 'bg-gray-700 text-gray-200'}`}>
            {selectedAttackPath?.severity || 'HIGHLIGHTED'}
          </span>
        </div>
      )}
      {analystMode === 'attack_path' && activeAttackPathNodes.length === 0 && (
        <div className={`border-b px-6 py-2 text-xs ${attackPathsError ? 'border-amber-800 bg-amber-950/40 text-amber-200' : 'border-gray-800 bg-gray-900/50 text-gray-300'}`} role={attackPathsError ? 'alert' : 'status'}>
          {attackPathsLoading ? 'Loading verified attack paths…' : attackPathsError ? 'Attack path data could not be loaded. Retry the page to refresh the published graph data.' : 'No verified attack paths are available in the current published snapshot.'}
        </div>
      )}

      {/* Active Focus Spotlight Banner */}
      {activeFocusedEntity && (
        <div className="bg-blue-950/80 border-b border-blue-800/80 px-6 py-2 flex items-center justify-between z-20 backdrop-blur-md shadow-md">
          <div className="flex items-center gap-2.5 text-xs">
            <span className="w-2 h-2 rounded-full bg-blue-400 animate-ping shrink-0" />
            <span className="font-semibold text-blue-200">
              Focusing <strong className="text-white font-mono">{activeFocusedEntity.label}</strong> ({activeFocusedEntity.type})
            </span>
            <span className="text-gray-400 text-[11px] hidden sm:inline">
              — {activeFocusedEntity.isIdentity ? 'Reachable access path highlighted. Unrelated cloud resources dimmed.' : 'Inbound access path highlighted. Unrelated cloud resources dimmed.'}
            </span>
          </div>
          <button
            onClick={handleClearFocus}
            className="px-2.5 py-0.5 bg-blue-600/30 hover:bg-blue-600/50 text-blue-200 border border-blue-500/40 rounded text-xs font-medium transition-all"
          >
            Clear Focus (Show All)
          </button>
        </div>
      )}

      {/* MAIN CONTENT AREA */}
      <main className="flex-1 flex overflow-hidden min-h-0 relative">
        
        {/* GRAPH CANVAS */}
        <div className="flex-1 relative flex flex-col min-w-0">
          <IdentityGraph 
            onNodeSelect={handleNodeSelect}
            onEdgeSelect={handleEdgeSelect}
            selectedIdentityId={selectedIdentityId}
            selectedResourceId={selectedResourceId}
            highlightedNodeIds={activeAttackPathNodes}
            searchQuery={searchQuery}
            showLabels={showLabels}
            showEdgeLabels={showEdgeLabels}
            highlightRisky={highlightRisky}
            showPolicies={showPolicies}
            analystMode={analystMode}
            customElements={isSimActive ? activeElements : undefined}
            activeAttackPath={activeAttackPathNodes}
            onClearFocus={handleClearFocus}
          />

          {/* Unified Node & Edge Details Side Overlay */}
          {(selectedNode || selectedEdge) && (
            <div className="absolute top-4 right-4 z-20 shadow-2xl h-[calc(100%-2rem)] w-96 rounded-xl border border-gray-700 bg-gray-900/95 backdrop-blur-xl flex flex-col overflow-hidden animate-in slide-in-from-right duration-200">
              <NodeDetailsPanel 
                nodeData={selectedNode}
                edgeData={selectedEdge}
                onClose={() => {
                  setSelectedNode(null);
                  setSelectedEdge(null);
                }}
              />
            </div>
          )}

          {/* Toggle Button for Collapsible Right Sidebar */}
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

            {/* Display Settings */}
            <div className="p-5">
              <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                <Filter className="w-4 h-4 text-blue-400" />
                <span>Display Settings</span>
              </h3>
              
              <div className="space-y-3">
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input type="checkbox" checked={showLabels} onChange={(e) => setShowLabels(e.target.checked)} className="rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-blue-600" />
                  <span className="text-xs text-gray-300">Show Node Labels</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input type="checkbox" checked={showEdgeLabels} onChange={(e) => setShowEdgeLabels(e.target.checked)} className="rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-blue-600" />
                  <span className="text-xs text-gray-300">Show Relationship Labels</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input type="checkbox" checked={highlightRisky} onChange={(e) => setHighlightRisky(e.target.checked)} className="rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-blue-600" />
                  <span className="text-xs text-gray-300">Highlight Risky Paths</span>
                </label>
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
