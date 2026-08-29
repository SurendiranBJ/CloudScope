import { useState, useRef, useEffect, useMemo } from 'react';
import type { FC } from 'react';
import { useNavigate } from 'react-router-dom';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import {
  GitMerge,
  ArrowDown,
  Sparkles,
  RefreshCw,
  Bot,
  Terminal,
  ChevronDown,
  ChevronUp,
  Target,
  ShieldAlert,
  Search,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Layers,
  Flame,
  Radio,
  SlidersHorizontal,
  FolderGit2,
  Share2
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getAttackPaths } from '../api/attack';
import { postCopilotMessage } from '../api/copilot';
import { ScanTrigger } from '../components/ScanTrigger';
import { ScannedRegionBadge } from '../components/ScannedRegionBadge';
import type { AttackPath, AttackPathNode } from '../types';

// Register dagre layout
cytoscape.use(dagre);

export interface ConsolidatedAttackPathGroup {
  groupId: string;
  name: string;
  sourceNode: AttackPathNode;
  sharedNodes: AttackPathNode[];
  targets: AttackPathNode[];
  originalPaths: AttackPath[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  maxLikelihood: number;
  blastRadiusSummary: string;
  mitreTechniques: string[];
  recommendation: string;
  description: string;
}

export const AttackPaths: FC = () => {
  const navigate = useNavigate();
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  const [resourceTypeFilter, setResourceTypeFilter] = useState<string>('all');
  const [aiExpanded, setAiExpanded] = useState<Record<string, { loading: boolean; text: string; codeBlock?: string } | null>>({});
  const [isTreeExpanded, setIsTreeExpanded] = useState(true);

  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  const { data } = useQuery({
    queryKey: ['attackPaths'],
    queryFn: getAttackPaths,
    refetchInterval: 10000
  });

  const rawAttackPaths = data || [];

  // Natural relationship labels lookup
  function getHopRelationshipLabel(srcType: string, tgtType: string): string {
    const s = (srcType || '').toLowerCase();
    const t = (tgtType || '').toLowerCase();
    if (s === 'user' && t === 'group') return 'MEMBER_OF';
    if (s === 'group' && t === 'policy') return 'HAS_POLICY';
    if (s === 'user' && t === 'policy') return 'ATTACHED_POLICY';
    if (s === 'policy' && t === 'role') return 'CAN_ASSUME';
    if (s === 'user' && t === 'role') return 'CAN_ASSUME';
    if (s === 'role' && t === 'policy') return 'HAS_POLICY';
    if (s === 'policy') return 'ALLOWS';
    if (s === 'role') return 'ALLOWS_ACCESS';
    return 'CAN_ACCESS';
  }

  // 1. PATH GROUPING ALGORITHM: Consolidate duplicate linear paths sharing common prefix
  const consolidatedGroups = useMemo<ConsolidatedAttackPathGroup[]>(() => {
    const groupMap: Record<string, ConsolidatedAttackPathGroup> = {};

    rawAttackPaths.forEach((path) => {
      if (!path.nodes || path.nodes.length === 0) return;

      // The shared prefix consists of all hops except the final target
      const sharedPrefixNodes = path.nodes.slice(0, -1);
      const targetNode = path.nodes[path.nodes.length - 1];

      // Build deterministic prefix key: source + ordered intermediate nodes
      const prefixKey = sharedPrefixNodes.length > 0 
        ? sharedPrefixNodes.map(n => n.id || n.name).join('->')
        : (path.nodes[0]?.id || path.nodes[0]?.name || 'unknown');

      const sev = (path.severity || 'high').toLowerCase() as 'critical' | 'high' | 'medium' | 'low';

      if (!groupMap[prefixKey]) {
        groupMap[prefixKey] = {
          groupId: `group:${prefixKey}`,
          name: path.name,
          sourceNode: path.nodes[0],
          sharedNodes: sharedPrefixNodes,
          targets: targetNode ? [targetNode] : [],
          originalPaths: [path],
          severity: sev,
          maxLikelihood: path.likelihood || 80,
          blastRadiusSummary: path.blastRadius || 'Multiple connected resources',
          mitreTechniques: [...(path.mitreTechniques || [])],
          recommendation: path.recommendation || '',
          description: path.description || ''
        };
      } else {
        const group = groupMap[prefixKey];
        group.originalPaths.push(path);
        
        // Add target if not already present
        if (targetNode && !group.targets.some(t => (t.id || t.name) === (targetNode.id || targetNode.name))) {
          group.targets.push(targetNode);
        }

        // Track max likelihood
        if (path.likelihood && path.likelihood > group.maxLikelihood) {
          group.maxLikelihood = path.likelihood;
        }

        // Elevate severity if higher
        const severityValues: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
        const currentRank = severityValues[group.severity] || 1;
        const incomingSev = (path.severity || 'low').toLowerCase();
        const newRank = severityValues[incomingSev] || 1;
        if (newRank > currentRank) {
          group.severity = incomingSev as 'critical' | 'high' | 'medium' | 'low';
        }

        // Union MITRE techniques
        (path.mitreTechniques || []).forEach(tech => {
          if (!group.mitreTechniques.includes(tech)) {
            group.mitreTechniques.push(tech);
          }
        });
      }
    });

    return Object.values(groupMap);
  }, [rawAttackPaths]);

  // Filtered Consolidated Groups
  const filteredGroups = useMemo(() => {
    return consolidatedGroups.filter(g => {
      const q = searchQuery.trim().toLowerCase();
      const matchesSearch = q === '' || 
        g.name.toLowerCase().includes(q) || 
        g.description.toLowerCase().includes(q) ||
        g.sourceNode.name.toLowerCase().includes(q) ||
        g.sharedNodes.some(n => n.name.toLowerCase().includes(q) || n.type.toLowerCase().includes(q)) ||
        g.targets.some(t => t.name.toLowerCase().includes(q) || t.type.toLowerCase().includes(q));

      const matchesSeverity = severityFilter === 'all' || g.severity === severityFilter;

      const matchesType = resourceTypeFilter === 'all' || 
        g.targets.some(t => t.type.toLowerCase() === resourceTypeFilter.toLowerCase());

      return matchesSearch && matchesSeverity && matchesType;
    });
  }, [consolidatedGroups, searchQuery, severityFilter, resourceTypeFilter]);

  // Active selected group
  const selectedGroup = useMemo(() => {
    return consolidatedGroups.find(g => g.groupId === selectedGroupId) || filteredGroups[0] || null;
  }, [consolidatedGroups, filteredGroups, selectedGroupId]);

  // 2. Build Merged Branching Attack DAG Elements for Cytoscape Top Visualizer
  const treeElements = useMemo(() => {
    const nodesMap: Record<string, any> = {};
    const edgesMap: Record<string, any> = {};

    const groupsToRender = filteredGroups.length > 0 ? filteredGroups : consolidatedGroups;

    groupsToRender.forEach((group) => {
      // 1. Add shared prefix chain nodes exactly once
      group.sharedNodes.forEach((node, idx) => {
        const nodeId = node.id || `node:${node.name}`;
        if (!nodesMap[nodeId]) {
          nodesMap[nodeId] = {
            data: {
              id: nodeId,
              label: node.name,
              type: node.type,
              isRoot: idx === 0,
              isShared: true,
              riskScore: group.maxLikelihood
            }
          };
        }
      });

      // 2. Connect consecutive hops in the shared chain
      for (let i = 0; i < group.sharedNodes.length - 1; i++) {
        const sNode = group.sharedNodes[i];
        const tNode = group.sharedNodes[i + 1];
        const sId = sNode.id || `node:${sNode.name}`;
        const tId = tNode.id || `node:${tNode.name}`;
        const edgeId = `edge:${sId}->${tId}`;

        if (!edgesMap[edgeId]) {
          edgesMap[edgeId] = {
            data: {
              id: edgeId,
              source: sId,
              target: tId,
              label: getHopRelationshipLabel(sNode.type, tNode.type),
              groupIds: [group.groupId],
              severity: group.severity
            }
          };
        } else if (!edgesMap[edgeId].data.groupIds.includes(group.groupId)) {
          edgesMap[edgeId].data.groupIds.push(group.groupId);
        }
      }

      // 3. Connect the last shared node to all branching divergent targets
      const lastSharedNode = group.sharedNodes[group.sharedNodes.length - 1] || group.sourceNode;
      const lastSharedId = lastSharedNode.id || `node:${lastSharedNode.name}`;

      group.targets.forEach((targetNode) => {
        const targetId = targetNode.id || `node:${targetNode.name}`;
        if (!nodesMap[targetId]) {
          nodesMap[targetId] = {
            data: {
              id: targetId,
              label: targetNode.name,
              type: targetNode.type,
              isTarget: true,
              riskScore: group.maxLikelihood
            }
          };
        }

        const branchEdgeId = `branch:${lastSharedId}->${targetId}`;
        if (!edgesMap[branchEdgeId]) {
          edgesMap[branchEdgeId] = {
            data: {
              id: branchEdgeId,
              source: lastSharedId,
              target: targetId,
              label: getHopRelationshipLabel(lastSharedNode.type, targetNode.type),
              groupIds: [group.groupId],
              severity: group.severity
            }
          };
        } else if (!edgesMap[branchEdgeId].data.groupIds.includes(group.groupId)) {
          edgesMap[branchEdgeId].data.groupIds.push(group.groupId);
        }
      });
    });

    return [...Object.values(nodesMap), ...Object.values(edgesMap)];
  }, [filteredGroups, consolidatedGroups]);

  // Blast Radius Metric Strip Stats
  const blastRadiusStats = useMemo(() => {
    const uniqueIdentities = new Set<string>();
    const uniqueTargets = new Set<string>();
    let maxDepth = 0;
    let criticalTargets = 0;

    rawAttackPaths.forEach(p => {
      if (p.nodes.length > 0) {
        uniqueIdentities.add(p.nodes[0].name);
        const target = p.nodes[p.nodes.length - 1];
        uniqueTargets.add(target.name);
        const t = target.type as string;
        if (p.severity === 'critical' || t === 'Secrets' || t === 'Secret' || t === 'RDS') {
          criticalTargets++;
        }
      }
      if (p.nodes.length > maxDepth) {
        maxDepth = p.nodes.length;
      }
    });

    return {
      totalRawPaths: rawAttackPaths.length,
      consolidatedGroupCount: consolidatedGroups.length,
      compromisedIdentities: uniqueIdentities.size,
      reachableAssets: uniqueTargets.size,
      criticalAssets: criticalTargets,
      maxDepth: Math.max(1, maxDepth)
    };
  }, [rawAttackPaths, consolidatedGroups]);

  // Cytoscape Instance Lifecycle
  useEffect(() => {
    if (!containerRef.current) return;

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: JSON.parse(JSON.stringify(treeElements)),
      minZoom: 0.15,
      maxZoom: 2.5,
      wheelSensitivity: 0.2,
      style: [
        // Base Node Style
        {
          selector: 'node',
          style: {
            'content': 'data(label)',
            'font-family': 'Inter, sans-serif',
            'font-size': '11px',
            'font-weight': 'bold',
            'color': '#F3F4F6',
            'text-valign': 'bottom',
            'text-margin-y': 8,
            'background-color': '#1E293B',
            'border-width': '2px',
            'border-color': '#4B5563',
            'width': '42px',
            'height': '42px',
            'transition-property': 'background-color, border-color, border-width, opacity, width, height',
            'transition-duration': 0.25,
            'text-background-color': '#0F172A',
            'text-background-opacity': 0.85,
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle'
          }
        },
        // Entity Node Types
        {
          selector: 'node[type="User"]',
          style: {
            'background-color': '#3B82F6', // Blue
            'border-color': '#60A5FA',
            'shape': 'ellipse',
            'width': '42px',
            'height': '42px'
          }
        },
        {
          selector: 'node[type="Group"]',
          style: {
            'background-color': '#6366F1', // Indigo
            'border-color': '#818CF8',
            'border-width': '3px',
            'shape': 'round-rectangle',
            'width': '52px',
            'height': '42px'
          }
        },
        {
          selector: 'node[type="Policy"]',
          style: {
            'background-color': '#14B8A6', // Teal
            'border-color': '#2DD4BF',
            'shape': 'diamond',
            'width': '42px',
            'height': '42px'
          }
        },
        {
          selector: 'node[type="Role"]',
          style: {
            'background-color': '#8B5CF6', // Purple
            'border-color': '#A78BFA',
            'shape': 'hexagon',
            'width': '46px',
            'height': '46px'
          }
        },
        {
          selector: 'node[type="S3"]',
          style: {
            'background-color': '#F59E0B', // Amber
            'border-color': '#FBBF24',
            'shape': 'barrel'
          }
        },
        {
          selector: 'node[type="EC2"]',
          style: {
            'background-color': '#10B981', // Emerald
            'border-color': '#34D399',
            'shape': 'round-rectangle'
          }
        },
        {
          selector: 'node[type="Lambda"]',
          style: {
            'background-color': '#EC4899', // Pink
            'border-color': '#F472B6',
            'shape': 'ellipse'
          }
        },
        {
          selector: 'node[type="RDS"]',
          style: {
            'background-color': '#0EA5E9', // Sky Blue
            'border-color': '#38BDF8',
            'shape': 'database' as cytoscape.Css.NodeShape
          }
        },
        {
          selector: 'node[type="Secrets"], node[type="Secret"]',
          style: {
            'background-color': '#EF4444', // Red
            'border-color': '#F87171',
            'border-width': '3px',
            'shape': 'ellipse'
          }
        },
        // Edge Styling: Directed Arrow Hierarchical Connectors
        {
          selector: 'edge',
          style: {
            'label': 'data(label)',
            'font-family': 'Inter, monospace',
            'font-size': '9px',
            'font-weight': 'bold',
            'color': '#CBD5E1',
            'text-background-color': '#0F172A',
            'text-background-opacity': 0.85,
            'text-background-padding': '2px',
            'text-background-shape': 'roundrectangle',
            'width': 2,
            'line-color': '#475569',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'text-rotation': 'autorotate',
            'text-margin-y': -8,
            'opacity': 0.6,
            'transition-property': 'line-color, target-arrow-color, width, opacity',
            'transition-duration': 0.25
          }
        },
        // Selected / Highlighted Branch
        {
          selector: 'node.highlighted',
          style: {
            'border-width': '4px',
            'border-color': '#FBBF24',
            'opacity': 1,
            'z-index': 999
          }
        },
        {
          selector: 'edge.highlighted',
          style: {
            'line-color': '#EF4444',
            'target-arrow-color': '#EF4444',
            'width': 3.5,
            'opacity': 1,
            'z-index': 998
          }
        },
        {
          selector: 'node.dimmed',
          style: {
            'opacity': 0.12
          }
        },
        {
          selector: 'edge.dimmed',
          style: {
            'opacity': 0.08
          }
        }
      ],
      layout: {
        name: 'dagre',
        directed: true,
        padding: 50,
        rankDir: 'TB',
        nodeSep: 70,
        rankSep: 110,
        edgeSep: 35,
        fit: true,
        spacingFactor: 1.15
      } as any
    });

    cyRef.current = cy;

    // Node click: select associated consolidated attack path group
    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      const nodeId = node.id();
      
      const matchingGroup = consolidatedGroups.find(g => 
        g.sharedNodes.some(n => (n.id || `node:${n.name}`) === nodeId) ||
        g.targets.some(t => (t.id || `node:${t.name}`) === nodeId)
      );

      if (matchingGroup) {
        setSelectedGroupId(matchingGroup.groupId);
      }
    });

    cy.ready(() => {
      cy.fit(undefined, 50);
    });

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [treeElements, consolidatedGroups]);

  // Apply Branch Highlighting on selectedGroup change
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      if (selectedGroup) {
        cy.elements().addClass('dimmed').removeClass('highlighted');

        const activeNodeIds = [
          ...selectedGroup.sharedNodes.map(n => n.id || `node:${n.name}`),
          ...selectedGroup.targets.map(t => t.id || `node:${t.name}`)
        ];

        // Highlight nodes
        activeNodeIds.forEach(nId => {
          const ele = cy.getElementById(nId);
          if (ele.length > 0) {
            ele.removeClass('dimmed').addClass('highlighted');
          }
        });

        // Highlight shared chain edges + branching target edges
        cy.edges().forEach(edge => {
          const groupIds: string[] = edge.data('groupIds') || [];
          if (groupIds.includes(selectedGroup.groupId)) {
            edge.removeClass('dimmed').addClass('highlighted');
          }
        });
      } else {
        cy.elements().removeClass('dimmed').removeClass('highlighted');
      }
    });
  }, [selectedGroup]);

  // AI Copilot Explainer on Consolidated Group
  const handleExplainAI = async (group: ConsolidatedAttackPathGroup) => {
    const current = aiExpanded[group.groupId];
    if (current && !current.loading) {
      setAiExpanded(prev => ({ ...prev, [group.groupId]: null }));
      return;
    }

    setAiExpanded(prev => ({ ...prev, [group.groupId]: { loading: true, text: '' } }));

    try {
      const prompt = `Analyze the consolidated attack path for identity "${group.sourceNode.name}". 
Severity: ${group.severity}. 
Shared Privilege Path: ${group.sharedNodes.map(n => `${n.name} (${n.type})`).join(' → ')}. 
Reachable Branching Targets (${group.targets.length}): ${group.targets.map(t => `${t.name} (${t.type})`).join(', ')}. 
MITRE techniques: ${group.mitreTechniques.join(', ')}. 
Explain why this identity's privilege chain allows it to reach multiple cloud assets and suggest an IAM remediation.`;
      
      const response = await postCopilotMessage(prompt);
      setAiExpanded(prev => ({
        ...prev,
        [group.groupId]: { loading: false, text: response.text, codeBlock: response.codeBlock }
      }));
    } catch {
      setAiExpanded(prev => ({
        ...prev,
        [group.groupId]: {
          loading: false,
          text: `This consolidated attack path reveals that the identity "${group.sourceNode.name}" traverses a single shared privilege chain (${group.sharedNodes.map(n => n.name).join(' → ')}) to access ${group.targets.length} distinct cloud targets (${group.targets.map(t => t.name).join(', ')}). Recommendation: ${group.recommendation || 'Apply least-privilege scoping to the attached IAM policy.'}`
        }
      }));
    }
  };

  const handleZoomIn = () => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom({
      level: Math.min(2.5, cy.zoom() * 1.25),
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 }
    });
  };

  const handleZoomOut = () => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom({
      level: Math.max(0.15, cy.zoom() / 1.25),
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 }
    });
  };

  const handleFit = () => {
    cyRef.current?.fit(undefined, 50);
  };

  const handleExportPNG = () => {
    if (!cyRef.current) return;
    const png = cyRef.current.png({ bg: '#0B1120', full: true });
    const a = document.createElement('a');
    a.href = png;
    a.download = 'consolidated-attack-dag-tree.png';
    a.click();
  };

  const handleHighlightInFullGraph = (group: ConsolidatedAttackPathGroup) => {
    const allNodeIds = [
      ...group.sharedNodes.map(n => n.id || n.name),
      ...group.targets.map(t => t.id || t.name)
    ];
    navigate(`/graph?highlight=${allNodeIds.join(',')}`);
  };

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto bg-enterprise-bg select-none text-gray-200">
      
      {/* Header */}
      <div className="flex justify-between items-center flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <GitMerge className="w-6 h-6 text-enterprise-accent" />
            <span>Attack Paths & Lateral Movement DAG</span>
          </h1>
          <p className="text-xs text-enterprise-subtext mt-1">
            Consolidated branching attack trees merging duplicate common prefixes into single multi-target lateral vectors.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <ScannedRegionBadge />
          <ScanTrigger />
        </div>
      </div>

      {/* Blast Radius & Risk Summary Metric Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
        <div className="p-3.5 bg-enterprise-card border border-enterprise-border rounded-xl flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-blue-500/10 text-blue-400">
            <FolderGit2 className="w-4 h-4" />
          </div>
          <div>
            <p className="text-[10px] text-enterprise-subtext font-bold uppercase tracking-wider">Consolidated Trees</p>
            <div className="flex items-baseline gap-1.5">
              <span className="text-lg font-black text-white">{blastRadiusStats.consolidatedGroupCount}</span>
              <span className="text-[10px] text-gray-400 font-mono">({blastRadiusStats.totalRawPaths} raw)</span>
            </div>
          </div>
        </div>

        <div className="p-3.5 bg-enterprise-card border border-enterprise-border rounded-xl flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-indigo-500/10 text-indigo-400">
            <Radio className="w-4 h-4" />
          </div>
          <div>
            <p className="text-[10px] text-enterprise-subtext font-bold uppercase tracking-wider">Compromised Roots</p>
            <p className="text-lg font-black text-white">{blastRadiusStats.compromisedIdentities}</p>
          </div>
        </div>

        <div className="p-3.5 bg-enterprise-card border border-enterprise-border rounded-xl flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-amber-500/10 text-amber-400">
            <Flame className="w-4 h-4" />
          </div>
          <div>
            <p className="text-[10px] text-enterprise-subtext font-bold uppercase tracking-wider">Reachable Targets</p>
            <p className="text-lg font-black text-white">{blastRadiusStats.reachableAssets}</p>
          </div>
        </div>

        <div className="p-3.5 bg-enterprise-card border border-enterprise-border rounded-xl flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-red-500/10 text-red-400">
            <ShieldAlert className="w-4 h-4" />
          </div>
          <div>
            <p className="text-[10px] text-enterprise-subtext font-bold uppercase tracking-wider">Critical Assets</p>
            <p className="text-lg font-black text-white">{blastRadiusStats.criticalAssets}</p>
          </div>
        </div>

        <div className="p-3.5 bg-enterprise-card border border-enterprise-border rounded-xl flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-purple-500/10 text-purple-400">
            <Layers className="w-4 h-4" />
          </div>
          <div>
            <p className="text-[10px] text-enterprise-subtext font-bold uppercase tracking-wider">Max Chain Depth</p>
            <p className="text-lg font-black text-white">{blastRadiusStats.maxDepth}</p>
          </div>
        </div>
      </div>

      {/* Search & Filters Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-enterprise-card p-3 rounded-xl border border-enterprise-border">
        <div className="flex items-center gap-2 flex-wrap">
          {/* Search */}
          <div className="relative flex items-center">
            <Search className="w-3.5 h-3.5 absolute left-3 text-gray-500" />
            <input
              type="text"
              placeholder="Search identity, policy, role, target..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-gray-900 border border-gray-700 text-xs rounded-lg pl-8 pr-3 py-1.5 focus:outline-none focus:border-blue-500 w-64 text-white placeholder-gray-500"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1 bg-gray-900 p-1 rounded-lg border border-gray-700 text-[11px]">
            <span className="text-gray-400 px-1 font-semibold">Severity:</span>
            {(['all', 'critical', 'high', 'medium', 'low'] as const).map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-0.5 rounded capitalize font-medium transition-colors ${
                  severityFilter === sev
                    ? 'bg-blue-600 text-white shadow'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Resource Type Filter */}
          <div className="flex items-center gap-1 bg-gray-900 p-1 rounded-lg border border-gray-700 text-[11px]">
            <span className="text-gray-400 px-1 font-semibold">Target:</span>
            {(['all', 's3', 'ec2', 'lambda', 'rds', 'secrets'] as const).map((t) => (
              <button
                key={t}
                onClick={() => setResourceTypeFilter(t)}
                className={`px-2 py-0.5 rounded uppercase font-mono font-medium transition-colors ${
                  resourceTypeFilter === t
                    ? 'bg-indigo-600 text-white shadow'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                {t}
              </button>
            ))}
          </div>
        </div>

        <button
          onClick={() => setIsTreeExpanded(prev => !prev)}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-xs font-semibold rounded-lg text-gray-300 border border-gray-700 transition-colors"
        >
          <SlidersHorizontal className="w-3.5 h-3.5 text-blue-400" />
          <span>{isTreeExpanded ? 'Collapse DAG Visualizer' : 'Expand DAG Visualizer'}</span>
        </button>
      </div>

      {/* INTERACTIVE BRANCHING ATTACK DAG TREE VISUALIZER */}
      {isTreeExpanded && (
        <div className="bg-[#0F172A] border border-enterprise-border rounded-xl p-4 shadow-2xl relative overflow-hidden flex flex-col h-[480px]">
          <div className="flex items-center justify-between mb-2 z-10 pb-2 border-b border-gray-800">
            <div className="flex items-center gap-2">
              <GitMerge className="w-4 h-4 text-enterprise-accent" />
              <span className="text-xs font-bold text-white uppercase tracking-wider">Branching Attack Path DAG Tree</span>
              <span className="text-[10px] text-gray-400 font-mono">
                ({filteredGroups.length} Consolidated Trees | {blastRadiusStats.totalRawPaths} Underlying Paths)
              </span>
            </div>

            {/* Tree Canvas Floating Controls */}
            <div className="flex items-center gap-1.5 bg-gray-900/90 border border-gray-700 rounded-lg p-1">
              <button onClick={handleZoomIn} className="p-1 hover:bg-gray-800 rounded text-gray-300 transition-colors" title="Zoom In"><ZoomIn className="w-3.5 h-3.5" /></button>
              <button onClick={handleZoomOut} className="p-1 hover:bg-gray-800 rounded text-gray-300 transition-colors" title="Zoom Out"><ZoomOut className="w-3.5 h-3.5" /></button>
              <button onClick={handleFit} className="p-1 hover:bg-gray-800 rounded text-gray-300 transition-colors" title="Fit"><Maximize2 className="w-3.5 h-3.5" /></button>
              <div className="w-[1px] h-3 bg-gray-700 mx-1" />
              <button onClick={handleExportPNG} className="p-1 hover:bg-gray-800 rounded text-gray-300 transition-colors text-[10px] flex items-center gap-1 font-semibold" title="Export PNG">
                <span>PNG</span>
              </button>
            </div>
          </div>

          {/* Cytoscape Canvas */}
          <div ref={containerRef} className="w-full flex-1 relative bg-[#0B1120] rounded-lg" />

          {/* Canvas Helper Legend */}
          <div className="absolute bottom-6 left-6 z-10 bg-gray-900/90 backdrop-blur-md border border-gray-700 rounded-lg px-3 py-1.5 text-[10px] flex items-center gap-3 text-gray-300">
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-blue-500" /><span>User</span></div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2 rounded bg-indigo-500" /><span>Group</span></div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rotate-45 bg-teal-500" /><span>Policy</span></div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 bg-purple-500" /><span>Role</span></div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2 rounded bg-amber-500" /><span>Resource</span></div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-red-500" /><span>Secret</span></div>
          </div>
        </div>
      )}

      {/* CONSOLIDATED ATTACK PATH GROUPS LIST */}
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Target className="w-4 h-4 text-red-400" />
            <span>Consolidated Attack Path Groups</span>
          </h3>
          <span className="text-xs text-gray-400 font-mono">
            {filteredGroups.length} unique privilege vectors ({blastRadiusStats.totalRawPaths} raw paths consolidated)
          </span>
        </div>

        {filteredGroups.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-12 border border-dashed border-enterprise-border rounded-xl bg-enterprise-card/50">
            <Sparkles className="w-12 h-12 text-enterprise-subtext mb-4" />
            <h3 className="text-lg font-bold text-white mb-2">No Attack Paths Found</h3>
            <p className="text-sm text-enterprise-subtext text-center max-w-md">
              No lateral movement vectors match your current search or filter criteria.
            </p>
          </div>
        ) : (
          filteredGroups.map((group) => {
            const isSelected = selectedGroup && selectedGroup.groupId === group.groupId;
            const aiState = aiExpanded[group.groupId];
            const isAIExpanded = !!aiState && !aiState.loading;
            const isAILoading = !!aiState?.loading;

            return (
              <div
                key={group.groupId}
                onClick={() => setSelectedGroupId(group.groupId)}
                className={`bg-enterprise-card border rounded-2xl p-6 transition-all shadow-xl flex flex-col gap-5 cursor-pointer ${
                  isSelected
                    ? 'border-red-500/80 bg-[#141B2D] ring-1 ring-red-500/50 shadow-red-500/10'
                    : 'border-enterprise-border hover:border-gray-700'
                }`}
              >
                {/* Group Card Top Header Bar */}
                <div className="flex flex-wrap items-start justify-between gap-4 border-b border-enterprise-border pb-4">
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <span
                        className={`text-[10px] font-black px-2.5 py-0.5 rounded uppercase tracking-wider border ${
                          group.severity === 'critical'
                            ? 'bg-enterprise-critical/20 text-enterprise-critical border-enterprise-critical/40'
                            : 'bg-enterprise-warning/20 text-enterprise-warning border-enterprise-warning/40'
                        }`}
                      >
                        {group.severity} RISK
                      </span>
                      <span className="text-[10px] text-enterprise-accent bg-enterprise-accent/10 border border-enterprise-accent/30 px-2.5 py-0.5 rounded font-bold">
                        {group.maxLikelihood}% LIKELIHOOD
                      </span>
                      <span className="text-[10px] text-purple-300 bg-purple-950/50 border border-purple-500/40 px-2.5 py-0.5 rounded font-mono font-bold flex items-center gap-1">
                        <Share2 className="w-3 h-3 text-purple-400" />
                        <span>{group.targets.length} Reachable Target{group.targets.length > 1 ? 's' : ''}</span>
                      </span>
                      <h3 className="text-base font-bold text-white ml-1">{group.name}</h3>
                    </div>
                    <p className="text-xs text-enterprise-subtext leading-relaxed">{group.description}</p>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex items-center gap-2">
                    <button
                      onClick={(e) => { e.stopPropagation(); handleHighlightInFullGraph(group); }}
                      className="flex items-center gap-1.5 px-3.5 py-1.5 bg-enterprise-accent hover:bg-blue-600 text-white font-semibold rounded-lg text-xs transition-colors shadow"
                    >
                      <GitMerge className="w-3.5 h-3.5" />
                      <span>Trace in Full Graph</span>
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleExplainAI(group); }}
                      disabled={isAILoading}
                      className="flex items-center gap-1.5 px-3.5 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-60 text-white border border-enterprise-border font-semibold rounded-lg text-xs transition-colors"
                    >
                      {isAILoading ? (
                        <RefreshCw className="w-3.5 h-3.5 animate-spin text-enterprise-accent" />
                      ) : (
                        <Sparkles className="w-3.5 h-3.5 text-enterprise-accent" />
                      )}
                      <span>Explain with AI</span>
                      {!isAILoading && (isAIExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />)}
                    </button>
                  </div>
                </div>

                {/* EXACT REFERENCE DESIGN: VERTICAL HIERARCHICAL BRANCHING DIAGRAM */}
                <div className="bg-[#0B1120]/80 rounded-xl p-5 border border-enterprise-border/80 flex flex-col items-center select-none shadow-inner">
                  
                  {/* Shared Linear Privilege Chain: User -> Roles -> Policies */}
                  <div className="flex flex-col items-center w-full max-w-xl">
                    {group.sharedNodes.map((node, index) => {
                      const nextNode = group.sharedNodes[index + 1];
                      const relLabel = nextNode ? getHopRelationshipLabel(node.type, nextNode.type) : 'ALLOWS';

                      return (
                        <div key={node.id || node.name} className="flex flex-col items-center w-full">
                          {/* Node Box */}
                          <div className={`px-4 py-2 rounded-xl border flex items-center gap-3 shadow-md min-w-[240px] justify-center ${
                            (node.type as string) === 'User'
                              ? 'bg-blue-950/40 border-blue-500/50 text-blue-100'
                              : (node.type as string) === 'Group'
                              ? 'bg-indigo-950/40 border-indigo-500/50 text-indigo-100'
                              : (node.type as string) === 'Policy'
                              ? 'bg-teal-950/40 border-teal-500/50 text-teal-100'
                              : (node.type as string) === 'Role'
                              ? 'bg-purple-950/40 border-purple-500/50 text-purple-100'
                              : 'bg-slate-900 border-gray-700 text-gray-200'
                          }`}>
                            <span
                              className={`w-2.5 h-2.5 rounded-full shrink-0 shadow-sm ${
                                (node.type as string) === 'User'
                                  ? 'bg-blue-400'
                                  : (node.type as string) === 'Group'
                                  ? 'bg-indigo-400'
                                  : (node.type as string) === 'Policy'
                                  ? 'bg-teal-400'
                                  : (node.type as string) === 'Role'
                                  ? 'bg-purple-400'
                                  : 'bg-amber-400'
                              }`}
                            />
                            <div className="text-center">
                              <p className="font-bold text-xs text-white leading-tight font-mono">{node.name}</p>
                              <p className="text-[9px] text-gray-400 uppercase tracking-wider font-semibold mt-0.5">{node.type}</p>
                            </div>
                          </div>

                          {/* Vertical Connector Down */}
                          <div className="flex flex-col items-center py-1">
                            <span className="text-[8px] font-mono text-gray-500 font-bold uppercase tracking-wider mb-0.5">
                              {relLabel}
                            </span>
                            <div className="w-0.5 h-3 bg-gradient-to-b from-gray-600 to-gray-400" />
                            <ArrowDown className="w-3.5 h-3.5 text-gray-400 -mt-1" />
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* BRANCHING FORK CONNECTOR TO MULTIPLE TARGET ASSETS */}
                  <div className="w-full flex flex-col items-center mt-1">
                    
                    {/* Multi-Target Horizontal Distribution Line */}
                    {group.targets.length > 1 ? (
                      <div className="w-full flex flex-col items-center">
                        <div className="w-3/4 max-w-2xl h-[2px] bg-gradient-to-r from-red-500/20 via-red-500 to-red-500/20 my-1 relative">
                          <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 bg-[#0B1120] px-2 text-[8px] font-mono font-bold text-red-400 uppercase tracking-widest border border-red-500/40 rounded">
                            {group.targets.length} Target Branches
                          </div>
                        </div>
                      </div>
                    ) : null}

                    {/* Target Resources Grid */}
                    <div className="flex flex-wrap items-center justify-center gap-3 mt-3 w-full">
                      {group.targets.map((target) => {
                        const t = target.type as string;
                        const isCritical = t === 'Secrets' || t === 'Secret' || t === 'RDS';

                        return (
                          <div
                            key={target.id || target.name}
                            className={`px-3.5 py-2 rounded-xl border flex items-center gap-2.5 shadow-lg transition-transform hover:scale-105 ${
                              isCritical
                                ? 'bg-red-950/50 border-red-500/70 text-red-100 ring-1 ring-red-500/30'
                                : 'bg-amber-950/30 border-amber-500/50 text-amber-100'
                            }`}
                          >
                            <span
                              className={`w-2.5 h-2.5 rounded-full shrink-0 shadow-sm ${
                                isCritical ? 'bg-red-400 animate-pulse' : 'bg-amber-400'
                              }`}
                            />
                            <div>
                              <p className="font-bold text-xs text-white leading-tight font-mono">{target.name}</p>
                              <div className="flex items-center gap-1 mt-0.5">
                                <span className="text-[8px] text-gray-400 uppercase font-semibold">{target.type}</span>
                                {isCritical && (
                                  <span className="text-[8px] text-red-400 font-bold bg-red-950 px-1 rounded uppercase">CRITICAL</span>
                                )}
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    {/* Bottom Impact Summary Bar */}
                    <div className="mt-4 pt-3 border-t border-gray-800/80 w-full flex items-center justify-between text-xs text-gray-400 flex-wrap gap-2">
                      <div className="flex items-center gap-2">
                        <Flame className="w-3.5 h-3.5 text-red-400" />
                        <span className="font-mono text-[11px]">
                          <strong className="text-white">Blast Radius:</strong> {group.blastRadiusSummary}
                        </span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <span className="text-[10px] text-gray-500 uppercase font-bold tracking-wider">MITRE ATT&CK:</span>
                        <div className="flex flex-wrap gap-1">
                          {group.mitreTechniques.map(tech => (
                            <span key={tech} className="px-1.5 py-0.5 bg-gray-900 text-[9px] font-mono text-gray-300 rounded border border-gray-700">
                              {tech}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* AI Explanation Card */}
                {isAIExpanded && aiState && (
                  <div className="bg-enterprise-accent/5 p-4 rounded-xl border border-enterprise-accent/20 flex gap-3 text-xs leading-relaxed text-gray-200 mt-1">
                    <Bot className="w-5 h-5 text-enterprise-accent shrink-0 mt-0.5" />
                    <div className="space-y-3 w-full">
                      <h4 className="font-extrabold text-white text-xs flex items-center gap-1.5">
                        <span>Copilot Security Explanation</span>
                      </h4>
                      <p className="text-[11px] text-enterprise-subtext whitespace-pre-wrap">{aiState.text}</p>
                      {aiState.codeBlock && (
                        <div className="space-y-1.5">
                          <span className="font-semibold text-white text-[10px] flex items-center gap-1">
                            <Terminal className="w-3.5 h-3.5 text-enterprise-accent" />
                            <span>Remediation Reference</span>
                          </span>
                          <pre className="p-3 bg-gray-900 border border-enterprise-border rounded-lg text-[9px] font-mono text-gray-300 overflow-x-auto">
                            {aiState.codeBlock}
                          </pre>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
