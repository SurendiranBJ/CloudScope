import { useState, useRef, useEffect, useMemo } from 'react';
import type { FC } from 'react';
import { useNavigate } from 'react-router-dom';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import {
  GitMerge,
  ArrowDown,
  Sparkles,
  LoaderCircle,
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
  Share2,
  Users,
  Activity,
  FileText,
  Key,
  ShieldCheck,
  Network,
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getAttackPaths } from '../api/attack';
import { explainAttackPath, type CopilotMessage } from '../api/copilot';
import { ScanTrigger } from '../components/ScanTrigger';
import { ScannedRegionBadge } from '../components/ScannedRegionBadge';
import type { AttackPath, AttackPathNode, DownstreamReachableAsset } from '../types';
import { ENTITY_STYLES, normalizeGraphType, getGraphEntityStyle } from '../constants/graphStyles';

// Register dagre layout
cytoscape.use(dagre);

export interface ConsolidatedAttackPathGroup {
  groupId: string;
  name: string;
  sources: AttackPathNode[];
  sharedChain: AttackPathNode[];
  targets: AttackPathNode[];
  isRoleTarget?: boolean;
  targetRole?: AttackPathNode;
  downstreamAssets?: DownstreamReachableAsset[];
  originalPaths: AttackPath[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  maxRiskScore: number;
  blastRadiusSummary: string;
  mitreTechniques: string[];
  recommendation: string;
  description: string;
  diffStatus?: 'NEW' | 'REMOVED' | 'CHANGED' | 'UNCHANGED';
  currentRiskScore?: number;
  desiredRiskScore?: number;
  riskDelta?: number;
}

export const AttackPaths: FC = () => {
  const navigate = useNavigate();
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [focusedSourceId, setFocusedSourceId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  const [resourceTypeFilter, setResourceTypeFilter] = useState<string>('all');
  const [isTreeExpanded, setIsTreeExpanded] = useState(true);
  const [evidenceExpanded, setEvidenceExpanded] = useState<Record<string, boolean>>({});
  const [inspectedAsset, setInspectedAsset] = useState<DownstreamReachableAsset | null>(null);
  const [aiPathResponses, setAiPathResponses] = useState<Record<string, CopilotMessage>>({});
  const [aiPathLoading, setAiPathLoading] = useState<Record<string, boolean>>({});
  const [aiPathErrors, setAiPathErrors] = useState<Record<string, string>>({});

  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  const { data } = useQuery({
    queryKey: ['attackPaths'],
    queryFn: getAttackPaths,
    refetchInterval: 10000
  });

  const rawAttackPaths = useMemo(() => data || [], [data]);

  const handleHighlightInFullGraph = (selectedPath: AttackPath) => {
    const pathNodeIds = selectedPath.nodes.map(n => n.id || n.name).filter(Boolean);
    if (pathNodeIds.length === 0) return;
    navigate(`/graph?highlight=${encodeURIComponent(pathNodeIds.join(','))}`);
  };

  const handleExplainPathWithAI = async (group: ConsolidatedAttackPathGroup) => {
    const representativePath = group.originalPaths[0];
    if (!representativePath?.id) {
      setAiPathErrors((current) => ({ ...current, [group.groupId]: 'No verified path ID is available for this group.' }));
      return;
    }

    setAiPathLoading((current) => ({ ...current, [group.groupId]: true }));
    setAiPathErrors((current) => ({ ...current, [group.groupId]: '' }));
    try {
      const explanation = await explainAttackPath(representativePath.id);
      setAiPathResponses((current) => ({ ...current, [group.groupId]: explanation }));
    } catch (error: any) {
      setAiPathErrors((current) => ({
        ...current,
        [group.groupId]: error?.response?.data?.detail || 'AI could not explain this path. Check that an AI provider is configured, then try again.',
      }));
    } finally {
      setAiPathLoading((current) => ({ ...current, [group.groupId]: false }));
    }
  };

  // Extract exact relationship label from backend evidence or orderedRelationships (canonical truth)
  function findExactEdgeLabel(group: ConsolidatedAttackPathGroup, srcNodeIdOrName: string, tgtNodeIdOrName: string): string {
    for (const path of group.originalPaths) {
      // 1. Prioritize step-by-step evidence transitions (has exact from_node and to_node IDs)
      if (path.evidence && Array.isArray(path.evidence)) {
        for (const step of path.evidence) {
          const fromMatch = (step.from_node === srcNodeIdOrName || (!step.from_node && step.from_name === srcNodeIdOrName));
          const toMatch = (step.to_node === tgtNodeIdOrName || (!step.to_node && step.to_name === tgtNodeIdOrName));
          if (fromMatch && toMatch && step.relationship) {
            return step.relationship;
          }
        }
      }
      // 2. Canonical node sequence matching
      if (path.nodes && path.orderedRelationships) {
        for (let i = 0; i < path.nodes.length - 1; i++) {
          const u = path.nodes[i];
          const v = path.nodes[i + 1];
          const uMatch = (u.id === srcNodeIdOrName || (!u.id && u.name === srcNodeIdOrName));
          const vMatch = (v.id === tgtNodeIdOrName || (!v.id && v.name === tgtNodeIdOrName));
          if (uMatch && vMatch && path.orderedRelationships[i]) {
            return path.orderedRelationships[i];
          }
        }
      }
    }
    // If connecting role to downstream reachable asset
    if (group.isRoleTarget && group.downstreamAssets) {
      const matchAsset = group.downstreamAssets.find(a => (a.id === tgtNodeIdOrName || a.name === tgtNodeIdOrName));
      if (matchAsset) {
        return matchAsset.evidence?.action ? 'ALLOWS' : 'REACHABLE';
      }
    }
    return '';
  }

  // 1. ADVANCED DEDUPLICATION & GROUPING ALGORITHM (Cases A, B, C)
  // Groups paths sharing the identical intermediate privilege chain (Roles, Policies)
  const consolidatedGroups = useMemo<ConsolidatedAttackPathGroup[]>(() => {
    const groupMap: Record<string, ConsolidatedAttackPathGroup> = {};

    rawAttackPaths.forEach((path) => {
      if (!path.nodes || path.nodes.length === 0) return;

      const sourceNode = path.nodes[0];
      const targetNode = path.nodes.length > 1 ? path.nodes[path.nodes.length - 1] : null;
      
      // Intermediate chain: nodes strictly between source (hop 0) and final target
      const intermediateNodes = path.nodes.length > 2 
        ? path.nodes.slice(1, -1) 
        : [];

      // If final node is a Role (e.g. Surendiran -> OverlyTrustingAdminRole), preserve role as target while displaying in chain
      const isDirectRoleTarget = !!(targetNode && targetNode.type === 'Role');
      const effectiveSharedChain = isDirectRoleTarget 
        ? (path.nodes.length > 2 ? [...intermediateNodes, targetNode] : [targetNode])
        : intermediateNodes;
      const effectiveTargetNode = isDirectRoleTarget ? null : targetNode;

      const rawDownstream: DownstreamReachableAsset[] =
        path.downstream_reachable_assets || (path as any).downstreamReachableAssets || [];

      // Grouping key: string of ordered shared privilege nodes + ordered relationships
      const relsKey = (path.orderedRelationships || []).join('=>');
      const chainNodesKey = effectiveSharedChain.length > 0
        ? effectiveSharedChain.map(n => `${n.type}:${n.id || n.name}`).join('->')
        : (effectiveTargetNode ? `target:${effectiveTargetNode.type}:${effectiveTargetNode.id || effectiveTargetNode.name}` : `source:${sourceNode.name}`);
      const chainKey = `${chainNodesKey}|rels:${relsKey}`;

      const sev = (path.severity || 'low').toLowerCase() as 'critical' | 'high' | 'medium' | 'low';
      const score = typeof path.riskScore === 'number' ? path.riskScore : 0;

      const tagged = path as any;
      const diffStatus = tagged._diffStatus as 'NEW' | 'REMOVED' | 'CHANGED' | 'UNCHANGED' | undefined;
      const currentRisk = tagged._currentRisk as number | undefined;
      const desiredRisk = tagged._desiredRisk as number | undefined;
      const riskDelta = tagged._riskDelta as number | undefined;

      if (!groupMap[chainKey]) {
        groupMap[chainKey] = {
          groupId: `group:${chainKey}`,
          name: path.name,
          sources: [sourceNode],
          sharedChain: effectiveSharedChain,
          targets: effectiveTargetNode ? [effectiveTargetNode] : [],
          isRoleTarget: isDirectRoleTarget,
          targetRole: isDirectRoleTarget ? targetNode : undefined,
          downstreamAssets: [...rawDownstream],
          originalPaths: [path],
          severity: sev,
          maxRiskScore: score,
          blastRadiusSummary: path.blastRadius || 'Multiple connected resources',
          mitreTechniques: [...(path.mitreTechniques || [])],
          recommendation: path.recommendation || '',
          description: path.description || '',
          diffStatus,
          currentRiskScore: currentRisk,
          desiredRiskScore: desiredRisk,
          riskDelta,
        };
      } else {
        const group = groupMap[chainKey];
        group.originalPaths.push(path);

        // Deduplicate and append source identity
        const srcId = sourceNode.id || sourceNode.name;
        if (!group.sources.some(s => (s.id || s.name) === srcId)) {
          group.sources.push(sourceNode);
        }

        // Deduplicate and append target resource (never add source as target)
        if (effectiveTargetNode) {
          const tgtId = effectiveTargetNode.id || effectiveTargetNode.name;
          const isSourceAlready = group.sources.some(s => (s.id || s.name) === tgtId);
          if (!isSourceAlready && !group.targets.some(t => (t.id || t.name) === tgtId)) {
            group.targets.push(effectiveTargetNode);
          }
        }

        // Deduplicate and append downstream reachable assets
        if (rawDownstream.length > 0) {
          if (!group.downstreamAssets) group.downstreamAssets = [];
          rawDownstream.forEach((da) => {
            const daId = da.id || da.name;
            if (!group.downstreamAssets!.some((existing) => (existing.id || existing.name) === daId)) {
              group.downstreamAssets!.push(da);
            }
          });
        }

        // Diff status prioritization: CHANGED > NEW > REMOVED > UNCHANGED
        if (diffStatus === 'CHANGED' || diffStatus === 'NEW') {
          group.diffStatus = diffStatus;
          if (currentRisk !== undefined) group.currentRiskScore = currentRisk;
          if (desiredRisk !== undefined) group.desiredRiskScore = desiredRisk;
          if (riskDelta !== undefined) group.riskDelta = riskDelta;
        } else if (!group.diffStatus && diffStatus) {
          group.diffStatus = diffStatus;
        }

        // Elevate severity if higher
        const severityValues: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
        const currentRank = severityValues[group.severity] || 1;
        const incomingSev = (path.severity || 'low').toLowerCase();
        const newRank = severityValues[incomingSev] || 1;
        if (newRank > currentRank) {
          group.severity = incomingSev as 'critical' | 'high' | 'medium' | 'low';
        }

        // Track max risk score
        if (score > group.maxRiskScore) {
          group.maxRiskScore = score;
        }

        // Union MITRE techniques
        (path.mitreTechniques || []).forEach(tech => {
          if (!group.mitreTechniques.includes(tech)) {
            group.mitreTechniques.push(tech);
          }
        });
      }
    });

    const severityRank: Record<ConsolidatedAttackPathGroup['severity'], number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
    };
    return Object.values(groupMap).sort((a, b) =>
      severityRank[b.severity] - severityRank[a.severity]
      || b.maxRiskScore - a.maxRiskScore
      || (a.sources[0]?.name || '').localeCompare(b.sources[0]?.name || '')
      || (a.targets[0]?.name || a.downstreamAssets?.[0]?.name || '').localeCompare(b.targets[0]?.name || b.downstreamAssets?.[0]?.name || '')
      || a.groupId.localeCompare(b.groupId)
    );
  }, [rawAttackPaths]);

  // Filtered Consolidated Groups
  const filteredGroups = useMemo(() => {
    return consolidatedGroups.filter(g => {
      const q = searchQuery.trim().toLowerCase();
      const matchesSearch = q === '' || 
        g.name.toLowerCase().includes(q) || 
        g.description.toLowerCase().includes(q) ||
        g.sources.some(s => s.name.toLowerCase().includes(q) || s.type.toLowerCase().includes(q)) ||
        g.sharedChain.some(n => n.name.toLowerCase().includes(q) || n.type.toLowerCase().includes(q)) ||
        g.targets.some(t => t.name.toLowerCase().includes(q) || t.type.toLowerCase().includes(q));

      const matchesSeverity = severityFilter === 'all' || g.severity === severityFilter;

      const matchesType = resourceTypeFilter === 'all' || 
        g.targets.some(t => normalizeGraphType(t.type).toLowerCase() === normalizeGraphType(resourceTypeFilter).toLowerCase());

      return matchesSearch && matchesSeverity && matchesType;
    });
  }, [consolidatedGroups, searchQuery, severityFilter, resourceTypeFilter]);

  // Active selected group
  const selectedGroup = useMemo(() => {
    return consolidatedGroups.find(g => g.groupId === selectedGroupId) || filteredGroups[0] || null;
  }, [consolidatedGroups, filteredGroups, selectedGroupId]);

  // 2. Build Merged Multi-Source & Multi-Target Branching DAG for Cytoscape
  const treeElements = useMemo(() => {
    const nodesMap: Record<string, any> = {};
    const edgesMap: Record<string, any> = {};

    const groupsToRender = filteredGroups.length > 0 ? filteredGroups : consolidatedGroups;

    groupsToRender.forEach((group) => {
      // 1. Add all source nodes
      group.sources.forEach((sourceNode) => {
        const sId = sourceNode.id || `node:${sourceNode.name}`;
        if (!nodesMap[sId]) {
          nodesMap[sId] = {
            data: {
              id: sId,
              label: sourceNode.name,
              type: sourceNode.type,
              isSource: true,
              riskScore: group.maxRiskScore
            }
          };
        }
      });

      // 2. Add shared intermediate privilege chain nodes
      group.sharedChain.forEach((node) => {
        const nodeId = node.id || `node:${node.name}`;
        if (!nodesMap[nodeId]) {
          nodesMap[nodeId] = {
            data: {
              id: nodeId,
              label: node.name,
              type: node.type,
              isShared: true,
              riskScore: group.maxRiskScore
            }
          };
        }
      });

      // 3. Connect sources -> First shared chain node
      const firstSharedNode = group.sharedChain[0];
      if (firstSharedNode) {
        const firstSharedId = firstSharedNode.id || `node:${firstSharedNode.name}`;
        group.sources.forEach((sourceNode) => {
          const sId = sourceNode.id || `node:${sourceNode.name}`;
          const edgeId = `src_edge:${sId}->${firstSharedId}`;
          if (!edgesMap[edgeId]) {
            edgesMap[edgeId] = {
              data: {
                id: edgeId,
                source: sId,
                target: firstSharedId,
                label: findExactEdgeLabel(group, sourceNode.id || sourceNode.name, firstSharedNode.id || firstSharedNode.name),
                groupIds: [group.groupId],
                severity: group.severity,
                diffStatus: group.diffStatus
              }
            };
          } else if (!edgesMap[edgeId].data.groupIds.includes(group.groupId)) {
            edgesMap[edgeId].data.groupIds.push(group.groupId);
          }
        });
      }

      // 4. Connect consecutive hops in the shared chain
      for (let i = 0; i < group.sharedChain.length - 1; i++) {
        const sNode = group.sharedChain[i];
        const tNode = group.sharedChain[i + 1];
        const sId = sNode.id || `node:${sNode.name}`;
        const tId = tNode.id || `node:${tNode.name}`;
        const edgeId = `chain_edge:${sId}->${tId}`;

        if (!edgesMap[edgeId]) {
          edgesMap[edgeId] = {
            data: {
              id: edgeId,
              source: sId,
              target: tId,
              label: findExactEdgeLabel(group, sNode.id || sNode.name, tNode.id || tNode.name),
              groupIds: [group.groupId],
              severity: group.severity,
              diffStatus: group.diffStatus
            }
          };
        } else if (!edgesMap[edgeId].data.groupIds.includes(group.groupId)) {
          edgesMap[edgeId].data.groupIds.push(group.groupId);
        }
      }

      // 5. Connect last shared chain node -> all target resources or downstream reachable assets
      const lastSharedNode = group.sharedChain.length > 0 
        ? group.sharedChain[group.sharedChain.length - 1] 
        : group.sources[0];
      const lastSharedId = lastSharedNode ? (lastSharedNode.id || `node:${lastSharedNode.name}`) : null;

      if (lastSharedId && lastSharedNode) {
        // Direct target resources (Cases B, C, D)
        group.targets.forEach((targetNode) => {
          const targetId = targetNode.id || `node:${targetNode.name}`;
          if (!nodesMap[targetId]) {
            nodesMap[targetId] = {
              data: {
                id: targetId,
                label: targetNode.name,
                type: targetNode.type,
                isTarget: true,
                riskScore: group.maxRiskScore
              }
            };
          }

          const branchEdgeId = `tgt_edge:${lastSharedId}->${targetId}`;
          if (!edgesMap[branchEdgeId]) {
            edgesMap[branchEdgeId] = {
              data: {
                id: branchEdgeId,
                source: lastSharedId,
                target: targetId,
                label: findExactEdgeLabel(group, lastSharedNode.id || lastSharedNode.name, targetNode.id || targetNode.name),
                groupIds: [group.groupId],
                severity: group.severity,
                diffStatus: group.diffStatus
              }
            };
          } else if (!edgesMap[branchEdgeId].data.groupIds.includes(group.groupId)) {
            edgesMap[branchEdgeId].data.groupIds.push(group.groupId);
          }
        });

        // Downstream reachable assets (Case A - Role targets)
        if (group.isRoleTarget && group.downstreamAssets) {
          group.downstreamAssets.forEach((asset) => {
            const assetId = asset.id || `asset:${asset.name}`;
            if (!nodesMap[assetId]) {
              nodesMap[assetId] = {
                data: {
                  id: assetId,
                  label: asset.name,
                  type: asset.type,
                  isTarget: true,
                  isDownstream: true,
                  riskScore: asset.riskScore ?? group.maxRiskScore
                }
              };
            }

            const downstreamEdgeId = `downstream_edge:${lastSharedId}->${assetId}`;
            if (!edgesMap[downstreamEdgeId]) {
              edgesMap[downstreamEdgeId] = {
                data: {
                  id: downstreamEdgeId,
                  source: lastSharedId,
                  target: assetId,
                  label: findExactEdgeLabel(group, lastSharedNode.id || lastSharedNode.name, asset.id || asset.name) || (asset.evidence?.action ? 'ALLOWS' : 'REACHABLE'),
                  groupIds: [group.groupId],
                  severity: group.severity,
                  diffStatus: group.diffStatus
                }
              };
            } else if (!edgesMap[downstreamEdgeId].data.groupIds.includes(group.groupId)) {
              edgesMap[downstreamEdgeId].data.groupIds.push(group.groupId);
            }
          });
        }
      }
    });

    return [...Object.values(nodesMap), ...Object.values(edgesMap)];
  }, [filteredGroups, consolidatedGroups]);

  // Blast Radius Metric Strip Stats
  const blastRadiusStats = useMemo(() => {
    const uniqueIdentities = new Set<string>();
    const uniqueTargets = new Set<string>();
    const uniqueCriticalTargets = new Set<string>();
    let maxDepth = 0;

    rawAttackPaths.forEach(p => {
      if (p.nodes && p.nodes.length > 0) {
        const src = p.nodes[0];
        uniqueIdentities.add(src.id || src.name);
        const target = p.nodes[p.nodes.length - 1];
        const targetId = target.id || target.name;
        uniqueTargets.add(targetId);
        const t = target.type as string;
        if (p.severity === 'critical' || t === 'Secrets' || t === 'Secret' || t === 'RDS' || (target.riskScore && target.riskScore >= 70)) {
          uniqueCriticalTargets.add(targetId);
        }
      }
      // Include downstream reachable assets in targets count
      const downstream = p.downstream_reachable_assets || (p as any).downstreamReachableAssets || [];
      downstream.forEach((da: any) => {
        const dId = da.id || da.name;
        uniqueTargets.add(dId);
        const dt = da.type as string;
        if (p.severity === 'critical' || dt === 'Secrets' || dt === 'Secret' || dt === 'RDS' || (da.riskScore && da.riskScore >= 70)) {
          uniqueCriticalTargets.add(dId);
        }
      });
      if (p.nodes && p.nodes.length > maxDepth) {
        maxDepth = p.nodes.length;
      }
    });

    return {
      totalRawPaths: rawAttackPaths.length,
      consolidatedGroupCount: consolidatedGroups.length,
      compromisedIdentities: uniqueIdentities.size,
      reachableAssets: uniqueTargets.size,
      criticalAssets: uniqueCriticalTargets.size,
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
            'background-color': ENTITY_STYLES.User.backgroundColor,
            'border-color': ENTITY_STYLES.User.borderColor,
            'shape': 'ellipse',
            'width': '42px',
            'height': '42px'
          }
        },
        {
          selector: 'node[type="Group"]',
          style: {
            'background-color': ENTITY_STYLES.Group.backgroundColor,
            'border-color': ENTITY_STYLES.Group.borderColor,
            'border-width': '3px',
            'shape': 'round-rectangle',
            'width': '52px',
            'height': '42px'
          }
        },
        {
          selector: 'node[type="Policy"]',
          style: {
            'background-color': ENTITY_STYLES.Policy.backgroundColor,
            'border-color': ENTITY_STYLES.Policy.borderColor,
            'shape': 'diamond',
            'width': '42px',
            'height': '42px'
          }
        },
        {
          selector: 'node[type="Role"]',
          style: {
            'background-color': ENTITY_STYLES.Role.backgroundColor,
            'border-color': ENTITY_STYLES.Role.borderColor,
            'shape': 'hexagon',
            'width': '46px',
            'height': '46px'
          }
        },
        {
          selector: 'node[type="S3"]',
          style: {
            'background-color': ENTITY_STYLES.S3.backgroundColor,
            'border-color': ENTITY_STYLES.S3.borderColor,
            'shape': 'barrel'
          }
        },
        {
          selector: 'node[type="EC2"]',
          style: {
            'background-color': ENTITY_STYLES.EC2.backgroundColor,
            'border-color': ENTITY_STYLES.EC2.borderColor,
            'shape': 'round-rectangle'
          }
        },
        {
          selector: 'node[type="Lambda"]',
          style: {
            'background-color': ENTITY_STYLES.Lambda.backgroundColor,
            'border-color': ENTITY_STYLES.Lambda.borderColor,
            'shape': 'ellipse'
          }
        },
        {
          selector: 'node[type="RDS"]',
          style: {
            'background-color': ENTITY_STYLES.RDS.backgroundColor,
            'border-color': ENTITY_STYLES.RDS.borderColor,
            'shape': 'barrel'
          }
        },
        {
          selector: 'node[type="DynamoDB"]',
          style: {
            'background-color': ENTITY_STYLES.DynamoDB.backgroundColor,
            'border-color': ENTITY_STYLES.DynamoDB.borderColor,
            'shape': 'barrel'
          }
        },
        {
          selector: 'node[type="Secrets"], node[type="Secret"]',
          style: {
            'background-color': ENTITY_STYLES.Secrets.backgroundColor,
            'border-color': ENTITY_STYLES.Secrets.borderColor,
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
        {
          selector: 'edge[diffStatus = "NEW"]',
          style: {
            'line-color': '#10B981',
            'target-arrow-color': '#10B981',
            'width': 2.5,
            'line-style': 'dashed',
            'opacity': 0.95
          }
        },
        {
          selector: 'edge[diffStatus = "REMOVED"]',
          style: {
            'line-color': '#EF4444',
            'target-arrow-color': '#EF4444',
            'width': 2.5,
            'line-style': 'dashed',
            'opacity': 0.7
          }
        },
        {
          selector: 'edge[diffStatus = "CHANGED"]',
          style: {
            'line-color': '#F59E0B',
            'target-arrow-color': '#F59E0B',
            'width': 2.5,
            'opacity': 0.95
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
        g.sources.some(s => (s.id || `node:${s.name}`) === nodeId) ||
        g.sharedChain.some(n => (n.id || `node:${n.name}`) === nodeId) ||
        g.targets.some(t => (t.id || `node:${t.name}`) === nodeId) ||
        (g.downstreamAssets && g.downstreamAssets.some(d => (d.id || `asset:${d.name}`) === nodeId))
      );

      if (matchingGroup) {
        setSelectedGroupId(matchingGroup.groupId);
        // If clicking a source, set focused source
        if (matchingGroup.sources.some(s => (s.id || `node:${s.name}`) === nodeId)) {
          setFocusedSourceId(nodeId);
        } else {
          setFocusedSourceId(null);
        }
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

  // Apply Branch Highlighting on selectedGroup or focusedSource change
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      if (selectedGroup) {
        cy.elements().addClass('dimmed').removeClass('highlighted');

        const activeSources = focusedSourceId 
          ? selectedGroup.sources.filter(s => (s.id || `node:${s.name}`) === focusedSourceId)
          : selectedGroup.sources;

        const activeNodeIds = [
          ...activeSources.map(s => s.id || `node:${s.name}`),
          ...selectedGroup.sharedChain.map(n => n.id || `node:${n.name}`),
          ...selectedGroup.targets.map(t => t.id || `node:${t.name}`),
          ...(selectedGroup.downstreamAssets || []).map(d => d.id || `asset:${d.name}`)
        ];

        // Highlight nodes
        activeNodeIds.forEach(nId => {
          const ele = cy.getElementById(nId);
          if (ele.length > 0) {
            ele.removeClass('dimmed').addClass('highlighted');
          }
        });

        // Highlight group edges
        cy.edges().forEach(edge => {
          const groupIds: string[] = edge.data('groupIds') || [];
          if (groupIds.includes(selectedGroup.groupId)) {
            // If focusing on single source, only highlight edges from that source
            if (focusedSourceId) {
              const srcId = edge.source().id();
              const isOtherSource = selectedGroup.sources.some(s => (s.id || `node:${s.name}`) === srcId && srcId !== focusedSourceId);
              if (!isOtherSource) {
                edge.removeClass('dimmed').addClass('highlighted');
              }
            } else {
              edge.removeClass('dimmed').addClass('highlighted');
            }
          }
        });
      } else {
        cy.elements().removeClass('dimmed').removeClass('highlighted');
      }
    });
  }, [selectedGroup, focusedSourceId]);

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

  return (
    <div className="flex-1 min-h-0 p-6 space-y-6 overflow-y-auto bg-enterprise-bg select-none text-gray-200">
      
      {/* Header */}
      <div className="flex justify-between items-center flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <GitMerge className="w-6 h-6 text-enterprise-accent" />
            <span>Attack Paths</span>
          </h1>
          <p className="text-xs text-enterprise-subtext mt-1">
            See how identities can reach sensitive cloud resources and what access enables each path.
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
            <p className="text-[10px] text-enterprise-subtext font-bold uppercase tracking-wider">Consolidated Groups</p>
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
            {(['all', 's3', 'ec2', 'lambda', 'rds', 'dynamodb', 'secrets'] as const).map((t) => (
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
        <div className="attack-path-graph-panel bg-[#0F172A] border border-enterprise-border rounded-xl p-4 shadow-2xl relative overflow-hidden flex flex-col h-[480px]">
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
          <div className="graph-legend absolute bottom-6 left-6 z-10 bg-gray-900/90 backdrop-blur-md border border-gray-700 rounded-lg px-3 py-1.5 text-[10px] flex items-center gap-3 text-gray-300 flex-wrap max-w-2xl">
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: ENTITY_STYLES.User.backgroundColor }} /><span>User</span></div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2 rounded" style={{ backgroundColor: ENTITY_STYLES.Group.backgroundColor }} /><span>Group</span></div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rotate-45" style={{ backgroundColor: ENTITY_STYLES.Policy.backgroundColor }} /><span>Policy</span></div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: ENTITY_STYLES.Role.backgroundColor }} /><span>Role</span></div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2 rounded" style={{ backgroundColor: ENTITY_STYLES.S3.backgroundColor }} /><span>S3</span></div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2 rounded" style={{ backgroundColor: ENTITY_STYLES.EC2.backgroundColor }} /><span>EC2</span></div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: ENTITY_STYLES.Lambda.backgroundColor }} /><span>Lambda</span></div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2 rounded" style={{ backgroundColor: ENTITY_STYLES.RDS.backgroundColor }} /><span>RDS</span></div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2 rounded" style={{ backgroundColor: ENTITY_STYLES.DynamoDB.backgroundColor }} /><span>DynamoDB</span></div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: ENTITY_STYLES.Secrets.backgroundColor }} /><span>Secrets</span></div>
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
          filteredGroups.map((group, groupIndex) => {
            const isSelected = selectedGroup && selectedGroup.groupId === group.groupId;
            const correlationStatus = group.originalPaths.find(p => p.correlationStatus === 'OBSERVED_ATTACK_ACTIVITY' || (p as any).correlation_status === 'OBSERVED_ATTACK_ACTIVITY')?.correlationStatus ||
              group.originalPaths.find(p => p.correlationStatus === 'CORRELATED_ACTIVITY' || (p as any).correlation_status === 'CORRELATED_ACTIVITY')?.correlationStatus ||
              group.originalPaths.find(p => p.correlationStatus === 'OBSERVED_ACTIVITY' || (p as any).correlation_status === 'OBSERVED_ACTIVITY')?.correlationStatus ||
              'POSSIBLE_CAPABILITY';

            const privEsc = group.originalPaths.find(p => (p.privilegeEscalationDetails || (p as any).privilege_escalation_details)?.is_passrole)?.privilegeEscalationDetails ||
              (group.originalPaths.find(p => (p.privilegeEscalationDetails || (p as any).privilege_escalation_details)?.is_passrole) as any)?.privilege_escalation_details;

            const representativeEvidence = group.originalPaths.find(p => (p.evidence || []).length > 0)?.evidence || [];
            const minEvidenceConfidence = group.originalPaths.length
              ? Math.min(...group.originalPaths.map(path => path.confidence ?? 0))
              : undefined;
            const confidenceBasis = group.originalPaths.find(path => path.confidence_basis)?.confidence_basis;
            const isEvidenceOpen = Boolean(evidenceExpanded[group.groupId]);
            const aiResponse = aiPathResponses[group.groupId];
            const aiError = aiPathErrors[group.groupId];
            const isAiLoading = Boolean(aiPathLoading[group.groupId]);

            return (
              <div
                key={group.groupId}
                onClick={() => { setSelectedGroupId(group.groupId); setFocusedSourceId(null); }}
                className={`bg-enterprise-card border rounded-2xl p-6 transition-all shadow-xl flex flex-col gap-5 cursor-pointer ${
                  isSelected
                    ? 'border-red-500/80 bg-[#141B2D] ring-1 ring-red-500/50 shadow-red-500/10'
                    : group.diffStatus === 'NEW'
                    ? 'border-emerald-500/50 bg-emerald-950/10 hover:border-emerald-500'
                    : group.diffStatus === 'REMOVED'
                    ? 'border-red-500/40 bg-red-950/10 opacity-70 hover:opacity-90'
                    : group.diffStatus === 'CHANGED'
                    ? 'border-amber-500/50 bg-amber-950/10 hover:border-amber-500'
                    : 'border-enterprise-border hover:border-gray-700'
                }`}
              >
                {/* Group Card Top Header Bar */}
                <div className="flex flex-wrap items-start justify-between gap-4 border-b border-enterprise-border pb-4">
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      {group.diffStatus && (
                        <span
                          className={`text-[10px] font-black px-2.5 py-0.5 rounded uppercase tracking-wider border flex items-center gap-1.5 ${
                            group.diffStatus === 'NEW'
                              ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50'
                              : group.diffStatus === 'REMOVED'
                              ? 'bg-red-500/20 text-red-400 border-red-500/50 line-through'
                              : group.diffStatus === 'CHANGED'
                              ? 'bg-amber-500/20 text-amber-300 border-amber-500/50'
                              : 'bg-gray-800 text-gray-400 border-gray-700'
                          }`}
                        >
                          {group.diffStatus === 'NEW' && '+ NEW PATH'}
                          {group.diffStatus === 'REMOVED' && '- REMOVED PATH'}
                          {group.diffStatus === 'CHANGED' && (
                            <span>
                              CHANGED (Current Risk: {group.currentRiskScore ?? 'â€”'} â†’ Desired Risk: {group.desiredRiskScore ?? 'â€”'}{' '}
                              | Delta:{' '}
                              {group.riskDelta !== undefined
                                ? (group.riskDelta > 0 ? `+${group.riskDelta}` : group.riskDelta)
                                : '0'})
                            </span>
                          )}
                          {group.diffStatus === 'UNCHANGED' && 'UNCHANGED'}
                        </span>
                      )}
                      {correlationStatus === 'OBSERVED_ATTACK_ACTIVITY' ? (
                        <span className="text-[10px] font-black px-2.5 py-0.5 rounded uppercase tracking-wider bg-red-500/20 text-red-400 border border-red-500/50 flex items-center gap-1">
                          <Activity className="w-3 h-3 text-red-400 animate-pulse" />
                          <span>Observed Attack Activity</span>
                        </span>
                      ) : correlationStatus === 'CORRELATED_ACTIVITY' ? (
                        <span className="text-[10px] font-black px-2.5 py-0.5 rounded uppercase tracking-wider bg-blue-500/20 text-blue-300 border border-blue-500/50 flex items-center gap-1">
                          <Activity className="w-3 h-3 text-blue-400" />
                          <span>Correlated Activity</span>
                        </span>
                      ) : correlationStatus === 'OBSERVED_ACTIVITY' ? (
                        <span className="text-[10px] font-black px-2.5 py-0.5 rounded uppercase tracking-wider bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 flex items-center gap-1">
                          <Activity className="w-3 h-3 text-cyan-400" />
                          <span>Observed Activity</span>
                        </span>
                      ) : (
                        <span className="text-[10px] font-black px-2.5 py-0.5 rounded uppercase tracking-wider bg-gray-800/80 text-gray-400 border border-gray-700 flex items-center gap-1">
                          <ShieldCheck className="w-3 h-3 text-gray-400" />
                          <span>Possible Capability (Static)</span>
                        </span>
                      )}
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
                        RISK SCORE: {group.maxRiskScore} / 100
                      </span>
                      {minEvidenceConfidence !== undefined && minEvidenceConfidence > 0 && (
                        <span
                          className="text-[10px] text-cyan-300 bg-cyan-950/50 border border-cyan-500/40 px-2.5 py-0.5 rounded font-mono font-bold"
                          title={`Evidence confidence: ${confidenceBasis || 'not classified'}. This measures evidence quality, not whether the path has been executed.`}
                        >
                          EVIDENCE CONFIDENCE: {minEvidenceConfidence}%
                        </span>
                      )}
                      <span className="text-[10px] text-blue-400 bg-blue-950/50 border border-blue-500/40 px-2.5 py-0.5 rounded font-mono font-bold flex items-center gap-1">
                        <Users className="w-3 h-3 text-blue-400" />
                        <span>{group.sources.length} Compromised Source{group.sources.length > 1 ? 's' : ''}</span>
                      </span>
                      {group.targets.length > 0 && (
                        <span className="text-[10px] text-purple-300 bg-purple-950/50 border border-purple-500/40 px-2.5 py-0.5 rounded font-mono font-bold flex items-center gap-1">
                          <Share2 className="w-3 h-3 text-purple-400" />
                          <span>{group.targets.length} Reachable Target{group.targets.length > 1 ? 's' : ''}</span>
                        </span>
                      )}
                      <h3 className="text-base font-bold text-white ml-1">
                        Attack Path {groupIndex + 1}: {group.name.replace(/^Attack Path\s+\d+\s*:\s*/i, '')}
                      </h3>
                    </div>
                    <p className="text-xs text-enterprise-subtext leading-relaxed">{group.description}</p>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        const selectedPath = group.originalPaths[0];
                        if (selectedPath) handleHighlightInFullGraph(selectedPath);
                      }}
                      disabled={!group.originalPaths[0]?.nodes?.length}
                      className="inline-flex items-center gap-2 rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-2 text-sm font-semibold text-enterprise-text transition-colors hover:border-enterprise-accent/50 hover:text-enterprise-accent focus:outline-none focus:ring-2 focus:ring-enterprise-accent/50 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <Network aria-hidden="true" className="h-4 w-4" />
                      Trace in Cloud Graph
                    </button>
                    <button
                      type="button"
                      disabled={isAiLoading}
                      onClick={(event) => {
                        event.stopPropagation();
                        void handleExplainPathWithAI(group);
                      }}
                      className="inline-flex items-center gap-2 rounded-lg border border-enterprise-accent/40 bg-enterprise-accent/10 px-3 py-2 text-sm font-semibold text-enterprise-accent transition-colors hover:bg-enterprise-accent/20 focus:outline-none focus:ring-2 focus:ring-enterprise-accent/50 disabled:cursor-wait disabled:opacity-60"
                    >
                      {isAiLoading
                        ? <LoaderCircle aria-hidden="true" className="h-4 w-4 animate-spin" />
                        : <Sparkles aria-hidden="true" className="h-4 w-4" />}
                      {isAiLoading
                        ? 'Explaining…'
                        : aiResponse ? 'Explain again' : 'Explain with AI'}
                    </button>
                  </div>
                </div>

                {(aiResponse || aiError) && (
                  <section
                    aria-live="polite"
                    className="rounded-xl border border-enterprise-accent/30 bg-enterprise-accent/5 p-4 text-enterprise-text"
                    onClick={(event) => event.stopPropagation()}
                  >
                    <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
                      <Sparkles aria-hidden="true" className="h-4 w-4 text-enterprise-accent" />
                      AI explanation
                    </div>
                    {aiError && (
                      <p role="alert" className="text-sm text-red-700 dark:text-red-300">{aiError}</p>
                    )}
                    {aiResponse && (
                      <div className="space-y-3 text-sm">
                        <p className="text-xs text-enterprise-subtext">Explanation for the primary path in this consolidated group.</p>
                        {aiResponse.summary && <p className="font-semibold">{aiResponse.summary}</p>}
                        <p className="whitespace-pre-wrap leading-relaxed">{aiResponse.analysis || aiResponse.text}</p>
                        {aiResponse.evidence?.length ? (
                          <div>
                            <p className="mb-1 text-xs font-semibold text-enterprise-subtext">Evidence</p>
                            <ul className="list-disc space-y-1 pl-5">{aiResponse.evidence.map((item, index) => <li key={index}>{item}</li>)}</ul>
                          </div>
                        ) : null}
                        {aiResponse.recommendations?.length ? (
                          <div>
                            <p className="mb-1 text-xs font-semibold text-enterprise-subtext">Suggested remediation</p>
                            <ol className="list-decimal space-y-1 pl-5">{aiResponse.recommendations.map((item, index) => <li key={index}>{item}</li>)}</ol>
                          </div>
                        ) : null}
                        {aiResponse.limitations?.length ? <p className="text-xs text-enterprise-subtext">Scope: {aiResponse.limitations.join(' ')}</p> : null}
                        <p className="text-xs text-enterprise-subtext">AI guidance is advisory. Verify the path evidence and review changes before applying them.</p>
                      </div>
                    )}
                  </section>
                )}

                {/* Observed Attack Activity Callout Banner */}
                {(() => {
                  const observedAttack = group.originalPaths.find(p => p.correlationStatus === 'OBSERVED_ATTACK_ACTIVITY' || (p as any).correlation_status === 'OBSERVED_ATTACK_ACTIVITY')?.observedActivity?.[0] ||
                    (group.originalPaths.find(p => p.correlationStatus === 'OBSERVED_ATTACK_ACTIVITY' || (p as any).correlation_status === 'OBSERVED_ATTACK_ACTIVITY') as any)?.observed_activity?.[0];
                  
                  if (!observedAttack) return null;

                  return (
                    <div className="bg-red-950/40 border border-red-500/60 rounded-xl p-4 flex items-start gap-3.5 text-xs shadow-xl">
                      <div className="p-2 bg-red-500/20 rounded-lg text-red-400 shrink-0 mt-0.5">
                        <Activity className="w-5 h-5 animate-pulse text-red-400" />
                      </div>
                      <div className="space-y-2 w-full font-mono">
                        <div className="flex items-center justify-between flex-wrap gap-2">
                          <span className="font-bold text-red-300 text-sm flex items-center gap-2">
                            <span>ðŸš¨ Active Attack Observed in CloudTrail:</span>
                            <span className="text-white px-2 py-0.5 bg-red-900/60 rounded border border-red-500/40 font-bold">
                              {observedAttack.event_name || observedAttack.eventName || 'Security Event'}
                            </span>
                          </span>
                          <span className="text-[10px] text-gray-300 bg-black/50 px-2.5 py-1 rounded border border-red-500/30">
                            Event ID: {observedAttack.event_id || observedAttack.eventId || 'N/A'}
                          </span>
                        </div>
                        
                        <p className="text-[11px] text-gray-200 font-sans leading-relaxed">
                          <strong className="text-red-300 font-bold">Reason:</strong> {observedAttack.reason || 'CloudTrail recorded runtime activity matching a specific transition in this attack path.'}
                        </p>

                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2 text-[10px] pt-1.5 border-t border-red-900/40">
                          <div>
                            <span className="text-gray-400 font-sans block">Event Time:</span>
                            <span className="text-white font-bold">{observedAttack.event_time || observedAttack.timestamp || 'N/A'}</span>
                          </div>
                          <div>
                            <span className="text-gray-400 font-sans block">Principal:</span>
                            <span className="text-blue-300 font-bold">{observedAttack.principal || observedAttack.actor_name || observedAttack.actor || 'Unknown'}</span>
                          </div>
                          <div>
                            <span className="text-gray-400 font-sans block">Target:</span>
                            <span className="text-amber-300 font-bold">{observedAttack.target_name || observedAttack.target || 'N/A'}</span>
                          </div>
                          <div>
                            <span className="text-gray-400 font-sans block">Matched Transition:</span>
                            <span className="text-emerald-300 font-bold">
                              {observedAttack.matched_transition?.description || observedAttack.matched_transition?.relationship || 'Path Transition'}
                            </span>
                          </div>
                        </div>

                        {observedAttack.evidence && (
                          <div className="text-[9px] text-gray-400 pt-1 font-mono">
                            <span className="text-gray-500">Evidence Classification:</span> {observedAttack.evidence.classification || 'OBSERVED_ATTACK_ACTIVITY'} | 
                            <span className="text-gray-500 ml-1">Source IP:</span> {observedAttack.evidence.source_ip || observedAttack.source_ip || 'N/A'} |
                            <span className="text-gray-500 ml-1">Region:</span> {observedAttack.evidence.region || observedAttack.region || 'global'}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })()}

                {/* Privilege Escalation Callout Banner */}
                {privEsc && (
                  <div className="bg-purple-950/40 border border-purple-500/50 rounded-xl p-3.5 flex items-start gap-3 text-xs shadow-lg">
                    <div className="p-2 bg-purple-500/20 rounded-lg text-purple-400 shrink-0 mt-0.5">
                      <Key className="w-4 h-4" />
                    </div>
                    <div className="space-y-1.5 w-full">
                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <span className="font-bold text-purple-200 text-xs">
                          Privilege Escalation Vector: {privEsc.trigger_permission || 'iam:PassRole'}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 bg-purple-900/60 rounded text-purple-300 border border-purple-500/30 font-bold">
                          Target Role: {privEsc.target_role || 'Target Role'}
                        </span>
                      </div>
                      <p className="text-[11px] text-gray-300">
                        <strong className="text-purple-300">Service Trust:</strong> {privEsc.target_role_trust_evidence || 'Trust policy allows service execution'}
                      </p>
                      {privEsc.risk_elevation && (
                        <p className="text-[11px] text-amber-300/90 font-medium">
                          <strong>Risk Elevation:</strong> {privEsc.risk_elevation}
                        </p>
                      )}
                    </div>
                  </div>
                )}

                {/* EXACT REFERENCE DESIGN: VERTICAL HIERARCHICAL BRANCHING DIAGRAM */}
                <div className="bg-[#0B1120]/80 rounded-xl p-5 border border-enterprise-border/80 flex flex-col items-center select-none shadow-inner">
                  
                  {/* LAYER 1: MULTIPLE SOURCE IDENTITIES / WORKLOADS (CONVERGING AT TOP) */}
                  <div className="w-full flex flex-col items-center">
                    <div className="flex items-center gap-2 mb-2">
                      <Users className="w-3.5 h-3.5 text-blue-400" />
                      <span className="text-[10px] font-mono font-bold text-blue-400 uppercase tracking-wider">
                        Source Entities ({group.sources.length})
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center justify-center gap-2 max-w-2xl">
                      {group.sources.map((src) => {
                        const isSourceFocused = focusedSourceId === (src.id || `node:${src.name}`);
                        const srcStyle = getGraphEntityStyle(src.type);
                        const srcType = src.type || 'Identity';
                        return (
                          <button
                            key={src.id || src.name}
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedGroupId(group.groupId);
                              setFocusedSourceId(prev => prev === (src.id || `node:${src.name}`) ? null : (src.id || `node:${src.name}`));
                            }}
                            className={`px-3 py-1.5 rounded-lg border flex items-center gap-2 shadow-md transition-all ${
                              isSourceFocused
                                ? 'bg-blue-600 border-blue-400 text-white ring-2 ring-blue-400 shadow-blue-500/20 scale-105'
                                : `${srcStyle.cardBgBorder} text-gray-100 hover:brightness-125`
                            }`}
                            title={`Click to focus on ${src.name} (${srcType}) trace`}
                          >
                            <span
                              className="w-2.5 h-2.5 rounded-full shrink-0 shadow-sm"
                              style={{ backgroundColor: srcStyle.dotBg }}
                            />
                            <span className="font-bold text-xs font-mono">{src.name}</span>
                            <span className="text-[8px] opacity-80 uppercase font-semibold tracking-wider px-1 py-0.2 bg-black/40 rounded border border-white/10">
                              {srcType}
                            </span>
                          </button>
                        );
                      })}
                    </div>

                    {/* Convergence Line down to shared chain */}
                    <div className="flex flex-col items-center py-2">
                      {group.sources.length > 1 && (
                        <div className="w-48 h-[2px] bg-gradient-to-r from-blue-500/20 via-blue-500 to-blue-500/20 my-0.5" />
                      )}
                      {(() => {
                        const lbl = group.sharedChain.length > 0 && group.sources.length > 0
                          ? findExactEdgeLabel(group, group.sources[0].id || group.sources[0].name, group.sharedChain[0].id || group.sharedChain[0].name)
                          : (group.targets.length > 0 && group.sources.length > 0
                              ? findExactEdgeLabel(group, group.sources[0].id || group.sources[0].name, group.targets[0].id || group.targets[0].name)
                              : '');
                        return lbl ? (
                          <span className="text-[8px] font-mono text-gray-500 font-bold uppercase tracking-wider mb-0.5">
                            {lbl}
                          </span>
                        ) : null;
                      })()}
                      <div className="w-0.5 h-3 bg-gradient-to-b from-gray-600 to-gray-400" />
                      <ArrowDown className="w-3.5 h-3.5 text-gray-400 -mt-1" />
                    </div>
                  </div>

                  {/* LAYER 2: SHARED INTERMEDIATE PRIVILEGE CHAIN (Rendered ONCE) */}
                  {group.sharedChain.length > 0 ? (
                    <div className="flex flex-col items-center w-full max-w-xl">
                      {group.sharedChain.map((node, index) => {
                        const nextNode = group.sharedChain[index + 1];
                        const relLabel = nextNode
                          ? findExactEdgeLabel(group, node.id || node.name, nextNode.id || nextNode.name)
                          : (group.targets.length > 0
                              ? findExactEdgeLabel(group, node.id || node.name, group.targets[0].id || group.targets[0].name)
                              : '');
                        const nodeStyle = getGraphEntityStyle(node.type);

                        return (
                          <div key={node.id || node.name} className="flex flex-col items-center w-full">
                            {/* Node Box */}
                            <div className={`px-4 py-2 rounded-xl border flex items-center gap-3 shadow-md min-w-[240px] justify-center ${nodeStyle.cardBgBorder}`}>
                              <span
                                className="w-2.5 h-2.5 rounded-full shrink-0 shadow-sm"
                                style={{ backgroundColor: nodeStyle.dotBg }}
                              />
                              <div className="text-center">
                                <p className="font-bold text-xs text-white leading-tight font-mono">{node.name}</p>
                                <p className="text-[9px] text-gray-400 uppercase tracking-wider font-semibold mt-0.5">{node.type}</p>
                              </div>
                            </div>

                            {/* Vertical Connector Down */}
                            <div className="flex flex-col items-center py-1">
                              {relLabel ? (
                                <span className="text-[8px] font-mono text-gray-500 font-bold uppercase tracking-wider mb-0.5">
                                  {relLabel}
                                </span>
                              ) : null}
                              <div className="w-0.5 h-3 bg-gradient-to-b from-gray-600 to-gray-400" />
                              <ArrowDown className="w-3.5 h-3.5 text-gray-400 -mt-1" />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  ) : null}

                  {/* LAYER 3A: DIRECT RESOURCE TARGETS (Cases B, C, D) */}
                  {!group.isRoleTarget && group.targets.length > 0 && (
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
                          const normType = normalizeGraphType(target.type);
                          const targetStyle = getGraphEntityStyle(target.type);
                          const isCritical = normType === 'Secrets' || (normType === 'RDS' && (target.riskScore ?? 0) >= 80);
                          const isCompute = normType === 'EC2' || normType === 'Lambda';

                          return (
                            <div
                              key={target.id || target.name}
                              className={`px-3.5 py-2 rounded-xl border flex items-center gap-2.5 shadow-lg transition-transform hover:scale-105 ${targetStyle.cardBgBorder}`}
                            >
                              <span
                                className={`w-2.5 h-2.5 rounded-full shrink-0 shadow-sm ${
                                  normType === 'Secrets' ? 'animate-pulse' : ''
                                }`}
                                style={{ backgroundColor: targetStyle.dotBg }}
                              />
                              <div>
                                <p className="font-bold text-xs text-white leading-tight font-mono">{target.name}</p>
                                <div className="flex items-center gap-1.5 mt-0.5">
                                  <span className="text-[9px] text-gray-300 font-mono">
                                    Type: <strong className="text-white uppercase">{target.type || normType}</strong>
                                  </span>
                                  {isCritical && (
                                    <span className="text-[8px] text-red-400 font-bold bg-red-950 px-1 rounded uppercase">CRITICAL</span>
                                  )}
                                  {isCompute && (
                                    <span className="text-[8px] text-emerald-400 font-bold bg-emerald-950 px-1 rounded uppercase">COMPUTE</span>
                                  )}
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* LAYER 3B: DOWNSTREAM REACHABLE ASSETS (Case A - Role-Target Paths) */}
                  {group.isRoleTarget && group.downstreamAssets && group.downstreamAssets.length > 0 && (
                    <div className="w-full flex flex-col items-center mt-2">
                      {/* Distribution Line with Downstream Impact Badge */}
                      <div className="w-full flex flex-col items-center">
                        <div className="w-3/4 max-w-2xl h-[2px] bg-gradient-to-r from-purple-500/20 via-purple-500 to-purple-500/20 my-1 relative">
                          <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 bg-[#0B1120] px-2.5 py-0.5 text-[8px] font-mono font-bold text-purple-300 uppercase tracking-widest border border-purple-500/50 rounded-full shadow-sm flex items-center gap-1.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-purple-400 animate-pulse" />
                            Downstream Reachable Assets ({group.downstreamAssets.length})
                          </div>
                        </div>
                        <p className="text-[10px] text-gray-400 mt-2 font-mono text-center">
                          Blast-radius cloud assets accessible via assumed role <strong className="text-purple-300">{group.targetRole?.name || 'elevated role'}</strong>
                        </p>
                      </div>

                      {/* Downstream Assets Grid with Canonical Resource Colors */}
                      <div className="flex flex-wrap items-center justify-center gap-3 mt-3 w-full">
                        {group.downstreamAssets.map((asset) => {
                          const normType = normalizeGraphType(asset.type);
                          const assetStyle = getGraphEntityStyle(asset.type);
                          const isCritical = normType === 'Secrets' || (normType === 'RDS' && (asset.riskScore ?? 0) >= 80);
                          const isCompute = normType === 'EC2' || normType === 'Lambda';

                          return (
                            <div
                              key={asset.id || asset.name}
                              onClick={(e) => {
                                e.stopPropagation();
                                setInspectedAsset(asset);
                              }}
                              className={`px-3.5 py-2 rounded-xl border flex items-center gap-2.5 shadow-lg transition-all hover:scale-105 cursor-pointer hover:ring-1 hover:ring-white/40 ${assetStyle.cardBgBorder}`}
                              title="Click to inspect asset evidence and access details"
                            >
                              <span
                                className={`w-2.5 h-2.5 rounded-full shrink-0 shadow-sm ${
                                  normType === 'Secrets' ? 'animate-pulse' : ''
                                }`}
                                style={{ backgroundColor: assetStyle.dotBg }}
                              />
                              <div>
                                <p className="font-bold text-xs text-white leading-tight font-mono">{asset.name}</p>
                                <div className="flex items-center gap-1.5 mt-0.5">
                                  <span className="text-[9px] text-gray-300 font-mono">
                                    Type: <strong className="text-white uppercase">{asset.type || normType}</strong>
                                  </span>
                                  {isCritical && (
                                    <span className="text-[8px] text-red-400 font-bold bg-red-950 px-1 rounded uppercase">CRITICAL</span>
                                  )}
                                  {isCompute && (
                                    <span className="text-[8px] text-emerald-400 font-bold bg-emerald-950 px-1 rounded uppercase">COMPUTE</span>
                                  )}
                                  {asset.region && (
                                    <span className="text-[8px] text-gray-400 font-mono">{asset.region}</span>
                                  )}
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Bottom Impact Summary Bar */}
                  <div className="mt-5 pt-3 border-t border-gray-800/80 w-full flex items-center justify-between text-xs text-gray-400 flex-wrap gap-2">
                    <div className="flex flex-col gap-1">
                      {(() => {
                        const assetsToBreakDown = (group.isRoleTarget && group.downstreamAssets && group.downstreamAssets.length > 0)
                          ? group.downstreamAssets
                          : group.targets;
                        
                        // Count unique canonical assets
                        const uniqueAssetsMap = new Map<string, string>();
                        assetsToBreakDown.forEach(a => {
                          const aId = a.id || a.name;
                          const aType = normalizeGraphType(a.type);
                          if (!uniqueAssetsMap.has(aId)) {
                            uniqueAssetsMap.set(aId, aType);
                          }
                        });
                        const totalUnique = uniqueAssetsMap.size;

                        const counts: Record<string, number> = {};
                        uniqueAssetsMap.forEach(type => {
                          counts[type] = (counts[type] || 0) + 1;
                        });
                        const items = Object.entries(counts).map(([type, count]) => `${count} ${type}`);

                        // Documented severity mapping based on reachable unique cloud assets
                        let vectorSeverity = 'Low';
                        if (totalUnique >= 5 || group.severity === 'critical') vectorSeverity = 'High';
                        else if (totalUnique >= 2 || group.severity === 'high') vectorSeverity = 'Medium';

                        return (
                          <>
                            <div className="flex items-center gap-2">
                              <Flame className="w-3.5 h-3.5 text-red-400" />
                              <span className="font-mono text-[11px]">
                                <strong className="text-white">Blast Radius:</strong>{' '}
                                <span className={vectorSeverity === 'High' ? 'text-red-400 font-bold' : vectorSeverity === 'Medium' ? 'text-amber-400 font-bold' : 'text-blue-400 font-bold'}>
                                  {vectorSeverity}
                                </span>{' '}
                                ({totalUnique} unique cloud asset{totalUnique !== 1 ? 's' : ''})
                              </span>
                            </div>
                            {items.length > 0 && (
                              <div className="flex flex-wrap items-center gap-1.5 ml-5 mt-0.5">
                                <span className="text-[9px] text-gray-500 uppercase tracking-wider font-semibold">Assets:</span>
                                {items.map((item, idx) => (
                                  <span key={idx} className="px-1.5 py-0.2 bg-gray-900 text-[9px] font-mono text-gray-300 rounded border border-gray-800">
                                    {item}
                                  </span>
                                ))}
                              </div>
                            )}
                          </>
                        );
                      })()}
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

                {/* Step-by-step Transition Evidence Accordion */}
                {representativeEvidence.length > 0 && (
                  <div className="border border-enterprise-border/80 bg-[#0B1120]/60 rounded-xl p-4">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setEvidenceExpanded(prev => ({ ...prev, [group.groupId]: !prev[group.groupId] }));
                      }}
                      className="flex items-center justify-between w-full text-xs font-semibold text-gray-300 hover:text-white transition-colors"
                    >
                      <span className="flex items-center gap-2">
                        <FileText className="w-4 h-4 text-blue-400" />
                        <span>Step-by-Step Transition Provenance & Authorization Evidence ({representativeEvidence.length} hops)</span>
                      </span>
                      {isEvidenceOpen ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
                    </button>
                    {isEvidenceOpen && (
                      <div className="mt-3 space-y-2">
                        {representativeEvidence.map((ev, i) => (
                          <div key={i} className="bg-gray-900/90 border border-gray-800 rounded-lg p-3 text-xs flex flex-col gap-1.5 font-mono">
                            <div className="flex items-center justify-between flex-wrap gap-2">
                              <span className="text-blue-400 font-bold text-xs">{ev.from_node || (ev as any).fromNode || `Step ${i + 1}`} â†’ {ev.to_node || (ev as any).toNode}</span>
                              <span className="text-[10px] px-2 py-0.5 rounded bg-blue-950 border border-blue-500/30 text-blue-300 font-bold">
                                {ev.relationship || ev.action || 'TRANSITION'}
                              </span>
                              {ev.access_mode && (
                                <span className={`text-[10px] px-2 py-0.5 rounded border font-bold uppercase ${
                                  ev.access_mode === 'read' ? 'bg-sky-950 border-sky-500/30 text-sky-300' :
                                  ev.access_mode === 'write' ? 'bg-amber-950 border-amber-500/30 text-amber-300' :
                                  ev.access_mode === 'execute' ? 'bg-purple-950 border-purple-500/30 text-purple-300' :
                                  ev.access_mode === 'admin' ? 'bg-red-950 border-red-500/30 text-red-300' :
                                  'bg-gray-800 border-gray-600 text-gray-300'
                                }`}>
                                  {ev.access_mode}
                                </span>
                              )}
                              {ev.workload_pivot_capability && (
                                <span className="text-[10px] px-2 py-0.5 rounded border bg-red-950 border-red-500/30 text-red-300 font-bold uppercase">
                                  Workload pivot: {ev.workload_pivot_capability}
                                </span>
                              )}
                            </div>
                            {ev.why && <p className="text-[11px] text-gray-300 font-sans">{ev.why}</p>}
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-2 text-[10px] text-gray-400 pt-1 border-t border-gray-800/60">
                              <div><span className="text-gray-500 font-sans">IAM action:</span> <span className="text-cyan-300">{ev.actions?.join(', ') || ev.action || ev.required_permission || '—'}</span></div>
                              <div><span className="text-gray-500 font-sans">Policy:</span> <span className="text-gray-300">{ev.policy_name || (ev as any).policyName || 'Implicit / Attached'}</span></div>
                              <div><span className="text-gray-500 font-sans">Statement:</span> <span className="text-gray-300">{ev.statement_sid || (ev as any).statementSid || 'Allow'}</span></div>
                              <div><span className="text-gray-500 font-sans">Decision:</span> <span className="text-emerald-400 font-bold">{ev.decision || 'ALLOW'}</span></div>
                              <div><span className="text-gray-500 font-sans">Conditions:</span> <span className="text-gray-300">{ev.condition_status || (ev as any).conditionStatus || 'Unconditional'}</span></div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

              </div>
            );
          })
        )}
      </div>

      {/* Downstream Reachable Asset Inspection Modal */}
      {inspectedAsset && (
        <div
          className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4"
          onClick={() => setInspectedAsset(null)}
        >
          <div
            className="bg-[#0B1120] border border-gray-700 rounded-2xl max-w-lg w-full p-6 shadow-2xl relative"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between border-b border-gray-800 pb-3">
              <div className="flex items-center gap-2.5">
                <span
                  className="w-3 h-3 rounded-full shrink-0"
                  style={{ backgroundColor: getGraphEntityStyle(inspectedAsset.type).dotBg }}
                />
                <div>
                  <h3 className="font-bold text-sm text-white font-mono">{inspectedAsset.name}</h3>
                  <p className="text-[10px] text-gray-400 font-mono mt-0.5">
                    Type: <strong className="text-white uppercase">{inspectedAsset.type}</strong>
                    {inspectedAsset.region && ` â€¢ Region: ${inspectedAsset.region}`}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setInspectedAsset(null)}
                className="text-gray-400 hover:text-white px-2 py-1 rounded-lg hover:bg-gray-800 text-xs font-mono transition-colors"
              >
                âœ•
              </button>
            </div>

            <div className="mt-4 space-y-3 text-xs">
              {inspectedAsset.arn && (
                <div>
                  <span className="text-[10px] text-gray-500 uppercase font-semibold block">Resource ARN</span>
                  <span className="font-mono text-gray-300 break-all text-[11px] bg-gray-900/80 px-2 py-1 rounded block border border-gray-800 mt-1">
                    {inspectedAsset.arn}
                  </span>
                </div>
              )}

              <div className="grid grid-cols-2 gap-2">
                <div className="bg-gray-900/60 p-2.5 rounded-xl border border-gray-800">
                  <span className="text-[10px] text-gray-500 uppercase font-semibold block">Category</span>
                  <span className="font-mono text-white text-xs mt-0.5 block">{inspectedAsset.access_category || 'CLOUD_RESOURCE'}</span>
                </div>
                <div className="bg-gray-900/60 p-2.5 rounded-xl border border-gray-800">
                  <span className="text-[10px] text-gray-500 uppercase font-semibold block">Risk Score</span>
                  <span className="font-mono text-white text-xs mt-0.5 block">{inspectedAsset.riskScore ?? 50}/100</span>
                </div>
              </div>

              {inspectedAsset.evidence && (
                <div className="bg-gray-950/70 p-3 rounded-xl border border-gray-800 space-y-1.5">
                  <span className="text-[10px] text-purple-400 uppercase font-semibold tracking-wider block">
                    Authorization & Provenance Evidence
                  </span>
                  {inspectedAsset.evidence.policy_name && (
                    <p className="text-gray-300 text-[11px] font-mono">
                      <strong className="text-gray-400">Policy:</strong> {inspectedAsset.evidence.policy_name}
                    </p>
                  )}
                  {inspectedAsset.evidence.action && (
                    <p className="text-gray-300 text-[11px] font-mono">
                      <strong className="text-gray-400">Allowed Action:</strong>{' '}
                      {Array.isArray(inspectedAsset.evidence.action)
                        ? inspectedAsset.evidence.action.join(', ')
                        : String(inspectedAsset.evidence.action)}
                    </p>
                  )}
                  {inspectedAsset.evidence.why && (
                    <p className="text-gray-300 text-[11px] font-mono">
                      <strong className="text-gray-400">Reason:</strong> {inspectedAsset.evidence.why}
                    </p>
                  )}
                </div>
              )}
            </div>

            <div className="mt-5 flex justify-end">
              <button
                onClick={() => setInspectedAsset(null)}
                className="px-4 py-1.5 bg-gray-800 hover:bg-gray-700 text-white rounded-lg text-xs font-semibold transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
