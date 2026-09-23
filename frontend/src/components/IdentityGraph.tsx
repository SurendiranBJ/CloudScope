import { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import type { FC } from 'react';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { 
  ZoomIn, ZoomOut, Maximize2, List, Download, 
  ShieldAlert, ChevronDown
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getGraphElements, getEffectiveAccess } from '../api/graph';
import type { CytoscapeElement, EffectiveAccessRecord } from '../api/graph';
import { formatRegion } from '../utils/regionNames';
import type { NodeData, EdgeData } from './NodeDetailsPanel';

// Register dagre layout extension
cytoscape.use(dagre);

export type AnalystMode = 'identity_overview' | 'resource_detail' | 'attack_path';
export type FocusDepth = '1-hop' | '2-hop' | 'all';

export interface IdentityGraphProps {
  onNodeSelect?: (nodeData: NodeData | null) => void;
  onEdgeSelect?: (edgeData: EdgeData | null) => void;
  highlightedNodeIds?: string[];
  searchQuery?: string;
  showLabels?: boolean;
  showEdgeLabels?: boolean;
  highlightRisky?: boolean;
  securityFilter?: 'all' | 'critical' | 'high' | 'medium' | 'low' | 'attack_paths_only';
  showPolicies?: boolean;
  analystMode?: AnalystMode;
  selectedResourceId?: string | null;
  focusDepth?: FocusDepth;
  customElements?: any[];
  graphMode?: 'current' | 'desired' | 'diff';
  activeAttackPath?: string[];
}

export const formatShortLabel = (label?: string, id?: string): string => {
  const raw = label || id || '';
  if (!raw) return '';
  let clean = raw;
  if (clean.startsWith('arn:aws:')) {
    const parts = clean.split(/[/:]/);
    clean = parts[parts.length - 1] || clean;
  }
  if (clean.startsWith('aws:')) {
    const parts = clean.split(':');
    clean = parts[parts.length - 1] || clean;
  }
  if (clean.length > 22) {
    return clean.substring(0, 20) + '...';
  }
  return clean;
};

// Canonical category determination
export const getActionCategory = (actions: string[]): string => {
  if (!actions || actions.length === 0) return 'ACCESS';
  const acts = actions.map(a => a.toLowerCase().trim());
  if (acts.some(a => a === '*' || a === '*:*' || a.includes('administratoraccess'))) {
    return 'FULL ADMIN';
  }
  if (acts.some(a => a.startsWith('sts:assumerole') || a.includes(':assumerole'))) {
    return 'ASSUME_ROLE';
  }
  if (acts.some(a => a.startsWith('rds-db:connect'))) {
    return 'DB_CONNECT';
  }
  if (acts.some(a => a.startsWith('iam:') || a.includes('admin'))) {
    return 'ADMIN';
  }

  const hasWrite = acts.some(a => {
    const v = a.split(':').pop() || a;
    return /^(put|create|update|modify|post|batchwrite|attach|set|write)/.test(v);
  });
  const hasDelete = acts.some(a => {
    const v = a.split(':').pop() || a;
    return /^(delete|remove|drop|purge|terminate|detach)/.test(v);
  });
  const hasRead = acts.some(a => {
    const v = a.split(':').pop() || a;
    return /^(get|list|describe|view|batchget|read|lookup|head|download)/.test(v);
  });
  const hasExec = acts.some(a => {
    const v = a.split(':').pop() || a;
    return /^(invoke|run|start|execute|trigger)/.test(v);
  });

  if (hasWrite && hasRead) return 'READ / WRITE';
  if (hasWrite) return 'WRITE';
  if (hasDelete) return 'DELETE';
  if (hasExec) return 'EXECUTE';
  if (hasRead) return 'READ';
  return 'ACCESS';
};

const COLUMN_DEFINITIONS = [
  { col: 1, title: '1. USERS & GROUPS', color: '#3B82F6', desc: 'IAM Principals' },
  { col: 2, title: '2. ROLES & TRUST', color: '#8B5CF6', desc: 'Privileged Roles' },
  { col: 3, title: '3. CLOUD RESOURCES', color: '#10B981', desc: 'S3, EC2, Lambda, RDS, Secrets' }
];

export const IdentityGraph: FC<IdentityGraphProps> = ({
  onNodeSelect,
  onEdgeSelect,
  highlightedNodeIds = [],
  searchQuery = '',
  showLabels = true,
  showEdgeLabels = true,
  highlightRisky = false,
  securityFilter = 'all',
  showPolicies = false,
  analystMode = 'identity_overview',
  selectedResourceId = null,
  focusDepth = 'all',
  customElements,
  graphMode = 'current',
  activeAttackPath = []
}) => {
  void graphMode;
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  const [isLegendOpen, setIsLegendOpen] = useState(false);
  const [activeSelectedNodeId, setActiveSelectedNodeId] = useState<string | null>(null);
  const [activeSelectedEdgeId, setActiveSelectedEdgeId] = useState<string | null>(null);
  void activeSelectedEdgeId;

  // Fetch raw elements
  const { data: rawElementsData } = useQuery<CytoscapeElement[]>({
    queryKey: ['graphElements'],
    queryFn: getGraphElements,
    refetchInterval: 12000,
    enabled: !customElements
  });

  // Fetch precomputed effective access
  const { data: effectiveAccessData } = useQuery<EffectiveAccessRecord[]>({
    queryKey: ['effectiveAccess'],
    queryFn: getEffectiveAccess,
    refetchInterval: 15000,
    staleTime: 10000
  });

  const rawElements = useMemo(() => {
    return customElements || rawElementsData || [];
  }, [customElements, rawElementsData]);

  // Filter state for category pills
  const [activeFilters, setActiveFilters] = useState<Record<string, boolean>>({
    User: true,
    Group: true,
    Role: true,
    Policy: true,
    S3: true,
    EC2: true,
    Lambda: true,
    RDS: true,
    DynamoDB: true,
    Secrets: true,
    KMS: true,
    APIGateway: true
  });

  const [tooltip, setTooltip] = useState<{ x: number; y: number; text: string; visible: boolean }>({
    x: 0,
    y: 0,
    text: '',
    visible: false
  });

  const filterColors: Record<string, string> = {
    User: '#3B82F6',
    Group: '#6366F1',
    Role: '#8B5CF6',
    Policy: '#14B8A6',
    S3: '#F59E0B',
    EC2: '#10B981',
    Lambda: '#EC4899',
    RDS: '#0EA5E9',
    DynamoDB: '#A855F7',
    Secrets: '#EF4444',
    Secret: '#EF4444',
    KMS: '#EAB308',
    APIGateway: '#06B6D4'
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // 1. TOPOLOGY & EFFECTIVE-ACCESS AGGREGATION ENGINE
  // ─────────────────────────────────────────────────────────────────────────────
  const transformedGraph = useMemo(() => {
    const rawNodes = rawElements.filter(e => !e.data.source);
    const rawEdges = rawElements.filter(e => !!e.data.source);

    // Map nodes by ID
    const nodeMap = new Map<string, any>();
    rawNodes.forEach(n => {
      nodeMap.set(n.data.id, { ...n.data });
    });

    // Structural Maps
    const groupToUsers: Record<string, string[]> = {};
    const userToGroups: Record<string, string[]> = {};
    const identityToPolicies: Record<string, string[]> = {};
    const policyToAllows: Record<string, any[]> = {};

    rawEdges.forEach(e => {
      const src = e.data.source!;
      const tgt = e.data.target!;
      const lbl = e.data.label || e.data.edge_type || '';

      if (lbl === 'MEMBER_OF') {
        groupToUsers[tgt] = groupToUsers[tgt] || [];
        if (!groupToUsers[tgt].includes(src)) groupToUsers[tgt].push(src);

        userToGroups[src] = userToGroups[src] || [];
        if (!userToGroups[src].includes(tgt)) userToGroups[src].push(tgt);
      } else if (lbl === 'HAS_POLICY') {
        identityToPolicies[src] = identityToPolicies[src] || [];
        if (!identityToPolicies[src].includes(tgt)) identityToPolicies[src].push(tgt);
      } else if (lbl === 'ALLOWS' || lbl === 'DB_CONNECT' || lbl === 'CAN_ACCESS') {
        policyToAllows[src] = policyToAllows[src] || [];
        policyToAllows[src].push(e.data);
      }
    });

    // Result arrays
    const finalNodes: any[] = [];
    const finalEdges: any[] = [];
    const edgeAggregator = new Map<string, {
      id: string;
      source: string;
      target: string;
      sourceType: string;
      targetType: string;
      sourceArn?: string;
      targetArn?: string;
      label: string;
      edge_type: string;
      access_category: string;
      actions: Set<string>;
      policy_names: Set<string>;
      statement_sids: Set<string>;
      decision: string;
      why: string;
      isActivity: boolean;
      region?: string;
    }>();

    // Determine nodes to include
    rawNodes.forEach(n => {
      const type = n.data.type || 'Resource';
      // In default overview, hide Policy nodes unless showPolicies is toggled
      if (type === 'Policy' && !showPolicies) {
        return;
      }
      finalNodes.push({
        data: {
          ...n.data,
          shortLabel: formatShortLabel(n.data.label, n.data.id)
        },
        classes: n.classes || ''
      });
    });

    // 1. Process Structural / Identity Edges
    rawEdges.forEach(e => {
      const src = e.data.source!;
      const tgt = e.data.target!;
      const lbl = e.data.label || e.data.edge_type || '';

      if (lbl === 'MEMBER_OF' || lbl === 'CAN_ASSUME' || lbl === 'ATTACHED_TO' || lbl === 'EXECUTES_WITH') {
        finalEdges.push({
          data: {
            ...e.data,
            id: `str-${src}-${tgt}-${lbl}`,
            label: lbl,
            edge_type: lbl,
            access_category: lbl
          },
          classes: e.classes || ''
        });
      } else if (showPolicies && (lbl === 'HAS_POLICY' || lbl === 'ALLOWS' || lbl === 'DB_CONNECT')) {
        // In advanced showPolicies mode, include raw policy edges
        finalEdges.push({
          data: {
            ...e.data,
            id: e.data.id || `raw-${src}-${tgt}-${lbl}`,
            label: e.data.action ? formatShortLabel(e.data.action) : lbl,
            edge_type: lbl,
            access_category: e.data.access_category || (e.data.action ? getActionCategory([e.data.action]) : lbl)
          },
          classes: e.classes || ''
        });
      }
    });

    // 2. Synthesize Aggregated Effective-Access Edges (When showPolicies is false or as overlay)
    if (!showPolicies) {
      // First: derive from backend policy chains (Identity -> HAS_POLICY -> Policy -> ALLOWS -> Resource)
      Object.entries(identityToPolicies).forEach(([identityId, policies]) => {
        policies.forEach(policyId => {
          const allowsList = policyToAllows[policyId] || [];
          allowsList.forEach(allowEdge => {
            const resourceId = allowEdge.target;
            if (!nodeMap.has(identityId) || !nodeMap.has(resourceId)) return;

            const aggKey = `${identityId}|${resourceId}`;
            let entry = edgeAggregator.get(aggKey);
            if (!entry) {
              const srcNode = nodeMap.get(identityId);
              const tgtNode = nodeMap.get(resourceId);
              entry = {
                id: `agg-${identityId}-${resourceId}`,
                source: identityId,
                target: resourceId,
                sourceType: srcNode?.type || 'Identity',
                targetType: tgtNode?.type || 'Resource',
                sourceArn: srcNode?.arn,
                targetArn: tgtNode?.arn,
                label: 'ACCESS',
                edge_type: 'EFFECTIVE_ACCESS',
                access_category: 'ACCESS',
                actions: new Set<string>(),
                policy_names: new Set<string>(),
                statement_sids: new Set<string>(),
                decision: 'ALLOWED',
                why: '',
                isActivity: false,
                region: tgtNode?.region || allowEdge.region
              };
              edgeAggregator.set(aggKey, entry);
            }

            if (allowEdge.action) entry.actions.add(allowEdge.action);
            if (allowEdge.policy_name) entry.policy_names.add(allowEdge.policy_name);
            if (allowEdge.statement_sid) entry.statement_sids.add(allowEdge.statement_sid);
            if (allowEdge.isActivity) entry.isActivity = true;
          });
        });
      });

      // Second: supplement with precomputed effective access records from backend
      if (effectiveAccessData && effectiveAccessData.length > 0) {
        effectiveAccessData.forEach(rec => {
          const identId = rec.identity_id;
          const resId = `aws:${rec.target_resource_type.toLowerCase()}:${rec.target_resource_name}`;
          const altResId = `aws:${rec.target_resource_type.toLowerCase()}:${rec.target_resource_id}`;
          
          const targetId = nodeMap.has(resId) ? resId : nodeMap.has(altResId) ? altResId : null;
          if (!targetId || !nodeMap.has(identId)) return;

          const aggKey = `${identId}|${targetId}`;
          let entry = edgeAggregator.get(aggKey);
          if (!entry) {
            const srcNode = nodeMap.get(identId);
            const tgtNode = nodeMap.get(targetId);
            entry = {
              id: `agg-${identId}-${targetId}`,
              source: identId,
              target: targetId,
              sourceType: srcNode?.type || rec.identity_type,
              targetType: tgtNode?.type || rec.target_resource_type,
              sourceArn: srcNode?.arn,
              targetArn: tgtNode?.arn,
              label: 'ACCESS',
              edge_type: 'EFFECTIVE_ACCESS',
              access_category: 'ACCESS',
              actions: new Set<string>(),
              policy_names: new Set<string>(),
              statement_sids: new Set<string>(),
              decision: rec.evidence?.decision || 'ALLOWED',
              why: rec.evidence?.reason || '',
              isActivity: false,
              region: tgtNode?.region || rec.evidence?.region
            };
            edgeAggregator.set(aggKey, entry);
          }

          if (rec.evidence?.matched_action) entry.actions.add(rec.evidence.matched_action);
          if (rec.policy_names) rec.policy_names.forEach(p => entry?.policy_names.add(p));
          if (rec.evidence?.statement_sid) entry.statement_sids.add(rec.evidence.statement_sid);
        });
      }

      // Convert aggregated map to final edges
      edgeAggregator.forEach(agg => {
        const actionList = Array.from(agg.actions);
        const policyList = Array.from(agg.policy_names);
        const sidList = Array.from(agg.statement_sids);
        const category = getActionCategory(actionList);

        finalEdges.push({
          data: {
            id: agg.id,
            source: agg.source,
            target: agg.target,
            sourceType: agg.sourceType,
            targetType: agg.targetType,
            sourceArn: agg.sourceArn,
            targetArn: agg.targetArn,
            label: category,
            edge_type: 'EFFECTIVE_ACCESS',
            access_category: category,
            actions: actionList,
            action: actionList[0] || '*',
            policy_names: policyList,
            policy_name: policyList[0] || 'IAM Policy',
            statement_sids: sidList,
            statement_sid: sidList[0] || 'Statement',
            decision: agg.decision,
            region: agg.region,
            why: `Effective ${category} permissions granting ${actionList.length} action(s) via ${policyList.length} policy source(s).`,
            isActivity: agg.isActivity
          },
          classes: agg.isActivity ? 'edge-activity' : ''
        });
      });
    }

    return {
      nodes: finalNodes,
      edges: finalEdges,
      nodeMap,
      groupToUsers,
      userToGroups
    };
  }, [rawElements, showPolicies, effectiveAccessData]);

  // Compute node counts for filter pills
  const counts = useMemo(() => {
    const tally: Record<string, number> = {
      User: 0,
      Group: 0,
      Role: 0,
      Policy: 0,
      S3: 0,
      EC2: 0,
      Lambda: 0,
      RDS: 0,
      DynamoDB: 0,
      Secrets: 0,
      KMS: 0,
      APIGateway: 0
    };

    transformedGraph.nodes.forEach((n: any) => {
      const type = n.data.type || 'Resource';
      if (tally[type] !== undefined) {
        tally[type]++;
      } else if (type === 'Secret') {
        tally.Secrets++;
      }
    });

    return tally;
  }, [transformedGraph.nodes]);

  // ─────────────────────────────────────────────────────────────────────────────
  // 2. DETERMINISTIC HIERARCHICAL 3-COLUMN LAYOUT
  // ─────────────────────────────────────────────────────────────────────────────
  const computeDeterministicLayout = useCallback((cy: cytoscape.Core) => {
    const visibleNodes = cy.nodes().filter(n => n.style('display') !== 'none');
    const positions: Record<string, { x: number; y: number }> = {};

    // Group nodes by column category
    const col1Nodes: cytoscape.NodeSingular[] = []; // Users & Groups
    const col2Nodes: cytoscape.NodeSingular[] = []; // Roles
    const col25Nodes: cytoscape.NodeSingular[] = []; // Policies (if enabled)
    const col3Nodes: cytoscape.NodeSingular[] = []; // Resources

    visibleNodes.forEach(node => {
      const type = (node.data('type') || '').toLowerCase();
      if (type === 'user' || type === 'group') {
        col1Nodes.push(node);
      } else if (type === 'role') {
        col2Nodes.push(node);
      } else if (type === 'policy') {
        col25Nodes.push(node);
      } else {
        col3Nodes.push(node);
      }
    });

    // Deterministic sorting function (type then label/id)
    const nodeSorter = (a: cytoscape.NodeSingular, b: cytoscape.NodeSingular) => {
      const typeA = (a.data('type') || '').toLowerCase();
      const typeB = (b.data('type') || '').toLowerCase();
      if (typeA !== typeB) return typeA.localeCompare(typeB);
      const nameA = (a.data('label') || a.id()).toLowerCase();
      const nameB = (b.data('label') || b.id()).toLowerCase();
      return nameA.localeCompare(nameB);
    };

    col1Nodes.sort(nodeSorter);
    col2Nodes.sort(nodeSorter);
    col25Nodes.sort(nodeSorter);
    col3Nodes.sort(nodeSorter);

    // Coordinate Anchors
    const X_COL1 = 120;
    const X_COL2 = 500;
    const X_COL25 = 750;
    const X_COL3 = showPolicies ? 1020 : 880;

    const Y_START = 80;
    const Y_GAP = 75;

    // Position Column 1: Users & Groups
    // Clustered: Groups first with member users placed adjacent
    const placedCol1 = new Set<string>();
    let col1Y = Y_START;

    col1Nodes.forEach(n => {
      if (placedCol1.has(n.id())) return;
      positions[n.id()] = { x: X_COL1, y: col1Y };
      placedCol1.add(n.id());
      col1Y += Y_GAP;
    });

    // Position Column 2: Roles
    let col2Y = Y_START + 20;
    col2Nodes.forEach(n => {
      positions[n.id()] = { x: X_COL2, y: col2Y };
      col2Y += Y_GAP + 10;
    });

    // Position Column 2.5: Policies (if enabled)
    if (showPolicies && col25Nodes.length > 0) {
      let col25Y = Y_START + 10;
      col25Nodes.forEach(n => {
        positions[n.id()] = { x: X_COL25, y: col25Y };
        col25Y += Y_GAP;
      });
    }

    // Position Column 3: Resources
    let col3Y = Y_START;
    col3Nodes.forEach(n => {
      positions[n.id()] = { x: X_COL3, y: col3Y };
      col3Y += Y_GAP;
    });

    return {
      name: 'preset',
      positions,
      fit: true,
      padding: 60,
      animate: true,
      animationDuration: 300
    };
  }, [showPolicies]);

  // ─────────────────────────────────────────────────────────────────────────────
  // 3. VISIBILITY, FOCUS & PATHWAY APPLICATION
  // ─────────────────────────────────────────────────────────────────────────────
  const applyGraphFilters = useCallback(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      const q = searchQuery.trim().toLowerCase();
      const pathIds = activeAttackPath.length > 0 ? activeAttackPath : highlightedNodeIds;

      // Determine focus neighborhood if node selected
      let allowedFocusNodeIds: Set<string> | null = null;

      if (analystMode === 'resource_detail' && selectedResourceId) {
        // Mode B: Resource Detail mode -> only show selected resource and accessing principals
        allowedFocusNodeIds = new Set<string>([selectedResourceId]);
        const resNode = cy.getElementById(selectedResourceId);
        if (resNode.length > 0) {
          resNode.incomers().nodes().forEach(n => {
            allowedFocusNodeIds?.add(n.id());
          });
          // 2nd hop: Users that assume these roles
          resNode.incomers().nodes().incomers().nodes().forEach(n => {
            allowedFocusNodeIds?.add(n.id());
          });
        }
      } else if (analystMode === 'attack_path') {
        // Mode C: Attack path isolation
        allowedFocusNodeIds = new Set<string>(pathIds);
      } else if (activeSelectedNodeId && focusDepth !== 'all') {
        // Focus depth mode (1-hop or 2-hop)
        const target = cy.getElementById(activeSelectedNodeId);
        if (target.length > 0) {
          allowedFocusNodeIds = new Set<string>([activeSelectedNodeId]);
          const hop1 = target.neighborhood().nodes();
          hop1.forEach(n => {
            allowedFocusNodeIds?.add(n.id());
          });

          if (focusDepth === '2-hop') {
            hop1.neighborhood().nodes().forEach(n => {
              allowedFocusNodeIds?.add(n.id());
            });
          }
        }
      }

      cy.nodes().forEach(node => {
        const type = node.data('type') || 'Resource';
        const label = (node.data('label') || '').toLowerCase();
        const arn = (node.data('arn') || '').toLowerCase();
        const id = node.id().toLowerCase();
        const riskScore = node.data('riskScore') || 0;

        // Category filter
        const categoryKey = type === 'Secret' ? 'Secrets' : type;
        const passesCategory = activeFilters[categoryKey] !== false;

        // Search match
        const passesSearch = q === '' || label.includes(q) || arn.includes(q) || id.includes(q);

        // Security Severity
        let passesSeverity = true;
        if (securityFilter === 'critical') passesSeverity = riskScore >= 80;
        else if (securityFilter === 'high') passesSeverity = riskScore >= 60;
        else if (securityFilter === 'medium') passesSeverity = riskScore >= 40 && riskScore < 60;
        else if (securityFilter === 'low') passesSeverity = riskScore < 40;
        else if (securityFilter === 'attack_paths_only') {
          passesSeverity = pathIds.includes(node.id());
        }

        // Focus / Neighborhood filter
        const passesFocus = allowedFocusNodeIds === null || allowedFocusNodeIds.has(node.id());

        if (passesCategory && passesSearch && passesSeverity && passesFocus) {
          node.style('display', 'element');
          if (q !== '' && passesSearch) {
            node.addClass('search-match');
          } else {
            node.removeClass('search-match');
          }
        } else {
          node.style('display', 'none');
          node.removeClass('search-match');
        }
      });

      // Highlight attack path or selected neighborhood
      if (analystMode === 'attack_path' && pathIds.length > 0) {
        cy.elements().addClass('dimmed').removeClass('highlighted');
        pathIds.forEach(id => {
          cy.getElementById(id).removeClass('dimmed').addClass('highlighted');
        });

        for (let i = 0; i < pathIds.length - 1; i++) {
          const s = pathIds[i];
          const t = pathIds[i + 1];
          cy.edges().forEach(e => {
            if ((e.source().id() === s && e.target().id() === t) || (e.source().id() === t && e.target().id() === s)) {
              e.removeClass('dimmed').addClass('highlighted');
            }
          });
        }
      } else if (activeSelectedNodeId) {
        const target = cy.getElementById(activeSelectedNodeId);
        if (target.length > 0) {
          cy.elements().addClass('dimmed').removeClass('highlighted');
          target.removeClass('dimmed').addClass('highlighted');
          target.neighborhood().removeClass('dimmed');
          target.connectedEdges().removeClass('dimmed').addClass('highlighted');
        }
      } else {
        cy.elements().removeClass('dimmed').removeClass('highlighted');
      }

      if (highlightRisky) {
        cy.edges().forEach(e => {
          const cat = e.data('access_category') || '';
          if (cat === 'FULL ADMIN' || cat === 'ADMIN' || e.data('isRisky')) {
            e.addClass('highlighted');
          }
        });
      }
    });
  }, [searchQuery, activeAttackPath, highlightedNodeIds, analystMode, selectedResourceId, activeSelectedNodeId, focusDepth, activeFilters, securityFilter]);

  // ─────────────────────────────────────────────────────────────────────────────
  // 4. CYTOSCAPE INITIALIZATION & EVENT HANDLERS
  // ─────────────────────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!containerRef.current) return;

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const allElements = [
      ...transformedGraph.nodes,
      ...transformedGraph.edges
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements: JSON.parse(JSON.stringify(allElements)),
      minZoom: 0.15,
      maxZoom: 2.8,
      wheelSensitivity: 0.22,
      style: [
        // Base Node Style with Human-Readable Short Label
        {
          selector: 'node',
          style: {
            'content': ((ele: cytoscape.NodeSingular) => {
              if (!showLabels) return '';
              return ele.data('shortLabel') || formatShortLabel(ele.data('label'), ele.id());
            }) as any,
            'font-family': 'Inter, system-ui, sans-serif',
            'font-size': '11px',
            'font-weight': 'bold',
            'color': '#F8FAFC',
            'text-valign': 'bottom',
            'text-margin-y': 7,
            'background-color': '#1E293B',
            'border-width': '2px',
            'border-color': '#475569',
            'width': '44px',
            'height': '44px',
            'text-background-color': '#0F172A',
            'text-background-opacity': 0.88,
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            'text-border-width': 1,
            'text-border-color': '#334155',
            'transition-property': 'background-color, border-color, border-width, opacity, width, height',
            'transition-duration': 0.2
          }
        },
        // Types
        {
          selector: 'node[type="User"]',
          style: {
            'background-color': filterColors.User,
            'border-color': '#60A5FA',
            'shape': 'ellipse',
            'width': '42px',
            'height': '42px'
          }
        },
        {
          selector: 'node[type="Group"]',
          style: {
            'background-color': filterColors.Group,
            'border-color': '#818CF8',
            'shape': 'round-rectangle',
            'width': '52px',
            'height': '44px'
          }
        },
        {
          selector: 'node[type="Role"]',
          style: {
            'background-color': filterColors.Role,
            'border-color': '#C084FC',
            'shape': 'hexagon',
            'width': '46px',
            'height': '46px'
          }
        },
        {
          selector: 'node[type="Policy"]',
          style: {
            'background-color': filterColors.Policy,
            'border-color': '#2DD4BF',
            'shape': 'diamond',
            'width': '40px',
            'height': '40px'
          }
        },
        {
          selector: 'node[type="S3"]',
          style: {
            'background-color': filterColors.S3,
            'border-color': '#FBBF24',
            'shape': 'barrel',
            'width': '46px',
            'height': '44px'
          }
        },
        {
          selector: 'node[type="EC2"]',
          style: {
            'background-color': filterColors.EC2,
            'border-color': '#34D399',
            'shape': 'round-rectangle',
            'width': '46px',
            'height': '44px'
          }
        },
        {
          selector: 'node[type="Lambda"]',
          style: {
            'background-color': filterColors.Lambda,
            'border-color': '#F472B6',
            'shape': 'ellipse',
            'width': '44px',
            'height': '44px'
          }
        },
        {
          selector: 'node[type="RDS"]',
          style: {
            'background-color': filterColors.RDS,
            'border-color': '#38BDF8',
            'shape': 'database' as any,
            'width': '44px',
            'height': '48px'
          }
        },
        {
          selector: 'node[type="DynamoDB"]',
          style: {
            'background-color': filterColors.DynamoDB,
            'border-color': '#C084FC',
            'shape': 'database' as any,
            'width': '44px',
            'height': '48px'
          }
        },
        {
          selector: 'node[type="Secrets"], node[type="Secret"]',
          style: {
            'background-color': filterColors.Secrets,
            'border-color': '#F87171',
            'shape': 'ellipse',
            'width': '44px',
            'height': '44px'
          }
        },
        // Base Aggregated Edge Styling (Clean Left-to-Right arrows)
        {
          selector: 'edge',
          style: {
            'label': ((e: cytoscape.EdgeSingular) => {
              if (!showEdgeLabels && !e.hasClass('highlighted') && !e.hasClass('selected')) return '';
              return e.data('access_category') || e.data('label') || '';
            }) as any,
            'font-family': 'Inter, monospace',
            'font-size': '9px',
            'font-weight': 'bold',
            'color': '#CBD5E1',
            'text-background-color': '#0F172A',
            'text-background-opacity': 0.88,
            'text-background-padding': '2px',
            'text-background-shape': 'roundrectangle',
            'text-rotation': 'autorotate',
            'text-margin-y': -7,
            'width': 2,
            'line-color': '#475569',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'opacity': 0.6,
            'transition-property': 'line-color, target-arrow-color, width, opacity',
            'transition-duration': 0.2
          }
        },
        // Effective Access Aggregated Edges
        {
          selector: 'edge[edge_type = "EFFECTIVE_ACCESS"]',
          style: {
            'line-color': '#0EA5E9',
            'target-arrow-color': '#0EA5E9',
            'width': 2.2,
            'opacity': 0.75
          }
        },
        {
          selector: 'edge[access_category = "FULL ADMIN"], edge[access_category = "ADMIN"]',
          style: {
            'line-color': '#EF4444',
            'target-arrow-color': '#EF4444',
            'width': 3,
            'opacity': 0.85
          }
        },
        {
          selector: 'edge[access_category = "READ / WRITE"]',
          style: {
            'line-color': '#10B981',
            'target-arrow-color': '#10B981',
            'width': 2.5,
            'opacity': 0.8
          }
        },
        {
          selector: 'edge[access_category = "WRITE"], edge[access_category = "DELETE"]',
          style: {
            'line-color': '#F59E0B',
            'target-arrow-color': '#F59E0B',
            'width': 2.2,
            'opacity': 0.8
          }
        },
        {
          selector: 'edge[access_category = "READ"]',
          style: {
            'line-color': '#38BDF8',
            'target-arrow-color': '#38BDF8',
            'width': 2,
            'opacity': 0.75
          }
        },
        // Hierarchy / Structural Edges
        {
          selector: 'edge[label = "MEMBER_OF"]',
          style: {
            'line-color': '#818CF8',
            'target-arrow-color': '#818CF8',
            'width': 2,
            'opacity': 0.85
          }
        },
        {
          selector: 'edge[label = "CAN_ASSUME"]',
          style: {
            'line-color': '#A78BFA',
            'target-arrow-color': '#A78BFA',
            'line-style': 'dashed',
            'width': 2,
            'opacity': 0.85
          }
        },
        {
          selector: 'edge[label = "ATTACHED_TO"], edge[label = "EXECUTES_WITH"]',
          style: {
            'line-color': '#2DD4BF',
            'target-arrow-color': '#2DD4BF',
            'line-style': 'dashed',
            'width': 2,
            'opacity': 0.85
          }
        },
        // Selected / Highlighted states
        {
          selector: 'node.highlighted, node.selected',
          style: {
            'border-width': '4px',
            'border-color': '#F59E0B',
            'opacity': 1,
            'z-index': 999
          }
        },
        {
          selector: 'edge.highlighted, edge.selected',
          style: {
            'line-color': '#EF4444',
            'target-arrow-color': '#EF4444',
            'width': 3,
            'opacity': 1,
            'z-index': 998
          }
        },
        {
          selector: 'node.dimmed',
          style: {
            'opacity': 0.08
          }
        },
        {
          selector: 'edge.dimmed',
          style: {
            'opacity': 0.04
          }
        }
      ]
    });

    cyRef.current = cy;

    // Run deterministic layout
    const layoutConfig = computeDeterministicLayout(cy);
    cy.layout(layoutConfig as any).run();

    // Node click handler
    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      const nId = node.id();
      setActiveSelectedNodeId(nId);
      setActiveSelectedEdgeId(null);
      cy.edges().removeClass('selected');
      cy.nodes().removeClass('selected');
      node.addClass('selected');

      if (onEdgeSelect) onEdgeSelect(null);
      if (onNodeSelect) {
        onNodeSelect({
          id: nId,
          label: node.data('label') || nId,
          type: node.data('type') || 'Resource',
          riskScore: node.data('riskScore') || 0,
          arn: node.data('arn'),
          region: node.data('region'),
          description: node.data('description'),
          trustPolicy: node.data('trustPolicy'),
          policies: node.data('policies'),
          effectiveAccess: []
        });
      }
    });

    // Edge click handler: Provides complete aggregated evidence to side panel
    cy.on('tap', 'edge', (evt) => {
      const edge = evt.target;
      const d = edge.data();
      setActiveSelectedEdgeId(edge.id());
      cy.edges().removeClass('selected');
      edge.addClass('selected');

      if (onNodeSelect) onNodeSelect(null);
      if (onEdgeSelect) {
        onEdgeSelect({
          source: edge.source().data('label') || edge.source().id(),
          target: edge.target().data('label') || edge.target().id(),
          sourceType: edge.source().data('type') || 'Identity',
          targetType: edge.target().data('type') || 'Resource',
          sourceArn: edge.source().data('arn'),
          targetArn: edge.target().data('arn'),
          label: d.label || d.access_category || 'Relationship',
          edge_type: d.edge_type || 'EFFECTIVE_ACCESS',
          access_category: d.access_category || d.label,
          actions: d.actions || (d.action ? [d.action] : []),
          action: d.action,
          policy_names: d.policy_names || (d.policy_name ? [d.policy_name] : []),
          policy_name: d.policy_name,
          statement_sids: d.statement_sids || (d.statement_sid ? [d.statement_sid] : []),
          statement_sid: d.statement_sid,
          decision: d.decision || 'ALLOWED',
          region: d.region || edge.target().data('region'),
          why: d.why,
          isActivity: d.isActivity
        });
      }
    });

    // Hover tooltip
    cy.on('mouseover', 'node', (evt) => {
      const node = evt.target;
      const label = node.data('label') || node.id();
      const type = node.data('type') || 'Resource';
      const arn = node.data('arn');
      const region = node.data('region');
      const pos = node.renderedPosition();

      const lines = [
        `${label} (${type})`,
        ...(arn ? [arn] : []),
        ...(region ? [`📍 ${formatRegion(region)}`] : [])
      ];

      setTooltip({
        x: pos.x,
        y: pos.y - 25,
        text: lines.join('\n'),
        visible: true
      });
    });

    cy.on('mouseout', 'node', () => {
      setTooltip(prev => ({ ...prev, visible: false }));
    });

    cy.on('drag pan zoom', () => {
      setTooltip(prev => ({ ...prev, visible: false }));
    });

    // Background click resets selection
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setActiveSelectedNodeId(null);
        setActiveSelectedEdgeId(null);
        cy.elements().removeClass('selected');
        if (onNodeSelect) onNodeSelect(null);
        if (onEdgeSelect) onEdgeSelect(null);
      }
    });

    applyGraphFilters();
    cy.fit(undefined, 60);

    const handleReset = () => {
      setActiveSelectedNodeId(null);
      setActiveSelectedEdgeId(null);
      cy.elements().removeClass('dimmed').removeClass('highlighted').removeClass('selected');
      if (onNodeSelect) onNodeSelect(null);
      if (onEdgeSelect) onEdgeSelect(null);
      cy.layout(computeDeterministicLayout(cy) as any).run();
      cy.fit(undefined, 60);
    };

    window.addEventListener('graph:reset', handleReset);
    const handleResize = () => cy.resize();
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('graph:reset', handleReset);
      window.removeEventListener('resize', handleResize);
      cy.destroy();
      cyRef.current = null;
    };
  }, [transformedGraph, showLabels, showEdgeLabels, computeDeterministicLayout, onNodeSelect, onEdgeSelect, applyGraphFilters]);


  // Re-apply filters when filters or mode changes
  useEffect(() => {
    applyGraphFilters();
  }, [applyGraphFilters]);

  // Zoom & Fit Controls
  const handleZoomIn = () => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom({ level: Math.min(2.8, cy.zoom() * 1.25), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };

  const handleZoomOut = () => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom({ level: Math.max(0.15, cy.zoom() / 1.25), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };

  const handleFit = () => {
    cyRef.current?.fit(undefined, 60);
  };

  const handleExportPng = () => {
    if (!cyRef.current) return;
    const png = cyRef.current.png({ bg: '#0B1120', full: true });
    const a = document.createElement('a');
    a.href = png;
    a.download = `cloudscope-identity-graph-${analystMode}.png`;
    a.click();
  };

  return (
    <div className="w-full h-full relative bg-[#0B1120] overflow-hidden select-none">
      
      {/* 3-Column Layout Guide Guidelines */}
      <div className="absolute inset-0 pointer-events-none z-0 flex justify-between px-20 py-8 opacity-15">
        {COLUMN_DEFINITIONS.map(col => (
          <div key={col.col} className="flex flex-col items-center h-full">
            <span className="text-[11px] font-mono font-bold tracking-widest text-gray-400 uppercase">
              {col.title}
            </span>
            <div className="w-[1px] h-full bg-gradient-to-b from-gray-700 via-gray-800 to-transparent mt-2" />
          </div>
        ))}
      </div>

      {/* Floating Filter Pills Bar */}
      <div className="absolute top-4 left-4 right-4 z-10 flex flex-wrap items-center gap-1.5">
        {Object.keys(activeFilters).map(filterKey => {
          if (filterKey === 'Policy' && !showPolicies) return null;
          const color = filterColors[filterKey] || '#64748B';
          const active = activeFilters[filterKey];
          const count = counts[filterKey] || 0;
          return (
            <button
              key={filterKey}
              onClick={() => setActiveFilters(prev => ({ ...prev, [filterKey]: !prev[filterKey] }))}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium transition-all border ${
                active
                  ? 'bg-gray-900/90 text-white border-gray-700 shadow-sm'
                  : 'bg-gray-950/40 text-gray-500 border-gray-900 hover:text-gray-300'
              }`}
            >
              <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: color }} />
              <span>{filterKey}</span>
              <span className={`px-1 rounded-full text-[10px] ${active ? 'bg-gray-800 text-gray-300' : 'text-gray-600'}`}>
                {count}
              </span>
            </button>
          );
        })}

        <div className="flex-1" />

        {/* Zoom & Fit Action Buttons */}
        <div className="flex items-center gap-1 bg-gray-900/90 backdrop-blur border border-gray-700 rounded-lg p-1 shadow-lg">
          <button onClick={handleZoomIn} className="p-1 hover:bg-gray-800 rounded text-gray-300" title="Zoom In">
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button onClick={handleZoomOut} className="p-1 hover:bg-gray-800 rounded text-gray-300" title="Zoom Out">
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button onClick={handleFit} className="p-1 hover:bg-gray-800 rounded text-gray-300" title="Fit to Screen">
            <Maximize2 className="w-3.5 h-3.5" />
          </button>
          <div className="w-[1px] h-3.5 bg-gray-700 mx-0.5" />
          <button onClick={handleExportPng} className="p-1 hover:bg-gray-800 rounded text-gray-300" title="Export PNG">
            <Download className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Tooltip */}
      {tooltip.visible && (
        <div
          className="absolute z-50 pointer-events-none bg-gray-900/95 border border-gray-700 text-gray-200 text-xs px-3 py-1.5 rounded-lg shadow-2xl backdrop-blur-md transform -translate-x-1/2 -translate-y-full flex flex-col gap-0.5 max-w-sm"
          style={{ left: `${tooltip.x}px`, top: `${tooltip.y}px` }}
        >
          {tooltip.text.split('\n').map((line, i) => (
            <span key={i} className={i === 0 ? 'font-bold text-white truncate' : 'text-[10px] text-gray-400 truncate'}>
              {line}
            </span>
          ))}
        </div>
      )}

      {/* Security Legend Toggle */}
      <div className="absolute bottom-5 left-5 z-10">
        {!isLegendOpen ? (
          <button 
            onClick={() => setIsLegendOpen(true)}
            className="flex items-center gap-2 bg-gray-900/90 backdrop-blur border border-gray-800 hover:border-gray-700 rounded-lg px-3.5 py-1.5 text-xs font-semibold text-gray-300 shadow-xl transition-colors"
          >
            <List className="w-3.5 h-3.5" />
            <span>Show Legend</span>
          </button>
        ) : (
          <div className="bg-gray-900/95 backdrop-blur border border-gray-800 rounded-xl p-4 w-60 shadow-2xl space-y-3">
            <div className="flex justify-between items-center border-b border-gray-800 pb-2">
              <span className="text-xs font-bold text-gray-200 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-blue-400" />
                <span>Identity Graph Legend</span>
              </span>
              <button onClick={() => setIsLegendOpen(false)} className="text-gray-500 hover:text-gray-300">
                <ChevronDown className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center gap-2 text-xs">
                <div className="w-3 h-3 rounded-full bg-blue-500" />
                <span className="text-gray-300">IAM User</span>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <div className="w-3.5 h-2.5 rounded-sm bg-indigo-500" />
                <span className="text-gray-300">IAM Group</span>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <div className="w-3 h-3 rotate-45 bg-purple-500" />
                <span className="text-gray-300">IAM Role</span>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <div className="w-3 h-3 rounded-sm bg-amber-500" />
                <span className="text-gray-300">Cloud Resources</span>
              </div>
            </div>

            <div className="pt-2 border-t border-gray-800 space-y-1 text-[11px] font-mono">
              <div className="flex items-center gap-2">
                <div className="w-4 h-0.5 bg-emerald-500" />
                <span className="text-emerald-400">Effective Access</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-0.5 bg-purple-500 border-dashed" />
                <span className="text-purple-400">CAN_ASSUME</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-0.5 bg-red-500" />
                <span className="text-red-400">Critical / Admin</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Main Graph Canvas */}
      <div ref={containerRef} className="w-full h-full" />
    </div>
  );
};
