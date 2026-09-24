import { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import type { FC } from 'react';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { 
  ZoomIn, ZoomOut, Maximize2, RotateCcw, Download,
  Layers, Filter, Eye
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getGraphElements, getEffectiveAccess } from '../api/graph';
import type { CytoscapeElement, EffectiveAccessRecord } from '../api/graph';
import { formatRegion } from '../utils/regionNames';
import type { NodeData, EdgeData } from './NodeDetailsPanel';
import { ENTITY_STYLES, CANONICAL_FILTER_COLORS, normalizeGraphType } from '../constants/graphStyles';

// Register dagre layout extension
cytoscape.use(dagre);

export type AnalystMode = 'identity_overview' | 'resource_detail' | 'attack_path';
export type FocusDepth = '1-hop' | '2-hop' | 'all';

export interface IdentityGraphProps {
  onNodeSelect?: (nodeData: NodeData | null) => void;
  onEdgeSelect?: (edgeData: EdgeData | null) => void;
  selectedIdentityId?: string | null;
  selectedResourceId?: string | null;
  highlightedNodeIds?: string[];
  searchQuery?: string;
  showLabels?: boolean;
  showEdgeLabels?: boolean;
  highlightRisky?: boolean;
  securityFilter?: 'all' | 'critical' | 'high' | 'medium' | 'low' | 'attack_paths_only';
  showPolicies?: boolean;
  analystMode?: AnalystMode;
  focusDepth?: FocusDepth;
  customElements?: any[];
  graphMode?: 'current' | 'desired' | 'diff';
  activeAttackPath?: string[];
  onClearFocus?: () => void;
}

const formatShortLabel = (label?: string, id?: string): string => {
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

// Canonical action category classification
const getActionCategory = (actions: string[], targetType?: string): string => {
  if (!actions || actions.length === 0) return 'ACCESS';
  const acts = actions.map(a => a.toLowerCase().trim());
  if (acts.some(a => a === '*' || a === '*:*' || a.includes('administratoraccess'))) {
    if (targetType === 'Lambda') return 'CAN_MANAGE / INVOKE';
    return 'FULL ADMIN';
  }
  if (acts.some(a => a.startsWith('sts:assumerole') || a.includes(':assumerole'))) {
    return 'ASSUME_ROLE';
  }
  if (acts.some(a => a.startsWith('rds-db:connect'))) {
    return 'DB_CONNECT';
  }
  if (targetType === 'Lambda') {
    const hasInvoke = acts.some(a => a.includes('invoke'));
    const hasManage = acts.some(a => {
      const v = a.split(':').pop() || a;
      return /^(put|create|update|modify|delete|publish|add|remove|tag|untag)/.test(v);
    });
    if (hasInvoke && hasManage) return 'CAN_MANAGE / INVOKE';
    if (hasInvoke) return 'CAN_INVOKE';
    if (hasManage) return 'CAN_MANAGE';
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

export const IdentityGraph: FC<IdentityGraphProps> = ({
  onNodeSelect,
  onEdgeSelect,
  selectedIdentityId = null,
  selectedResourceId = null,
  highlightedNodeIds = [],
  searchQuery = '',
  showLabels = true,
  showEdgeLabels = true,
  highlightRisky = false,
  securityFilter = 'all',
  showPolicies = false,
  analystMode = 'identity_overview',
  focusDepth = 'all',
  customElements,
  graphMode = 'current',
  activeAttackPath = [],
  onClearFocus
}) => {
  void graphMode;
  void highlightRisky;
  void securityFilter;
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

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

  // Category filter state
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



  // ─────────────────────────────────────────────────────────────────────────────
  // 1. CANONICAL DEDUPLICATION & EFFECTIVE ACCESS AGGREGATION
  // ─────────────────────────────────────────────────────────────────────────────
  const transformedGraph = useMemo(() => {
    const rawNodes = rawElements.filter(e => !e.data.source);
    const rawEdges = rawElements.filter(e => !!e.data.source);

    // Defensive Deduplication: map every node to unique canonical entity
    const seenEntityKeys = new Set<string>();
    const idToCanonical = new Map<string, string>();
    const nodeMap = new Map<string, any>();
    const finalNodes: any[] = [];

    rawNodes.forEach(n => {
      const nid = n.data.id;
      const arn = n.data.arn || '';
      const ntype = n.data.type || 'Resource';

      // Canonical key prioritizes ARN, then ID
      const entityKey = arn ? `${ntype}:${arn}` : nid;
      if (seenEntityKeys.has(entityKey)) {
        // Record alias remapping to primary ID
        const existingId = idToCanonical.get(entityKey) || nid;
        idToCanonical.set(nid, existingId);
        if (arn) idToCanonical.set(arn, existingId);
        return;
      }

      seenEntityKeys.add(entityKey);
      idToCanonical.set(entityKey, nid);
      idToCanonical.set(nid, nid);
      if (arn) idToCanonical.set(arn, nid);

      // Hide policy diamond nodes unless showPolicies is toggled
      if (ntype === 'Policy' && !showPolicies) {
        return;
      }

      const nodeData = {
        ...n.data,
        id: nid,
        shortLabel: formatShortLabel(n.data.label, nid)
      };

      nodeMap.set(nid, nodeData);
      finalNodes.push({
        data: nodeData,
        classes: n.classes || ''
      });
    });

    // Structural Adjacency Maps
    const identityToPolicies: Record<string, string[]> = {};
    const policyToAllows: Record<string, any[]> = {};

    rawEdges.forEach(e => {
      const rawSrc = e.data.source!;
      const rawTgt = e.data.target!;
      const src = idToCanonical.get(rawSrc) || rawSrc;
      const tgt = idToCanonical.get(rawTgt) || rawTgt;
      const lbl = e.data.label || e.data.edge_type || '';

      if (lbl === 'HAS_POLICY') {
        identityToPolicies[src] = identityToPolicies[src] || [];
        if (!identityToPolicies[src].includes(tgt)) identityToPolicies[src].push(tgt);
      } else if (lbl === 'ALLOWS' || lbl === 'DB_CONNECT' || lbl === 'CAN_ACCESS') {
        policyToAllows[src] = policyToAllows[src] || [];
        policyToAllows[src].push({ ...e.data, target: tgt });
      }
    });

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

    // 1. Process Hierarchy & Structural Edges
    const seenEdgeSigs = new Set<string>();
    rawEdges.forEach(e => {
      const rawSrc = e.data.source!;
      const rawTgt = e.data.target!;
      const src = idToCanonical.get(rawSrc) || rawSrc;
      const tgt = idToCanonical.get(rawTgt) || rawTgt;
      const lbl = e.data.label || e.data.edge_type || '';

      if (!nodeMap.has(src) || !nodeMap.has(tgt) || src === tgt) {
        return;
      }

      if (lbl === 'MEMBER_OF' || lbl === 'CAN_ASSUME' || lbl === 'ATTACHED_TO' || lbl === 'EXECUTES_WITH') {
        const sig = `${src}->${tgt}:${lbl}`;
        if (seenEdgeSigs.has(sig)) return;
        seenEdgeSigs.add(sig);

        finalEdges.push({
          data: {
            ...e.data,
            id: `str-${src}-${tgt}-${lbl}`,
            source: src,
            target: tgt,
            label: lbl,
            edge_type: lbl,
            access_category: lbl
          },
          classes: e.classes || ''
        });
      } else if (showPolicies && (lbl === 'HAS_POLICY' || lbl === 'ALLOWS' || lbl === 'DB_CONNECT')) {
        const sig = `${src}->${tgt}:${lbl}:${e.data.action || ''}`;
        if (seenEdgeSigs.has(sig)) return;
        seenEdgeSigs.add(sig);

        finalEdges.push({
          data: {
            ...e.data,
            id: `pol-${src}-${tgt}-${lbl}-${seenEdgeSigs.size}`,
            source: src,
            target: tgt,
            label: e.data.action ? formatShortLabel(e.data.action) : lbl,
            edge_type: lbl,
            access_category: e.data.access_category || (e.data.action ? getActionCategory([e.data.action]) : lbl)
          },
          classes: e.classes || ''
        });
      }
    });

    // 2. Synthesize Aggregated Effective-Access Edges (When showPolicies is false)
    if (!showPolicies) {
      // First: derive from backend policy chains (Identity -> HAS_POLICY -> Policy -> ALLOWS -> Resource)
      Object.entries(identityToPolicies).forEach(([identityId, policies]) => {
        policies.forEach(policyId => {
          const allowsList = policyToAllows[policyId] || [];
          allowsList.forEach(allowEdge => {
            const rawResId = allowEdge.target;
            const resourceId = idToCanonical.get(rawResId) || rawResId;
            if (!nodeMap.has(identityId) || !nodeMap.has(resourceId) || identityId === resourceId) return;

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
          const rawIdentId = rec.identity_id;
          const identId = idToCanonical.get(rawIdentId) || rawIdentId;

          const resId = `aws:${rec.target_resource_type.toLowerCase()}:${rec.target_resource_name}`;
          const altResId = `aws:${rec.target_resource_type.toLowerCase()}:${rec.target_resource_id}`;
          const canonicalTarget = idToCanonical.get(resId) || idToCanonical.get(altResId);
          const targetId = canonicalTarget && nodeMap.has(canonicalTarget) ? canonicalTarget : null;

          if (!targetId || !nodeMap.has(identId) || identId === targetId) return;

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
        const category = getActionCategory(actionList, agg.targetType);
        const relType = category === 'CAN_INVOKE'
          ? 'CAN_INVOKE'
          : category === 'CAN_MANAGE' || category === 'CAN_MANAGE / INVOKE'
            ? 'CAN_MANAGE'
            : 'EFFECTIVE_ACCESS';

        finalEdges.push({
          data: {
            id: agg.id,
            source: agg.source,
            sourceId: agg.source,
            target: agg.target,
            targetId: agg.target,
            sourceType: agg.sourceType,
            targetType: agg.targetType,
            sourceArn: agg.sourceArn,
            targetArn: agg.targetArn,
            label: category,
            edge_type: relType,
            relationshipType: relType,
            access_category: category,
            actions: actionList,
            action: actionList[0] || '',
            policy_names: policyList,
            policy_name: policyList[0] || '',
            policies: policyList,
            statement_sids: sidList,
            statement_sid: sidList[0] || '',
            statementSids: sidList,
            decision: agg.decision,
            why: agg.why,
            provenance: agg.why || `Effective relationship (${category}) from '${agg.source}' to '${agg.target}'`,
            evidence: {
              sourceId: agg.source,
              targetId: agg.target,
              relationshipType: relType,
              decision: agg.decision,
              actions: actionList,
              policies: policyList,
              statementSids: sidList,
              why: agg.why
            },
            isActivity: agg.isActivity,
            region: agg.region
          }
        });
      });
    }

    return {
      nodes: finalNodes,
      edges: finalEdges
    };
  }, [rawElements, showPolicies, effectiveAccessData]);

  // Node Category Counts
  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    transformedGraph.nodes.forEach(n => {
      const t = n.data.type || 'Resource';
      counts[t] = (counts[t] || 0) + 1;
    });
    return counts;
  }, [transformedGraph]);

  // ─────────────────────────────────────────────────────────────────────────────
  // 2. SUBGRAPH FOCUS CALCULATION (Connected Security Subgraph)
  // ─────────────────────────────────────────────────────────────────────────────
  const activeFocusNodeId = selectedIdentityId || selectedResourceId || activeSelectedNodeId;

  const relevantSubgraph = useMemo(() => {
    if (!activeFocusNodeId) {
      return null;
    }

    const targetNode = transformedGraph.nodes.find(n => n.data.id === activeFocusNodeId);
    if (!targetNode) return null;

    const targetType = targetNode.data.type || 'Resource';
    const isIdentity = targetType === 'User' || targetType === 'Group' || targetType === 'Role' || targetType === 'Policy';

    const subNodes = new Set<string>();
    const subEdges = new Set<string>();

    subNodes.add(activeFocusNodeId);

    // Build directed adjacencies
    const outEdgesMap = new Map<string, Array<{ edgeId: string; target: string }>>();
    const inEdgesMap = new Map<string, Array<{ edgeId: string; source: string }>>();

    transformedGraph.edges.forEach(e => {
      const s = e.data.source;
      const t = e.data.target;
      const eid = e.data.id;

      if (!outEdgesMap.has(s)) outEdgesMap.set(s, []);
      outEdgesMap.get(s)!.push({ edgeId: eid, target: t });

      if (!inEdgesMap.has(t)) inEdgesMap.set(t, []);
      inEdgesMap.get(t)!.push({ edgeId: eid, source: s });
    });

    const maxHops = focusDepth === '1-hop' ? 1 : focusDepth === '2-hop' ? 2 : 99;

    if (isIdentity) {
      // Forward downstream traversal from identity to reachable resources
      // Also include direct upstream memberships (e.g. User -> Group)
      const queue: Array<{ id: string; depth: number }> = [{ id: activeFocusNodeId, depth: 0 }];
      const visited = new Set<string>([activeFocusNodeId]);

      // If user, also follow MEMBER_OF edges to parent groups
      if (targetType === 'User') {
        const outList = outEdgesMap.get(activeFocusNodeId) || [];
        outList.forEach(({ edgeId, target }) => {
          subNodes.add(target);
          subEdges.add(edgeId);
          if (!visited.has(target)) {
            visited.add(target);
            queue.push({ id: target, depth: 1 });
          }
        });
      }

      while (queue.length > 0) {
        const { id, depth } = queue.shift()!;
        if (depth >= maxHops) continue;

        const outList = outEdgesMap.get(id) || [];
        outList.forEach(({ edgeId, target }) => {
          subNodes.add(target);
          subEdges.add(edgeId);
          if (!visited.has(target)) {
            visited.add(target);
            queue.push({ id: target, depth: depth + 1 });
          }
        });
      }
    } else {
      // Reverse upstream traversal from resource to authorized identities
      const queue: Array<{ id: string; depth: number }> = [{ id: activeFocusNodeId, depth: 0 }];
      const visited = new Set<string>([activeFocusNodeId]);

      while (queue.length > 0) {
        const { id, depth } = queue.shift()!;
        if (depth >= maxHops) continue;

        const inList = inEdgesMap.get(id) || [];
        inList.forEach(({ edgeId, source }) => {
          subNodes.add(source);
          subEdges.add(edgeId);
          if (!visited.has(source)) {
            visited.add(source);
            queue.push({ id: source, depth: depth + 1 });
          }
        });
      }
    }

    return {
      focusedNodeId: activeFocusNodeId,
      subNodes,
      subEdges,
      isIdentity
    };
  }, [activeFocusNodeId, transformedGraph, focusDepth]);

  // ─────────────────────────────────────────────────────────────────────────────
  // 3. CYTOSCAPE INITIALIZATION (Visual DAG Model matching AttackPaths.tsx)
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
      maxZoom: 2.5,
      wheelSensitivity: 0.2,
      style: [
        // Base Node Style
        {
          selector: 'node',
          style: {
            'content': showLabels ? 'data(shortLabel)' : '',
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
        // Identity Node Types
        {
          selector: 'node[type = "User"]',
          style: {
            'background-color': ENTITY_STYLES.User.backgroundColor,
            'border-color': ENTITY_STYLES.User.borderColor,
            'shape': 'ellipse',
            'width': ENTITY_STYLES.User.width,
            'height': ENTITY_STYLES.User.height
          }
        },
        {
          selector: 'node[type = "Group"]',
          style: {
            'background-color': ENTITY_STYLES.Group.backgroundColor,
            'border-color': ENTITY_STYLES.Group.borderColor,
            'border-width': ENTITY_STYLES.Group.borderWidth || '3px',
            'shape': 'round-rectangle',
            'width': ENTITY_STYLES.Group.width,
            'height': ENTITY_STYLES.Group.height
          }
        },
        {
          selector: 'node[type = "Role"]',
          style: {
            'background-color': ENTITY_STYLES.Role.backgroundColor,
            'border-color': ENTITY_STYLES.Role.borderColor,
            'shape': 'hexagon',
            'width': ENTITY_STYLES.Role.width,
            'height': ENTITY_STYLES.Role.height
          }
        },
        {
          selector: 'node[type = "Policy"]',
          style: {
            'background-color': ENTITY_STYLES.Policy.backgroundColor,
            'border-color': ENTITY_STYLES.Policy.borderColor,
            'shape': 'diamond',
            'width': ENTITY_STYLES.Policy.width,
            'height': ENTITY_STYLES.Policy.height
          }
        },
        // Cloud Compute & Workloads
        {
          selector: 'node[type = "EC2"]',
          style: {
            'background-color': ENTITY_STYLES.EC2.backgroundColor,
            'border-color': ENTITY_STYLES.EC2.borderColor,
            'shape': 'round-rectangle',
            'width': ENTITY_STYLES.EC2.width,
            'height': ENTITY_STYLES.EC2.height
          }
        },
        {
          selector: 'node[type = "Lambda"]',
          style: {
            'background-color': ENTITY_STYLES.Lambda.backgroundColor,
            'border-color': ENTITY_STYLES.Lambda.borderColor,
            'shape': 'ellipse',
            'width': ENTITY_STYLES.Lambda.width,
            'height': ENTITY_STYLES.Lambda.height
          }
        },
        // Cloud Storage
        {
          selector: 'node[type = "S3"]',
          style: {
            'background-color': ENTITY_STYLES.S3.backgroundColor,
            'border-color': ENTITY_STYLES.S3.borderColor,
            'shape': 'barrel',
            'width': ENTITY_STYLES.S3.width,
            'height': ENTITY_STYLES.S3.height
          }
        },
        // Cloud Databases
        {
          selector: 'node[type = "RDS"], node[type = "Aurora"]',
          style: {
            'background-color': ENTITY_STYLES.RDS.backgroundColor,
            'border-color': ENTITY_STYLES.RDS.borderColor,
            'shape': 'round-rectangle',
            'width': ENTITY_STYLES.RDS.width,
            'height': ENTITY_STYLES.RDS.height
          }
        },
        {
          selector: 'node[type = "DynamoDB"]',
          style: {
            'background-color': ENTITY_STYLES.DynamoDB.backgroundColor,
            'border-color': ENTITY_STYLES.DynamoDB.borderColor,
            'shape': 'round-rectangle',
            'width': ENTITY_STYLES.DynamoDB.width,
            'height': ENTITY_STYLES.DynamoDB.height
          }
        },
        // Security & Secrets
        {
          selector: 'node[type = "Secrets"], node[type = "Secret"]',
          style: {
            'background-color': ENTITY_STYLES.Secrets.backgroundColor,
            'border-color': ENTITY_STYLES.Secrets.borderColor,
            'border-width': ENTITY_STYLES.Secrets.borderWidth || '3px',
            'shape': 'ellipse',
            'width': ENTITY_STYLES.Secrets.width,
            'height': ENTITY_STYLES.Secrets.height
          }
        },
        {
          selector: 'node[type = "KMS"]',
          style: {
            'background-color': ENTITY_STYLES.KMS.backgroundColor,
            'border-color': ENTITY_STYLES.KMS.borderColor,
            'shape': 'diamond',
            'width': ENTITY_STYLES.KMS.width,
            'height': ENTITY_STYLES.KMS.height
          }
        },
        // Application & Network
        {
          selector: 'node[type = "APIGateway"], node[type = "API"]',
          style: {
            'background-color': ENTITY_STYLES.APIGateway.backgroundColor,
            'border-color': ENTITY_STYLES.APIGateway.borderColor,
            'shape': 'round-rectangle',
            'width': ENTITY_STYLES.APIGateway.width,
            'height': ENTITY_STYLES.APIGateway.height
          }
        },
        {
          selector: 'node[type = "VPC"], node[type = "Subnet"], node[type = "SecurityGroup"]',
          style: {
            'background-color': ENTITY_STYLES.VPC.backgroundColor,
            'border-color': ENTITY_STYLES.VPC.borderColor,
            'shape': 'round-rectangle',
            'width': ENTITY_STYLES.VPC.width,
            'height': ENTITY_STYLES.VPC.height
          }
        },

        // Base Edge Style: Directed Connectors matching AttackPaths.tsx
        {
          selector: 'edge',
          style: {
            'label': showEdgeLabels ? 'data(label)' : '',
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

        // Effective Access Category Edge Color Palettes
        {
          selector: 'edge[label = "FULL ADMIN"], edge[access_category = "FULL ADMIN"]',
          style: {
            'line-color': '#EF4444',
            'target-arrow-color': '#EF4444',
            'width': 2.5,
            'opacity': 0.85
          }
        },
        {
          selector: 'edge[label = "READ / WRITE"], edge[access_category = "READ / WRITE"]',
          style: {
            'line-color': '#F59E0B',
            'target-arrow-color': '#F59E0B',
            'width': 2,
            'opacity': 0.8
          }
        },
        {
          selector: 'edge[label = "WRITE"], edge[access_category = "WRITE"]',
          style: {
            'line-color': '#F97316',
            'target-arrow-color': '#F97316',
            'width': 2,
            'opacity': 0.75
          }
        },
        {
          selector: 'edge[label = "READ"], edge[access_category = "READ"]',
          style: {
            'line-color': '#10B981',
            'target-arrow-color': '#10B981',
            'width': 2,
            'opacity': 0.75
          }
        },
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

        // ─────────────────────────────────────────────────────────────────────
        // VISUAL MODEL: Highlighted / Selected / Dimmed States
        // ─────────────────────────────────────────────────────────────────────
        {
          selector: 'node.highlighted',
          style: {
            'border-width': '4px',
            'border-color': '#FBBF24', // Amber glow
            'opacity': 1,
            'z-index': 999
          }
        },
        {
          selector: 'node.selected',
          style: {
            'border-width': '5px',
            'border-color': '#38BDF8', // Cyan spotlight
            'opacity': 1,
            'z-index': 1000
          }
        },
        {
          selector: 'edge.highlighted',
          style: {
            'line-color': '#EF4444', // Red path tracer
            'target-arrow-color': '#EF4444',
            'width': 3.5,
            'opacity': 1,
            'z-index': 998
          }
        },
        {
          selector: 'edge.selected',
          style: {
            'line-color': '#38BDF8',
            'target-arrow-color': '#38BDF8',
            'width': 4,
            'opacity': 1,
            'z-index': 999
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
        nodeSep: 60,
        rankSep: 100,
        edgeSep: 30,
        fit: true,
        spacingFactor: 1.15
      } as any
    });

    cyRef.current = cy;

    // Node click handler
    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      const nId = node.id();
      setActiveSelectedNodeId(nId);
      setActiveSelectedEdgeId(null);

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

    // Edge click handler
    cy.on('tap', 'edge', (evt) => {
      const edge = evt.target;
      const d = edge.data();
      setActiveSelectedEdgeId(edge.id());

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

    // Tooltip
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

    // Background click clears focus / selection
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setActiveSelectedNodeId(null);
        setActiveSelectedEdgeId(null);
        if (onNodeSelect) onNodeSelect(null);
        if (onEdgeSelect) onEdgeSelect(null);
        if (onClearFocus) onClearFocus();
      }
    });

    cy.ready(() => {
      cy.fit(undefined, 50);
    });

    const handleReset = () => {
      setActiveSelectedNodeId(null);
      setActiveSelectedEdgeId(null);
      if (onNodeSelect) onNodeSelect(null);
      if (onEdgeSelect) onEdgeSelect(null);
      if (onClearFocus) onClearFocus();
      cy.elements().removeClass('dimmed').removeClass('highlighted').removeClass('selected');
      cy.layout({
        name: 'dagre',
        directed: true,
        padding: 50,
        rankDir: 'TB',
        nodeSep: 60,
        rankSep: 100,
        edgeSep: 30,
        fit: true,
        spacingFactor: 1.15
      } as any).run();
      cy.fit(undefined, 50);
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
  }, [transformedGraph, showLabels, showEdgeLabels, onNodeSelect, onEdgeSelect, onClearFocus]);

  // ─────────────────────────────────────────────────────────────────────────────
  // 4. APPLY FOCUS & DIMMING SYSTEM (Synchronized across selection)
  // ─────────────────────────────────────────────────────────────────────────────
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      if (relevantSubgraph) {
        // Dim complete cloud graph
        cy.elements().addClass('dimmed').removeClass('highlighted').removeClass('selected');

        // Highlight active security subgraph nodes
        relevantSubgraph.subNodes.forEach(nid => {
          const ele = cy.getElementById(nid);
          if (ele.length > 0) {
            ele.removeClass('dimmed').addClass('highlighted');
          }
        });

        // Highlight active security subgraph edges
        relevantSubgraph.subEdges.forEach(eid => {
          const ele = cy.getElementById(eid);
          if (ele.length > 0) {
            ele.removeClass('dimmed').addClass('highlighted');
          }
        });

        // Strongest spotlight on primary selected entity
        const primary = cy.getElementById(relevantSubgraph.focusedNodeId);
        if (primary.length > 0) {
          primary.removeClass('dimmed').removeClass('highlighted').addClass('selected');
        }
      } else if (analystMode === 'attack_path' && (activeAttackPath.length > 0 || highlightedNodeIds.length > 0)) {
        // Attack Path Mode: Highlight only path sequence
        const pathNodes = activeAttackPath.length > 0 ? activeAttackPath : highlightedNodeIds;
        cy.elements().addClass('dimmed').removeClass('highlighted').removeClass('selected');

        pathNodes.forEach(nid => {
          const ele = cy.getElementById(nid);
          if (ele.length > 0) {
            ele.removeClass('dimmed').addClass('highlighted');
          }
        });

        // Highlight connecting edges along attack path
        for (let i = 0; i < pathNodes.length - 1; i++) {
          const u = pathNodes[i];
          const v = pathNodes[i + 1];
          cy.edges(`[source = "${u}"][target = "${v}"], [source = "${v}"][target = "${u}"]`)
            .removeClass('dimmed')
            .addClass('highlighted');
        }
      } else {
        // Normal Cloud View: All nodes and edges at normal opacity
        cy.elements().removeClass('dimmed').removeClass('highlighted').removeClass('selected');
      }

      // Filter Visibility Pills (Hide nodes if unselected in pill toolbar)
      Object.entries(activeFilters).forEach(([type, isVisible]) => {
        if (!isVisible) {
          cy.nodes(`[type = "${type}"]`).style('display', 'none');
          cy.nodes(`[type = "${type}"]`).connectedEdges().style('display', 'none');
        } else {
          cy.nodes(`[type = "${type}"]`).style('display', 'element');
          cy.nodes(`[type = "${type}"]`).connectedEdges().style('display', 'element');
        }
      });

      // Search Query Spotlight
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        cy.nodes().forEach(node => {
          const lbl = (node.data('label') || '').toLowerCase();
          const nid = (node.id() || '').toLowerCase();
          const t = (node.data('type') || '').toLowerCase();
          if (lbl.includes(q) || nid.includes(q) || t.includes(q)) {
            node.removeClass('dimmed').addClass('highlighted');
          }
        });
      }
    });
  }, [relevantSubgraph, analystMode, activeAttackPath, highlightedNodeIds, activeFilters, searchQuery]);

  // Zoom / Pan helpers
  const handleZoomIn = useCallback(() => {
    cyRef.current?.zoom({
      level: cyRef.current.zoom() * 1.25,
      renderedPosition: { x: cyRef.current.width() / 2, y: cyRef.current.height() / 2 }
    });
  }, []);

  const handleZoomOut = useCallback(() => {
    cyRef.current?.zoom({
      level: cyRef.current.zoom() * 0.8,
      renderedPosition: { x: cyRef.current.width() / 2, y: cyRef.current.height() / 2 }
    });
  }, []);

  const handleFit = useCallback(() => {
    cyRef.current?.fit(undefined, 50);
  }, []);

  const handleResetLayout = useCallback(() => {
    setActiveSelectedNodeId(null);
    setActiveSelectedEdgeId(null);
    if (onNodeSelect) onNodeSelect(null);
    if (onEdgeSelect) onEdgeSelect(null);
    if (onClearFocus) onClearFocus();
    if (cyRef.current) {
      cyRef.current.elements().removeClass('dimmed').removeClass('highlighted').removeClass('selected');
      cyRef.current.layout({
        name: 'dagre',
        directed: true,
        padding: 50,
        rankDir: 'TB',
        nodeSep: 60,
        rankSep: 100,
        edgeSep: 30,
        fit: true,
        spacingFactor: 1.15
      } as any).run();
      cyRef.current.fit(undefined, 50);
    }
  }, [onNodeSelect, onEdgeSelect, onClearFocus]);

  const handleExportPNG = useCallback(() => {
    if (!cyRef.current) return;
    const png = cyRef.current.png({ full: true, bg: '#0B0F19', scale: 2 });
    const a = document.createElement('a');
    a.href = png;
    a.download = `cloudscope-identity-graph-${new Date().toISOString().slice(0, 10)}.png`;
    a.click();
  }, []);

  const toggleFilter = (type: string) => {
    setActiveFilters(prev => ({ ...prev, [type]: !prev[type] }));
  };

  return (
    <div className="relative w-full h-full bg-[#0B0F19] overflow-hidden select-none flex flex-col">
      {/* Category Pills Toolbar */}
      <div className="flex-none px-4 py-2 border-b border-gray-800/80 bg-gray-950/70 backdrop-blur-md flex flex-wrap items-center justify-between gap-2 z-10">
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mr-1 flex items-center gap-1">
            <Filter className="w-3 h-3 text-gray-500" /> Universe:
          </span>
          {Object.entries(categoryCounts).map(([type, count]) => {
            const normalized = normalizeGraphType(type);
            const color = CANONICAL_FILTER_COLORS[normalized] || CANONICAL_FILTER_COLORS[type] || '#6B7280';
            const isActive = activeFilters[type] !== false;
            return (
              <button
                key={type}
                onClick={() => toggleFilter(type)}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-all flex items-center gap-1.5 border ${
                  isActive
                    ? 'bg-gray-900 border-gray-700 text-gray-200 hover:border-gray-500'
                    : 'bg-gray-950/40 border-gray-800/50 text-gray-600 line-through opacity-60'
                }`}
              >
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                <span>{type}</span>
                <span className="text-[10px] px-1 py-0.2 bg-gray-800 rounded font-mono text-gray-400">
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        {/* View Controls Toolbar */}
        <div className="flex items-center gap-1.5">
          {relevantSubgraph && (
            <button
              onClick={handleResetLayout}
              className="px-2 py-1 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 rounded text-xs font-medium flex items-center gap-1 transition-all mr-1 shadow-sm"
              title="Clear Highlight Focus and Show Complete Cloud Graph"
            >
              <Eye className="w-3.5 h-3.5" /> Show All
            </button>
          )}
          <button
            onClick={handleZoomIn}
            className="p-1.5 bg-gray-900/80 hover:bg-gray-800 text-gray-300 rounded border border-gray-800 hover:border-gray-700 transition-colors"
            title="Zoom In"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleZoomOut}
            className="p-1.5 bg-gray-900/80 hover:bg-gray-800 text-gray-300 rounded border border-gray-800 hover:border-gray-700 transition-colors"
            title="Zoom Out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleFit}
            className="p-1.5 bg-gray-900/80 hover:bg-gray-800 text-gray-300 rounded border border-gray-800 hover:border-gray-700 transition-colors"
            title="Fit Graph to Screen"
          >
            <Maximize2 className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleResetLayout}
            className="p-1.5 bg-gray-900/80 hover:bg-gray-800 text-gray-300 rounded border border-gray-800 hover:border-gray-700 transition-colors"
            title="Reset DAG Layout"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleExportPNG}
            className="p-1.5 bg-gray-900/80 hover:bg-gray-800 text-gray-300 rounded border border-gray-800 hover:border-gray-700 transition-colors"
            title="Export High-Res PNG"
          >
            <Download className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Main Graph Canvas Container */}
      <div className="relative flex-1 w-full h-full bg-[#0B0F19]">
        <div ref={containerRef} className="w-full h-full" />

        {/* Hover Tooltip */}
        {tooltip.visible && (
          <div
            className="absolute z-50 pointer-events-none px-2.5 py-1.5 bg-gray-900/95 text-gray-200 text-xs rounded shadow-xl border border-gray-700 backdrop-blur whitespace-pre-line font-mono"
            style={{
              left: `${tooltip.x}px`,
              top: `${tooltip.y}px`,
              transform: 'translate(-50%, -100%)'
            }}
          >
            {tooltip.text}
          </div>
        )}

        {/* Empty State Banner */}
        {transformedGraph.nodes.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-gray-500">
            <Layers className="w-12 h-12 mb-3 text-gray-600 animate-pulse" />
            <p className="text-sm font-medium">Synchronizing Cloud Topology...</p>
            <p className="text-xs text-gray-600 mt-1">Collecting IAM identities and cloud resources</p>
          </div>
        )}
      </div>
    </div>
  );
};
