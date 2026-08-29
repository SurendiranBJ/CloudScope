import { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { 
  ZoomIn, ZoomOut, Maximize2, List, Download, 
  Layers, ShieldAlert, Sparkles, ChevronDown
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getGraphElements } from '../api/graph';
import { formatRegion } from '../utils/regionNames';

// Register dagre extension
cytoscape.use(dagre);

export interface IdentityGraphProps {
  onNodeSelect?: (nodeData: any) => void;
  highlightedNodeIds?: string[];
  searchQuery?: string;
  showLabels?: boolean;
  showEdgeLabels?: boolean;
  highlightRisky?: boolean;
  securityFilter?: 'all' | 'critical' | 'high' | 'medium' | 'low' | 'attack_paths_only';
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
  if (clean.length > 20) {
    return clean.substring(0, 18) + '...';
  }
  return clean;
};

const SIX_LAYER_DEFINITIONS = [
  { rank: 0, title: '1. USERS', color: '#3B82F6', description: 'IAM Identities' },
  { rank: 1, title: '2. GROUPS', color: '#6366F1', description: 'IAM Group Clusters' },
  { rank: 2, title: '3. POLICIES', color: '#14B8A6', description: 'Permissions & AST Rules' },
  { rank: 3, title: '4. ROLES', color: '#8B5CF6', description: 'Privileged Roles' },
  { rank: 4, title: '5. RESOURCES', color: '#10B981', description: 'S3, EC2, Lambda, RDS, DynamoDB' },
  { rank: 5, title: '6. SENSITIVE ASSETS', color: '#EF4444', description: 'Secrets Manager' }
];

export const IdentityGraph: React.FC<IdentityGraphProps> = ({
  onNodeSelect,
  highlightedNodeIds = [],
  searchQuery = '',
  showLabels = true,
  showEdgeLabels = false,
  highlightRisky = false,
  securityFilter = 'all'
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [isLegendOpen, setIsLegendOpen] = useState(false);
  const [isLayerGuideOpen, setIsLayerGuideOpen] = useState(true);
  const [selectedEdgeData, setSelectedEdgeData] = useState<any>(null);
  const [activeSelectedNodeId, setActiveSelectedNodeId] = useState<string | null>(null);

  const { data } = useQuery({
    queryKey: ['graphElements'],
    queryFn: getGraphElements,
    refetchInterval: 10000
  });

  const rawElements = data || [];

  // Filter state for categories
  const [activeFilters, setActiveFilters] = useState<Record<string, boolean>>({
    User: true,
    Group: true,
    Policy: true,
    Role: true,
    S3: true,
    EC2: true,
    Lambda: true,
    RDS: true,
    DynamoDB: true,
    Secrets: true
  });

  const [tooltip, setTooltip] = useState<{ x: number; y: number; text: string; visible: boolean }>({
    x: 0,
    y: 0,
    text: '',
    visible: false
  });

  const filterColors: Record<string, string> = {
    User: '#3B82F6', // Blue
    Group: '#6366F1', // Indigo
    Policy: '#14B8A6', // Teal
    Role: '#8B5CF6', // Purple
    S3: '#F59E0B', // Amber
    EC2: '#10B981', // Green
    Lambda: '#EC4899', // Pink
    RDS: '#0EA5E9', // Sky Blue
    DynamoDB: '#A855F7', // Violet
    Secrets: '#EF4444', // Red
    Secret: '#EF4444'
  };

  // Build Topology mapping
  const graphTopology = useMemo(() => {
    const groupToUsers: Record<string, string[]> = {};
    const userToGroups: Record<string, string[]> = {};
    const groupToPolicies: Record<string, string[]> = {};
    const userToPolicies: Record<string, string[]> = {};
    const roleToPolicies: Record<string, string[]> = {};
    const policyToResources: Record<string, string[]> = {};
    const userToRoles: Record<string, string[]> = {};
    const roleToResources: Record<string, string[]> = {};

    rawElements.forEach((el: any) => {
      if (el.data.source && el.data.target) {
        const src = el.data.source;
        const tgt = el.data.target;
        const lbl = el.data.label;

        if (lbl === 'MEMBER_OF') {
          if (!groupToUsers[tgt]) groupToUsers[tgt] = [];
          if (!groupToUsers[tgt].includes(src)) groupToUsers[tgt].push(src);

          if (!userToGroups[src]) userToGroups[src] = [];
          if (!userToGroups[src].includes(tgt)) userToGroups[src].push(tgt);
        } else if (lbl === 'HAS_POLICY' || lbl === 'ATTACHED_TO') {
          if (src.includes(':group:')) {
            if (!groupToPolicies[src]) groupToPolicies[src] = [];
            if (!groupToPolicies[src].includes(tgt)) groupToPolicies[src].push(tgt);
          } else if (src.includes(':user:')) {
            if (!userToPolicies[src]) userToPolicies[src] = [];
            if (!userToPolicies[src].includes(tgt)) userToPolicies[src].push(tgt);
          } else if (src.includes(':role:')) {
            if (!roleToPolicies[src]) roleToPolicies[src] = [];
            if (!roleToPolicies[src].includes(tgt)) roleToPolicies[src].push(tgt);
          }
        } else if (lbl === 'ALLOWS' || lbl === 'CAN_ACCESS') {
          if (!policyToResources[src]) policyToResources[src] = [];
          if (!policyToResources[src].includes(tgt)) policyToResources[src].push(tgt);
        } else if (lbl === 'CAN_ASSUME' || lbl === 'ASSUMED_ROLE') {
          if (!userToRoles[src]) userToRoles[src] = [];
          if (!userToRoles[src].includes(tgt)) userToRoles[src].push(tgt);
        }
      }
    });

    return { 
      groupToUsers, userToGroups, groupToPolicies, 
      userToPolicies, roleToPolicies, policyToResources, 
      userToRoles, roleToResources 
    };
  }, [rawElements]);

  const counts = useMemo(() => {
    const tally: Record<string, number> = {
      User: 0,
      Group: 0,
      Policy: 0,
      Role: 0,
      S3: 0,
      EC2: 0,
      Lambda: 0,
      RDS: 0,
      DynamoDB: 0,
      Secrets: 0
    };

    const nodeElements = rawElements.filter((e: any) => !e.data.source);
    nodeElements.forEach((n: any) => {
      const type = n.data.type || 'Resource';
      if (tally[type] !== undefined) {
        tally[type]++;
      } else if (type === 'Secret') {
        tally.Secrets++;
      }
    });

    return tally;
  }, [rawElements]);

  const handleFilterToggle = (type: string) => {
    setActiveFilters((prev) => {
      const next = { ...prev, [type]: !prev[type] };
      applyFiltersAndPathways(next, highlightedNodeIds, searchQuery, securityFilter, activeSelectedNodeId);
      return next;
    });
  };

  // Helper function to update node visibility, filtering, and contextual isolation
  const applyFiltersAndPathways = useCallback((
    filters: typeof activeFilters,
    pathNodeIds: string[],
    search: string,
    secFilter: typeof securityFilter,
    selectedId: string | null
  ) => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      const q = search.trim().toLowerCase();
      let hasSearchMatch = false;

      cy.nodes().forEach((node) => {
        const type = node.data('type') || 'Resource';
        const label = (node.data('label') || '').toLowerCase();
        const arn = (node.data('arn') || '').toLowerCase();
        const id = node.id().toLowerCase();
        const riskScore = node.data('riskScore') || 0;

        // 1. Category filter
        const categoryKey = type === 'Secret' ? 'Secrets' : type;
        const passesCategory = filters[categoryKey] !== false;

        // 2. Search query matching name, ARN, or type
        const passesSearch = q === '' || label.includes(q) || arn.includes(q) || id.includes(q) || type.toLowerCase().includes(q);

        // 3. Security severity filter
        let passesSecurity = true;
        if (secFilter === 'critical') passesSecurity = riskScore >= 80;
        else if (secFilter === 'high') passesSecurity = riskScore >= 60;
        else if (secFilter === 'medium') passesSecurity = riskScore >= 40 && riskScore < 60;
        else if (secFilter === 'low') passesSecurity = riskScore < 40;
        else if (secFilter === 'attack_paths_only') {
          passesSecurity = pathNodeIds.includes(node.id());
        }

        if (passesCategory && passesSearch && passesSecurity) {
          node.style('display', 'element');
          if (q !== '' && passesSearch) {
            hasSearchMatch = true;
            node.addClass('search-match');
          } else {
            node.removeClass('search-match');
          }
        } else {
          node.style('display', 'none');
          node.removeClass('search-match');
        }
      });

      // 4. INTERACTIVE TRACE & HIGHLIGHT MODES
      if (pathNodeIds && pathNodeIds.length > 0) {
        // ATTACK PATH ISOLATION
        cy.elements().addClass('dimmed').removeClass('highlighted');

        pathNodeIds.forEach((id) => {
          const node = cy.getElementById(id);
          if (node.length > 0) {
            node.removeClass('dimmed').addClass('highlighted');
          }
        });

        for (let i = 0; i < pathNodeIds.length - 1; i++) {
          const source = pathNodeIds[i];
          const target = pathNodeIds[i + 1];
          cy.edges().forEach((edge) => {
            if (
              (edge.source().id() === source && edge.target().id() === target) ||
              (edge.source().id() === target && edge.target().id() === source)
            ) {
              edge.removeClass('dimmed').addClass('highlighted');
            }
          });
        }
      } else if (selectedId) {
        // CONTEXTUAL TRACE (User, Group, Role, Policy)
        const targetNode = cy.getElementById(selectedId);
        if (targetNode.length > 0) {
          cy.elements().addClass('dimmed').removeClass('highlighted');
          targetNode.removeClass('dimmed').addClass('highlighted');

          const type = (targetNode.data('type') || '').toLowerCase();
          if (type === 'group') {
            const memberIds = graphTopology.groupToUsers[selectedId] || [];
            memberIds.forEach(mId => {
              const mNode = cy.getElementById(mId);
              mNode.removeClass('dimmed').addClass('highlighted');
            });
            targetNode.connectedEdges().removeClass('dimmed').addClass('highlighted');
            const downstream = targetNode.outgoers();
            downstream.removeClass('dimmed').addClass('highlighted');
            downstream.outgoers().removeClass('dimmed').addClass('highlighted');
            downstream.outgoers().outgoers().removeClass('dimmed').addClass('highlighted');
          } else if (type === 'user') {
            const groupIds = graphTopology.userToGroups[selectedId] || [];
            groupIds.forEach(gId => {
              const gNode = cy.getElementById(gId);
              gNode.removeClass('dimmed').addClass('highlighted');
              gNode.outgoers().removeClass('dimmed').addClass('highlighted');
              gNode.outgoers().outgoers().removeClass('dimmed').addClass('highlighted');
            });
            targetNode.connectedEdges().removeClass('dimmed').addClass('highlighted');
            const downstream = targetNode.outgoers();
            downstream.removeClass('dimmed').addClass('highlighted');
            downstream.outgoers().removeClass('dimmed').addClass('highlighted');
          } else if (type === 'role') {
            targetNode.incomers().removeClass('dimmed').addClass('highlighted');
            targetNode.outgoers().removeClass('dimmed').addClass('highlighted');
            targetNode.connectedEdges().removeClass('dimmed').addClass('highlighted');
          } else {
            targetNode.neighborhood().removeClass('dimmed');
            targetNode.connectedEdges().removeClass('dimmed').addClass('highlighted');
          }
        }
      } else {
        // OVERVIEW: Clean state with subtle edges
        cy.elements().removeClass('dimmed').removeClass('highlighted');
      }

      if (q !== '' && hasSearchMatch) {
        const matches = cy.nodes('.search-match');
        if (matches.length > 0) {
          cy.animate({
            center: { eles: matches },
            zoom: Math.min(1.35, cy.zoom() * 1.1),
            duration: 350
          });
        }
      }
    });
  }, [graphTopology]);

  // Compute Clean 6-Layer Security Architecture Layout Coordinates
  const getLayoutOptions = useCallback((cyInstance?: cytoscape.Core) => {
    const activeCy = cyInstance || cyRef.current;
    if (!activeCy) {
      return { name: 'dagre', rankDir: 'TB', nodeSep: 70, rankSep: 140, fit: true };
    }

    const visibleNodes = activeCy.nodes().filter(n => n.style('display') !== 'none');
    const positions: Record<string, { x: number; y: number }> = {};

    const users = visibleNodes.filter(n => (n.data('type') || '').toLowerCase() === 'user');
    const groups = visibleNodes.filter(n => (n.data('type') || '').toLowerCase() === 'group');
    const policies = visibleNodes.filter(n => (n.data('type') || '').toLowerCase() === 'policy');
    const roles = visibleNodes.filter(n => (n.data('type') || '').toLowerCase() === 'role');
    const resources = visibleNodes.filter(n => {
      const t = (n.data('type') || '').toLowerCase();
      return t === 's3' || t === 'ec2' || t === 'lambda' || t === 'rds' || t === 'dynamodb' || t === 'resource';
    });
    const secrets = visibleNodes.filter(n => {
      const t = (n.data('type') || '').toLowerCase();
      return t === 'secrets' || t === 'secret';
    });

    // 1. Group & Member User Spatial Clustering (Zero crossing lines)
    const placedUserIds = new Set<string>();
    const groupClusterWidths: number[] = [];
    const groupCenters: Record<string, number> = {};

    groups.forEach((groupNode) => {
      const memberIds = graphTopology.groupToUsers[groupNode.id()] || [];
      const visibleMembers = users.filter(u => memberIds.includes(u.id()));
      visibleMembers.forEach(u => {
        placedUserIds.add(u.id());
      });

      const memberCount = Math.max(1, visibleMembers.length);
      const clusterWidth = Math.max(160, memberCount * 90);
      groupClusterWidths.push(clusterWidth);
    });

    const totalClusterSpan = groupClusterWidths.reduce((a, b) => a + b, 0) + Math.max(0, groups.length - 1) * 140;
    let currentX = -totalClusterSpan / 2;

    groups.forEach((groupNode, gIdx) => {
      const width = groupClusterWidths[gIdx];
      const groupCenterX = currentX + width / 2;
      groupCenters[groupNode.id()] = groupCenterX;

      // LAYER 2: GROUP (Y = 240px)
      positions[groupNode.id()] = {
        x: groupCenterX,
        y: 240
      };

      // LAYER 1: USERS BELONGING TO THIS GROUP (Y = 100px - directly above group)
      const memberIds = graphTopology.groupToUsers[groupNode.id()] || [];
      const visibleMembers = users.filter(u => memberIds.includes(u.id()));
      const mCount = visibleMembers.length;
      const mSpacing = 85;
      const mStartX = groupCenterX - ((mCount - 1) * mSpacing) / 2;

      visibleMembers.forEach((userNode, uIdx) => {
        positions[userNode.id()] = {
          x: mCount === 1 ? groupCenterX : mStartX + uIdx * mSpacing,
          y: 100
        };
      });

      currentX += width + 140; // Cluster separation gap
    });

    // Unassigned Users (Independent column)
    const unassignedUsers = users.filter(u => !placedUserIds.has(u.id()));
    if (unassignedUsers.length > 0) {
      const uStartX = currentX + 60;
      const uSpacing = 85;
      unassignedUsers.forEach((userNode, uIdx) => {
        positions[userNode.id()] = {
          x: uStartX + uIdx * uSpacing,
          y: 100
        };
      });
    }

    // 2. LAYER 3: POLICIES (Y = 380px)
    const placedPolicies = new Set<string>();
    policies.forEach((pNode) => {
      let assignedX = 0;
      let foundGroup = false;

      for (const [gId, gPolicies] of Object.entries(graphTopology.groupToPolicies)) {
        if (gPolicies.includes(pNode.id()) && groupCenters[gId] !== undefined) {
          assignedX = groupCenters[gId];
          foundGroup = true;
          break;
        }
      }

      if (foundGroup) {
        positions[pNode.id()] = { x: assignedX, y: 380 };
        placedPolicies.add(pNode.id());
      }
    });

    const remainingPolicies = policies.filter(p => !placedPolicies.has(p.id()));
    const rCount = remainingPolicies.length;
    const pSpacing = 110;
    const pStartX = -((rCount - 1) * pSpacing) / 2;
    remainingPolicies.forEach((pNode, idx) => {
      positions[pNode.id()] = {
        x: pStartX + idx * pSpacing,
        y: 380
      };
    });

    // 3. LAYER 4: ROLES (Y = 520px)
    const roleCount = roles.length;
    const roleSpacing = 120;
    const roleStartX = -((roleCount - 1) * roleSpacing) / 2;
    roles.forEach((rNode, i) => {
      positions[rNode.id()] = {
        x: roleStartX + i * roleSpacing,
        y: 520
      };
    });

    // 4. LAYER 5: RESOURCES (Y = 660px)
    const resCount = resources.length;
    const resSpacing = 105;
    const resStartX = -((resCount - 1) * resSpacing) / 2;
    resources.forEach((resNode, i) => {
      positions[resNode.id()] = {
        x: resStartX + i * resSpacing,
        y: 660
      };
    });

    // 5. LAYER 6: SENSITIVE ASSETS / SECRETS (Y = 800px)
    const secCount = secrets.length;
    const secSpacing = 120;
    const secStartX = -((secCount - 1) * secSpacing) / 2;
    secrets.forEach((secNode, i) => {
      positions[secNode.id()] = {
        x: secStartX + i * secSpacing,
        y: 800
      };
    });

    return {
      name: 'preset',
      positions,
      fit: true,
      padding: 60,
      animate: true,
      animationDuration: 350
    };
  }, [graphTopology]);

  // Update visibility & pathway highlights on state changes
  useEffect(() => {
    applyFiltersAndPathways(activeFilters, highlightedNodeIds, searchQuery, securityFilter, activeSelectedNodeId);
  }, [highlightedNodeIds, searchQuery, activeFilters, securityFilter, activeSelectedNodeId, applyFiltersAndPathways]);

  // Initializing Cytoscape Graph
  useEffect(() => {
    if (!containerRef.current) return;

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: JSON.parse(JSON.stringify(rawElements)),
      minZoom: 0.1,
      maxZoom: 3,
      wheelSensitivity: 0.2,
      style: [
        // Base Node Style with Short Readable Label
        {
          selector: 'node',
          style: {
            'content': ((ele: cytoscape.NodeSingular) => {
              if (!showLabels) return '';
              return formatShortLabel(ele.data('label') || ele.id());
            }) as any,
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
            'text-background-shape': 'roundrectangle',
            'text-border-width': 1,
            'text-border-color': '#334155',
            'text-border-opacity': 0.6
          }
        },
        // Layer 1: Users (Blue Circle)
        {
          selector: 'node[type="User"]',
          style: {
            'background-color': filterColors.User,
            'border-color': '#60A5FA',
            'shape': 'ellipse',
            'width': '40px',
            'height': '40px'
          }
        },
        // Layer 2: Groups (Indigo Rounded Container)
        {
          selector: 'node[type="Group"]',
          style: {
            'background-color': filterColors.Group,
            'border-color': '#818CF8',
            'border-width': '3px',
            'shape': 'round-rectangle',
            'width': '52px',
            'height': '44px'
          }
        },
        // Layer 3: Policies (Teal Diamond)
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
        // Layer 4: Roles (Purple Hexagon)
        {
          selector: 'node[type="Role"]',
          style: {
            'background-color': filterColors.Role,
            'border-color': '#A78BFA',
            'shape': 'hexagon',
            'width': '46px',
            'height': '46px'
          }
        },
        // Layer 5: Resources (S3, EC2, Lambda, RDS, DynamoDB)
        {
          selector: 'node[type="S3"]',
          style: {
            'background-color': filterColors.S3,
            'border-color': '#FBBF24',
            'shape': 'barrel'
          }
        },
        {
          selector: 'node[type="EC2"]',
          style: {
            'background-color': filterColors.EC2,
            'border-color': '#34D399',
            'shape': 'round-rectangle'
          }
        },
        {
          selector: 'node[type="Lambda"]',
          style: {
            'background-color': filterColors.Lambda,
            'border-color': '#F472B6',
            'shape': 'ellipse'
          }
        },
        {
          selector: 'node[type="RDS"]',
          style: {
            'background-color': filterColors.RDS,
            'border-color': '#38BDF8',
            'shape': 'database' as cytoscape.Css.NodeShape
          }
        },
        {
          selector: 'node[type="DynamoDB"]',
          style: {
            'background-color': filterColors.DynamoDB,
            'border-color': '#C084FC',
            'shape': 'database' as cytoscape.Css.NodeShape
          }
        },
        // Layer 6: Sensitive Assets (Secrets Red Ellipse)
        {
          selector: 'node[type="Secrets"], node[type="Secret"]',
          style: {
            'background-color': filterColors.Secrets,
            'border-color': '#F87171',
            'shape': 'ellipse'
          }
        },
        // Base Clean Edge Styling (Low default density to prevent spider web)
        {
          selector: 'edge',
          style: {
            'label': ((edge: cytoscape.EdgeSingular) => {
              if (showEdgeLabels) return edge.data('label') || '';
              if (edge.hasClass('highlighted') || edge.hasClass('selected')) return edge.data('label') || '';
              return '';
            }) as any,
            'font-family': 'Inter, monospace',
            'font-size': '9px',
            'font-weight': 'bold',
            'color': '#CBD5E1',
            'text-background-color': '#0F172A',
            'text-background-opacity': 0.85,
            'text-background-padding': '2px',
            'text-background-shape': 'roundrectangle',
            'width': 1.5,
            'line-color': '#475569',
            'line-style': 'solid',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'text-rotation': 'autorotate',
            'text-margin-y': -8,
            'opacity': 0.35,
            'transition-property': 'line-color, target-arrow-color, width, opacity',
            'transition-duration': 0.25
          }
        },
        // Direct Vertical MEMBER_OF Connectors (User -> Group)
        {
          selector: 'edge[label = "MEMBER_OF"]',
          style: {
            'line-color': '#818CF8',
            'target-arrow-color': '#818CF8',
            'line-style': 'solid',
            'width': 2,
            'curve-style': 'straight',
            'opacity': 0.85
          }
        },
        // Dynamic Activity Edges
        {
          selector: 'edge[label = "ASSUMED_ROLE"], edge[label = "MODIFIED_CONFIG"]',
          style: {
            'line-color': '#F59E0B',
            'target-arrow-color': '#F59E0B',
            'line-style': 'dashed',
            'width': 2.5,
            'opacity': 0.9
          }
        },
        // Focused / Selected States
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
          selector: 'node.search-match',
          style: {
            'border-width': '4px',
            'border-color': '#38BDF8',
            'opacity': 1,
            'z-index': 999
          }
        },
        {
          selector: 'edge.highlighted',
          style: {
            'line-color': '#EF4444',
            'target-arrow-color': '#EF4444',
            'width': 2.5,
            'opacity': 1,
            'line-style': 'solid',
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
        },
        {
          selector: 'edge.risky',
          style: {
            'line-color': '#EF4444',
            'target-arrow-color': '#EF4444',
            'width': 2,
            'line-style': 'solid',
            'opacity': 0.95
          }
        }
      ]
    });

    cyRef.current = cy;

    // Apply layout
    const initialLayout = cy.layout(getLayoutOptions(cy) as any);
    initialLayout.run();

    // Apply risky path highlighting if toggled
    if (highlightRisky) {
      cy.edges().forEach(edge => {
        if (edge.data('isRisky')) {
          edge.addClass('risky');
        }
      });
    } else {
      cy.edges().removeClass('risky');
    }

    // Node click handler: Triggers contextual identity / group / role trace
    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      const nId = node.id();
      
      setActiveSelectedNodeId(nId);
      if (onNodeSelect) {
        onNodeSelect(node.data());
      }
    });

    // Edge click handler
    cy.on('tap', 'edge', (evt) => {
      const edge = evt.target;
      cy.edges().removeClass('selected');
      edge.addClass('selected');
      setSelectedEdgeData({
        source: edge.source().data('label') || edge.source().id(),
        target: edge.target().data('label') || edge.target().id(),
        label: edge.data('label') || 'Relationship',
        type: edge.data('type') || ''
      });
    });

    // Hover tooltip events
    cy.on('mouseover', 'node', (evt) => {
      const node = evt.target;
      const label = node.data('label') || node.id();
      const type = node.data('type') || 'Resource';
      const arn = node.data('arn');
      const region = node.data('region');
      const renderedPos = node.renderedPosition();
      
      const tooltipLines = [
        `${label} (${type})`,
        ...(type.toLowerCase() === 'group' ? [`👥 Members: ${(graphTopology.groupToUsers[node.id()] || []).length}`] : []),
        ...(arn ? [arn] : []),
        ...(region ? [`📍 ${formatRegion(region)}`] : [])
      ];

      setTooltip({
        x: renderedPos.x,
        y: renderedPos.y - 30,
        text: tooltipLines.join('\n'),
        visible: true
      });
    });

    cy.on('mouseout', 'node', () => {
      setTooltip(prev => ({ ...prev, visible: false }));
    });

    cy.on('drag pan zoom', () => {
      setTooltip(prev => ({ ...prev, visible: false }));
    });

    // Background click handler to clear selection
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setActiveSelectedNodeId(null);
        setSelectedEdgeData(null);
        if (onNodeSelect) onNodeSelect(null);
      }
    });
    
    const handleReset = () => {
      setActiveSelectedNodeId(null);
      setSelectedEdgeData(null);
      if (onNodeSelect) onNodeSelect(null);
      cy.elements().removeClass('dimmed').removeClass('highlighted').removeClass('selected');
      cy.layout(getLayoutOptions(cy) as any).run();
    };
    
    window.addEventListener('graph:reset', handleReset);

    const handleResize = () => {
      cy.resize();
    };
    window.addEventListener('resize', handleResize);

    applyFiltersAndPathways(activeFilters, highlightedNodeIds, searchQuery, securityFilter, activeSelectedNodeId);

    cy.ready(() => {
      cy.fit(undefined, 60);
    });

    return () => {
      window.removeEventListener('graph:reset', handleReset);
      window.removeEventListener('resize', handleResize);
      cy.destroy();
      cyRef.current = null;
    };
  }, [rawElements, showLabels, showEdgeLabels, highlightRisky, onNodeSelect, getLayoutOptions, applyFiltersAndPathways, activeFilters, highlightedNodeIds, searchQuery, securityFilter, activeSelectedNodeId, graphTopology]);

  // Controls API
  const handleZoomIn = () => {
    const cy = cyRef.current;
    if (!cy) return;
    const currentZoom = cy.zoom();
    cy.zoom({
      level: Math.min(3, currentZoom * 1.25),
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 }
    });
  };

  const handleZoomOut = () => {
    const cy = cyRef.current;
    if (!cy) return;
    const currentZoom = cy.zoom();
    cy.zoom({
      level: Math.max(0.1, currentZoom / 1.25),
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 }
    });
  };

  const handleFit = () => {
    cyRef.current?.fit(undefined, 60);
  };

  const handleExportImage = () => {
    if (!cyRef.current) return;
    const png = cyRef.current.png({ bg: '#0B1120', full: true });
    const a = document.createElement('a');
    a.href = png;
    a.download = 'cloudscope-identity-architecture.png';
    a.click();
  };

  return (
    <div className="w-full h-full relative bg-[#0B1120] overflow-hidden select-none">
      
      {/* Subtle Horizontal Layer Guideline Markers */}
      <div className="absolute inset-0 pointer-events-none z-0 flex flex-col justify-between py-10 px-8 opacity-20">
        {SIX_LAYER_DEFINITIONS.map(layer => (
          <div key={layer.rank} className="flex items-center gap-4 w-full">
            <span className="text-[10px] font-mono font-bold tracking-widest text-gray-500 uppercase whitespace-nowrap">{layer.title}</span>
            <div className="flex-1 h-[1px] bg-gradient-to-r from-gray-700/60 via-gray-800/30 to-transparent" />
          </div>
        ))}
      </div>

      {/* Visual Architectural Layer Track (Left Guide Rail) */}
      {isLayerGuideOpen && (
        <div className="absolute left-4 top-16 z-10 hidden xl:flex flex-col gap-2 p-3 rounded-xl bg-[#0F172A]/90 backdrop-blur-md border border-gray-800 shadow-2xl pointer-events-auto">
          <div className="flex items-center justify-between gap-3 pb-1.5 border-b border-gray-800">
            <span className="text-[10px] uppercase font-bold tracking-wider text-gray-400 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-blue-400" />
              Security Architecture
            </span>
            <button 
              onClick={() => setIsLayerGuideOpen(false)}
              className="text-gray-500 hover:text-gray-300 text-[10px]"
              title="Hide Layer Guide"
            >
              ✕
            </button>
          </div>
          <div className="space-y-1.5 pt-1">
            {SIX_LAYER_DEFINITIONS.map(layer => (
              <div key={layer.rank} className="flex items-center gap-2 text-xs">
                <span className="w-2.5 h-2.5 rounded-full shrink-0 shadow-sm" style={{ backgroundColor: layer.color }} />
                <span className="font-mono text-[11px] font-semibold text-gray-300">{layer.title}</span>
                <span className="text-[10px] text-gray-500 ml-auto hidden 2xl:inline">({layer.description})</span>
              </div>
            ))}
          </div>

          <div className="pt-2 mt-1 border-t border-gray-800 flex items-center justify-between gap-2">
            <span className="text-[9px] text-gray-500 font-mono">
              {activeSelectedNodeId ? 'Mode: Focused Trace' : 'Mode: Security Overview'}
            </span>
          </div>
        </div>
      )}

      {/* Floating Category Filter Pills */}
      <div className="absolute top-4 left-4 right-4 z-10 flex flex-wrap items-center gap-2">
        {Object.keys(activeFilters).map((filterKey) => {
          const color = filterColors[filterKey] || '#64748B';
          const active = activeFilters[filterKey];
          const count = counts[filterKey] || 0;
          return (
            <button
              key={filterKey}
              onClick={() => handleFilterToggle(filterKey)}
              className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs font-medium transition-all duration-150 border ${
                active
                  ? 'bg-[#1E293B] text-white border-gray-700 shadow-sm'
                  : 'bg-transparent text-gray-500 border-transparent hover:text-gray-300'
              }`}
            >
              <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: color }} />
              <span>{filterKey}</span>
              <span className={`px-1.5 py-0.5 rounded-full text-[10px] ${active ? 'bg-gray-800 text-gray-300' : 'bg-transparent text-gray-600'}`}>{count}</span>
            </button>
          );
        })}
        
        <div className="flex-1" />
        
        {/* Floating Zoom & Export Controls */}
        <div className="flex items-center gap-1.5 bg-[#1E293B]/90 backdrop-blur border border-gray-700 rounded-lg p-1 shadow-lg">
          <button onClick={handleZoomIn} className="p-1 hover:bg-gray-700 rounded text-gray-300 transition-colors" title="Zoom In"><ZoomIn className="w-4 h-4" /></button>
          <button onClick={handleZoomOut} className="p-1 hover:bg-gray-700 rounded text-gray-300 transition-colors" title="Zoom Out"><ZoomOut className="w-4 h-4" /></button>
          <button onClick={handleFit} className="p-1 hover:bg-gray-700 rounded text-gray-300 transition-colors" title="Fit to Screen"><Maximize2 className="w-4 h-4" /></button>
          <div className="w-[1px] h-4 bg-gray-700 mx-1"></div>
          <button onClick={handleExportImage} className="p-1 hover:bg-gray-700 rounded text-gray-300 transition-colors" title="Export Security Architecture PNG"><Download className="w-4 h-4" /></button>
        </div>
      </div>

      {/* Selected Edge Info Banner */}
      {selectedEdgeData && (
        <div className="absolute top-16 right-4 z-10 bg-[#0F172A]/95 backdrop-blur-md border border-blue-500/50 rounded-lg px-4 py-2 text-xs shadow-2xl flex items-center gap-3">
          <Sparkles className="w-4 h-4 text-blue-400" />
          <div>
            <span className="text-gray-400 font-mono text-[10px]">RELATIONSHIP: </span>
            <span className="font-semibold text-blue-400 font-mono">{selectedEdgeData.label}</span>
            <div className="text-[11px] text-gray-300 mt-0.5">
              {selectedEdgeData.source} <span className="text-gray-500">→</span> {selectedEdgeData.target}
            </div>
          </div>
          <button onClick={() => setSelectedEdgeData(null)} className="text-gray-500 hover:text-gray-300 text-xs ml-2">✕</button>
        </div>
      )}

      {/* Legend Overlay */}
      <div className="absolute bottom-6 left-6 z-10">
        {!isLegendOpen ? (
          <div className="flex items-center gap-2">
            <button 
              onClick={() => setIsLegendOpen(true)}
              className="flex items-center gap-2 bg-[#0F172A]/90 backdrop-blur-md border border-gray-800 hover:border-gray-600 rounded-lg px-4 py-2 text-xs font-semibold text-gray-300 shadow-xl transition-colors"
            >
              <List className="w-4 h-4" />
              <span>Show Legend</span>
            </button>
            {!isLayerGuideOpen && (
              <button 
                onClick={() => setIsLayerGuideOpen(true)}
                className="flex items-center gap-2 bg-[#0F172A]/90 backdrop-blur-md border border-gray-800 hover:border-gray-600 rounded-lg px-3 py-2 text-xs font-medium text-gray-400 shadow-xl transition-colors"
              >
                <Layers className="w-3.5 h-3.5" />
                <span>Show Layers</span>
              </button>
            )}
          </div>
        ) : (
          <div className="bg-[#0F172A]/95 backdrop-blur-md border border-gray-800 rounded-xl p-4 w-56 shadow-2xl">
            <div className="flex justify-between items-center mb-3 border-b border-gray-800 pb-2">
              <h4 className="text-xs font-semibold text-gray-300 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-blue-400" />
                <span>Security Legend</span>
              </h4>
              <button 
                onClick={() => setIsLegendOpen(false)}
                className="text-gray-500 hover:text-gray-300 transition-colors"
              >
                <ChevronDown className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-2">
              {Object.keys(activeFilters).map((filterKey) => {
                 const color = filterColors[filterKey] || '#64748B';
                 let shapeClass = "w-3 h-3 rounded-full";
                 if (filterKey === 'Role' || filterKey === 'Policy') shapeClass = "w-3 h-3 rotate-45 transform bg-opacity-90";
                 if (filterKey === 'S3') shapeClass = "w-3 h-3 rounded-sm";
                 if (filterKey === 'EC2' || filterKey === 'Group') shapeClass = "w-3.5 h-2.5 rounded-sm";
                 
                 return (
                   <div key={filterKey} className="flex items-center gap-2">
                     <div className={`${shapeClass}`} style={{ backgroundColor: color }} />
                     <span className="text-[11px] text-gray-400">{filterKey}</span>
                   </div>
                 );
              })}
              
              <div className="pt-2 mt-2 border-t border-gray-800 space-y-1.5">
                <div className="flex items-center gap-2">
                   <div className="w-4 h-0 border-t-2 border-indigo-400 border-solid" />
                   <span className="text-[9px] text-indigo-400 font-mono tracking-wider">MEMBER_OF (Group)</span>
                </div>
                <div className="flex items-center gap-2">
                   <div className="w-4 h-0 border-t border-slate-500 border-solid" />
                   <span className="text-[9px] text-gray-400 font-mono tracking-wider">Access / Policy</span>
                </div>
                <div className="flex items-center gap-2">
                   <div className="w-4 h-0 border-t-2 border-amber-400 border-dashed" />
                   <span className="text-[9px] text-amber-400 font-mono tracking-wider">Activity (ASSUMED_ROLE)</span>
                </div>
                <div className="flex items-center gap-2">
                   <div className="w-4 h-0 border-t-2 border-red-500 border-solid" />
                   <span className="text-[9px] text-red-400 font-mono tracking-wider">Attack Path</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Hover Tooltip Overlay */}
      {tooltip.visible && (
        <div
          className="absolute z-50 pointer-events-none bg-[#0F172A]/95 border border-gray-700 text-gray-200 text-xs px-3 py-1.5 rounded-lg shadow-2xl backdrop-blur-md transition-opacity duration-150 transform -translate-x-1/2 -translate-y-full flex flex-col gap-0.5 max-w-sm"
          style={{
            left: `${tooltip.x}px`,
            top: `${tooltip.y}px`
          }}
        >
          {tooltip.text.split('\n').map((line, i) => (
            <span
              key={i}
              className={i === 0 ? 'font-semibold text-white truncate' : 'text-[10px] text-gray-400 truncate'}
            >
              {line}
            </span>
          ))}
        </div>
      )}

      {/* Graph Area */}
      <div ref={containerRef} className="w-full h-full" />
    </div>
  );
};
