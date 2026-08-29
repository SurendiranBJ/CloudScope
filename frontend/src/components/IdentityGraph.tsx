import { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { 
  ZoomIn, ZoomOut, Maximize2, ChevronDown, List, Download, 
  Layers, ShieldAlert, Sparkles, Eye, EyeOff 
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getGraphElements } from '../api/graph';
import { formatRegion } from '../utils/regionNames';

// Register dagre extension
cytoscape.use(dagre);

export interface IdentityGraphProps {
  onNodeSelect?: (nodeData: any) => void;
  highlightedNodeIds?: string[];
  layoutMode?: 'clustered' | 'vertical' | 'dagre' | 'breadthfirst' | 'cose';
  searchQuery?: string;
  showLabels?: boolean;
  showEdgeLabels?: boolean;
  highlightRisky?: boolean;
  securityFilter?: 'all' | 'critical' | 'high' | 'medium' | 'low' | 'attack_paths_only';
}

export const getNodeRank = (type?: string): number => {
  const t = (type || '').toLowerCase();
  if (t === 'group') return 0; // LEVEL 1: GROUPS
  if (t === 'user') return 1;  // LEVEL 2: USERS (Clustered directly under groups)
  if (t === 'policy') return 2; // LEVEL 3: POLICIES
  if (t === 'role') return 3;   // LEVEL 4: ROLES
  if (t === 's3' || t === 'ec2' || t === 'lambda' || t === 'rds' || t === 'dynamodb' || t === 'resource') return 4; // LEVEL 5: RESOURCES
  if (t === 'secrets' || t === 'secret') return 5; // LEVEL 6: SENSITIVE ASSETS
  return 4;
};

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
    return clean.substring(0, 19) + '...';
  }
  return clean;
};

const LAYER_DEFINITIONS = [
  { rank: 0, title: '1. GROUPS & USERS', color: '#6366F1', description: 'IAM Group Clusters & Identities' },
  { rank: 1, title: '2. POLICIES', color: '#14B8A6', description: 'Permissions & AST Rules' },
  { rank: 2, title: '3. ROLES', color: '#8B5CF6', description: 'Privileged IAM Roles' },
  { rank: 3, title: '4. RESOURCES', color: '#10B981', description: 'S3, EC2, Lambda, RDS, DynamoDB' },
  { rank: 4, title: '5. SENSITIVE ASSETS', color: '#EF4444', description: 'Secrets & High-Value Targets' }
];

export const IdentityGraph: React.FC<IdentityGraphProps> = ({
  onNodeSelect,
  highlightedNodeIds = [],
  layoutMode = 'clustered',
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
  const [collapsedGroups, setCollapsedGroups] = useState<Record<string, boolean>>({});

  const { data } = useQuery({
    queryKey: ['graphElements'],
    queryFn: getGraphElements,
    refetchInterval: 10000
  });

  const elements = data || [];

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

  // Build group membership map from elements
  const groupMembership = useMemo(() => {
    const map: Record<string, string[]> = {}; // groupId -> memberUserIds
    const userToGroups: Record<string, string[]> = {}; // userId -> groupIds

    elements.forEach((el: any) => {
      if (el.data.source && el.data.target && el.data.label === 'MEMBER_OF') {
        const userId = el.data.source;
        const groupId = el.data.target;
        if (!map[groupId]) map[groupId] = [];
        if (!map[groupId].includes(userId)) map[groupId].push(userId);

        if (!userToGroups[userId]) userToGroups[userId] = [];
        if (!userToGroups[userId].includes(groupId)) userToGroups[userId].push(groupId);
      }
    });

    return { groupToUsers: map, userToGroups };
  }, [elements]);

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

    const nodeElements = elements.filter((e: any) => !e.data.source);
    nodeElements.forEach((n: any) => {
      const type = n.data.type || 'Resource';
      if (tally[type] !== undefined) {
        tally[type]++;
      } else if (type === 'Secret') {
        tally.Secrets++;
      }
    });

    return tally;
  }, [elements]);

  const handleFilterToggle = (type: string) => {
    setActiveFilters((prev) => {
      const next = { ...prev, [type]: !prev[type] };
      applyFiltersAndPathways(next, highlightedNodeIds, searchQuery, securityFilter, collapsedGroups);
      return next;
    });
  };

  const toggleGroupCollapse = (groupId: string) => {
    setCollapsedGroups(prev => {
      const next = { ...prev, [groupId]: !prev[groupId] };
      applyFiltersAndPathways(activeFilters, highlightedNodeIds, searchQuery, securityFilter, next);
      return next;
    });
  };

  const toggleAllGroupsCollapse = (collapse: boolean) => {
    const groupNodes = elements.filter((e: any) => !e.data.source && e.data.type === 'Group');
    const next: Record<string, boolean> = {};
    groupNodes.forEach((g: any) => {
      next[g.data.id] = collapse;
    });
    setCollapsedGroups(next);
    applyFiltersAndPathways(activeFilters, highlightedNodeIds, searchQuery, securityFilter, next);
  };

  // Helper function to update node visibility, filters, search, and attack pathways
  const applyFiltersAndPathways = useCallback((
    filters: typeof activeFilters,
    pathNodeIds: string[],
    search: string,
    secFilter: typeof securityFilter,
    collapsed: Record<string, boolean>
  ) => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      const q = search.trim().toLowerCase();
      let hasSearchMatch = false;

      // Identify users hidden due to group collapse
      const hiddenMemberUsers = new Set<string>();
      Object.entries(collapsed).forEach(([groupId, isCollapsed]) => {
        if (isCollapsed && groupMembership.groupToUsers[groupId]) {
          groupMembership.groupToUsers[groupId].forEach(uId => hiddenMemberUsers.add(uId));
        }
      });

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

        // 4. Collapse filter for member users
        const isCollapsedUser = type === 'User' && hiddenMemberUsers.has(node.id());

        // Update group node label if collapsed
        if (type === 'Group') {
          const members = groupMembership.groupToUsers[node.id()] || [];
          if (collapsed[node.id()] && members.length > 0) {
            node.data('displayLabel', `${node.data('label') || node.id()} (${members.length} Users)`);
          } else {
            node.data('displayLabel', node.data('label') || node.id());
          }
        }

        if (passesCategory && passesSearch && passesSecurity && !isCollapsedUser) {
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

      // 5. Highlight attack pathway if active
      if (pathNodeIds && pathNodeIds.length > 0) {
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
      } else {
        cy.elements().removeClass('dimmed').removeClass('highlighted');
      }

      if (q !== '' && hasSearchMatch) {
        const matches = cy.nodes('.search-match');
        if (matches.length > 0) {
          cy.animate({
            center: { eles: matches },
            zoom: Math.min(1.4, cy.zoom() * 1.1),
            duration: 350
          });
        }
      }
    });
  }, [groupMembership]);

  // Compute Layout Options with Group-Clustered Top-to-Bottom Structure
  const getLayoutOptions = useCallback((mode: string, cyInstance?: cytoscape.Core) => {
    const activeCy = cyInstance || cyRef.current;
    
    if ((mode === 'clustered' || mode === 'vertical') && activeCy) {
      // USER-GROUP CLUSTERED HIERARCHICAL LAYOUT
      const visibleNodes = activeCy.nodes().filter(n => n.style('display') !== 'none');
      const positions: Record<string, { x: number; y: number }> = {};

      const groups = visibleNodes.filter(n => (n.data('type') || '').toLowerCase() === 'group');
      const directUsers = visibleNodes.filter(n => (n.data('type') || '').toLowerCase() === 'user');
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

      // 1. Position Groups and their Member Users as Distinct Spatial Clusters
      const placedUserIds = new Set<string>();
      const groupClusterWidths: number[] = [];
      const clusterCenters: number[] = [];

      // Calculate width and center for each group cluster
      groups.forEach((groupNode) => {
        const memberIds = groupMembership.groupToUsers[groupNode.id()] || [];
        const visibleMembers = directUsers.filter(u => memberIds.includes(u.id()));
        visibleMembers.forEach((u) => {
          placedUserIds.add(u.id());
        });

        const memberCount = visibleMembers.length;
        const clusterWidth = Math.max(160, memberCount * 90);
        groupClusterWidths.push(clusterWidth);
      });

      const totalClusterSpan = groupClusterWidths.reduce((a, b) => a + b, 0) + (groups.length - 1) * 120;
      let startX = -totalClusterSpan / 2;

      groups.forEach((groupNode, gIdx) => {
        const width = groupClusterWidths[gIdx];
        const groupCenterX = startX + width / 2;
        clusterCenters.push(groupCenterX);

        // Position Group Node at Level 1 (Y = 100)
        positions[groupNode.id()] = {
          x: groupCenterX,
          y: 100
        };

        // Position Member Users directly beneath this Group at Level 2 (Y = 220)
        const memberIds = groupMembership.groupToUsers[groupNode.id()] || [];
        const visibleMembers = directUsers.filter(u => memberIds.includes(u.id()));
        const mCount = visibleMembers.length;
        const mSpacing = 85;
        const mStartX = groupCenterX - ((mCount - 1) * mSpacing) / 2;

        visibleMembers.forEach((userNode, uIdx) => {
          positions[userNode.id()] = {
            x: mCount === 1 ? groupCenterX : mStartX + uIdx * mSpacing,
            y: 220
          };
        });

        startX += width + 120; // Move to next group cluster with separation gap
      });

      // Position unassigned users in a dedicated standalone cluster
      const unassignedUsers = directUsers.filter(u => !placedUserIds.has(u.id()));
      if (unassignedUsers.length > 0) {
        const unassignedStartX = startX;
        const uSpacing = 85;
        unassignedUsers.forEach((userNode, uIdx) => {
          positions[userNode.id()] = {
            x: unassignedStartX + uIdx * uSpacing,
            y: 220
          };
        });
      }

      // 2. Position Policies at Level 3 (Y = 380)
      const policyCount = policies.length;
      const policySpacing = 110;
      const policyStartX = -((policyCount - 1) * policySpacing) / 2;
      policies.forEach((policyNode, pIdx) => {
        positions[policyNode.id()] = {
          x: policyStartX + pIdx * policySpacing,
          y: 380
        };
      });

      // 3. Position Roles at Level 4 (Y = 540)
      const roleCount = roles.length;
      const roleSpacing = 110;
      const roleStartX = -((roleCount - 1) * roleSpacing) / 2;
      roles.forEach((roleNode, rIdx) => {
        positions[roleNode.id()] = {
          x: roleStartX + rIdx * roleSpacing,
          y: 540
        };
      });

      // 4. Position Resources (S3, EC2, Lambda, RDS, DynamoDB) at Level 5 (Y = 700)
      const resCount = resources.length;
      const resSpacing = 100;
      const resStartX = -((resCount - 1) * resSpacing) / 2;
      resources.forEach((resNode, resIdx) => {
        positions[resNode.id()] = {
          x: resStartX + resIdx * resSpacing,
          y: 700
        };
      });

      // 5. Position Sensitive Assets / Secrets at Level 6 (Y = 860)
      const secCount = secrets.length;
      const secSpacing = 110;
      const secStartX = -((secCount - 1) * secSpacing) / 2;
      secrets.forEach((secNode, sIdx) => {
        positions[secNode.id()] = {
          x: secStartX + sIdx * secSpacing,
          y: 860
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
    }

    switch (mode) {
      case 'dagre':
        return {
          name: 'dagre',
          directed: true,
          padding: 60,
          rankDir: 'TB',
          nodeSep: 70,
          rankSep: 140,
          edgeSep: 40,
          fit: true,
          spacingFactor: 1.2
        };
      case 'breadthfirst':
        return {
          name: 'breadthfirst',
          directed: true,
          padding: 60,
          circle: true,
          spacingFactor: 1.8,
          fit: true
        };
      case 'cose':
        return {
          name: 'cose',
          padding: 60,
          componentSpacing: 150,
          refresh: 20,
          fit: true,
          nodeRepulsion: () => 15000,
          idealEdgeLength: () => 120,
          edgeElasticity: () => 100,
          nestingFactor: 1.2,
          gravity: 1.5,
          numIter: 1000,
          initialTemp: 1000,
          coolingFactor: 0.99,
          minTemp: 1.0,
          spacingFactor: 1.3
        };
      default:
        return {
          name: 'dagre',
          directed: true,
          padding: 60,
          rankDir: 'TB',
          nodeSep: 70,
          rankSep: 140,
          fit: true
        };
    }
  }, [groupMembership]);

  // Update visibility & pathway highlights on prop changes
  useEffect(() => {
    applyFiltersAndPathways(activeFilters, highlightedNodeIds, searchQuery, securityFilter, collapsedGroups);
  }, [highlightedNodeIds, searchQuery, activeFilters, securityFilter, collapsedGroups, applyFiltersAndPathways]);

  // Initializing Cytoscape Graph
  useEffect(() => {
    if (!containerRef.current) return;

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: JSON.parse(JSON.stringify(elements)),
      minZoom: 0.1,
      maxZoom: 3,
      wheelSensitivity: 0.2,
      style: [
        // Base Node Style
        {
          selector: 'node',
          style: {
            'content': ((ele: cytoscape.NodeSingular) => {
              if (!showLabels) return '';
              const displayLabel = ele.data('displayLabel') || ele.data('label') || ele.id();
              return formatShortLabel(displayLabel, ele.id());
            }) as any,
            'font-family': 'Inter, sans-serif',
            'font-size': '11px',
            'font-weight': 'bold',
            'color': '#F3F4F6',
            'text-valign': 'bottom',
            'text-margin-y': 10,
            'background-color': '#1E293B',
            'border-width': '2px',
            'border-color': '#4B5563',
            'width': '42px',
            'height': '42px',
            'transition-property': 'background-color, border-color, border-width, opacity, width, height',
            'transition-duration': 0.25,
            'text-background-color': '#0F172A',
            'text-background-opacity': 0.8,
            'text-background-padding': '4px',
            'text-background-shape': 'roundrectangle',
            'text-border-width': 1,
            'text-border-color': '#334155',
            'text-border-opacity': 0.6
          }
        },
        // Entity Types Styling
        {
          selector: 'node[type="Group"]',
          style: {
            'background-color': filterColors.Group,
            'border-color': '#818CF8',
            'border-width': '3px',
            'shape': 'round-rectangle',
            'width': '48px',
            'height': '44px'
          }
        },
        {
          selector: 'node[type="User"]',
          style: {
            'background-color': filterColors.User,
            'border-color': '#60A5FA',
            'shape': 'ellipse',
            'width': '38px',
            'height': '38px'
          }
        },
        {
          selector: 'node[type="Policy"]',
          style: {
            'background-color': filterColors.Policy,
            'border-color': '#2DD4BF',
            'shape': 'diamond'
          }
        },
        {
          selector: 'node[type="Role"]',
          style: {
            'background-color': filterColors.Role,
            'border-color': '#A78BFA',
            'shape': 'hexagon'
          }
        },
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
          selector: 'node[type="Secrets"], node[type="Secret"]',
          style: {
            'background-color': filterColors.Secrets,
            'border-color': '#F87171',
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
        // Edge Styling: Clean & Readable
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
            'line-style': 'dashed',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'text-rotation': 'autorotate',
            'text-margin-y': -8,
            'transition-property': 'line-color, target-arrow-color, width, opacity',
            'transition-duration': 0.25
          }
        },
        // Dedicated Clean Vertical Routing for MEMBER_OF Edges
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
        // Activity & Dynamic Edges
        {
          selector: 'edge[label = "ASSUMED_ROLE"], edge[label = "MODIFIED_CONFIG"]',
          style: {
            'line-color': '#F59E0B',
            'target-arrow-color': '#F59E0B',
            'line-style': 'dashed',
            'width': 2.5
          }
        },
        // Highlight & Dim States
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
            'opacity': 0.12
          }
        },
        {
          selector: 'edge.dimmed',
          style: {
            'opacity': 0.08
          }
        },
        {
          selector: 'edge.risky',
          style: {
            'line-color': '#EF4444',
            'target-arrow-color': '#EF4444',
            'width': 2,
            'line-style': 'solid'
          }
        }
      ]
    });

    cyRef.current = cy;

    // Apply layout
    const initialLayout = cy.layout(getLayoutOptions(layoutMode, cy) as any);
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

    // Node click handler with Group & User centered highlighting
    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      const type = (node.data('type') || '').toLowerCase();
      
      if (onNodeSelect) {
        onNodeSelect(node.data());
      }

      cy.elements().addClass('dimmed').removeClass('highlighted');
      node.removeClass('dimmed').addClass('highlighted');

      if (type === 'group') {
        // Group clicked: Highlight group + all members + outgoing policy edges + reachable roles/resources
        const memberIds = groupMembership.groupToUsers[node.id()] || [];
        memberIds.forEach(mId => {
          const mNode = cy.getElementById(mId);
          mNode.removeClass('dimmed').addClass('highlighted');
        });

        // Connected edges and neighborhoods
        node.connectedEdges().removeClass('dimmed').addClass('highlighted');
        const downstreamEles = node.outgoers();
        downstreamEles.removeClass('dimmed').addClass('highlighted');
        downstreamEles.outgoers().removeClass('dimmed').addClass('highlighted');
      } else if (type === 'user') {
        // User clicked: Highlight user + parent groups + downstream policies + roles + resources
        const groupIds = groupMembership.userToGroups[node.id()] || [];
        groupIds.forEach(gId => {
          const gNode = cy.getElementById(gId);
          gNode.removeClass('dimmed').addClass('highlighted');
          gNode.outgoers().removeClass('dimmed').addClass('highlighted');
        });

        node.connectedEdges().removeClass('dimmed').addClass('highlighted');
        const userOutgoers = node.outgoers();
        userOutgoers.removeClass('dimmed').addClass('highlighted');
      } else {
        node.neighborhood().removeClass('dimmed');
        node.connectedEdges().removeClass('dimmed').addClass('highlighted');
      }
    });

    // Double-tap Group node to toggle collapse/expand
    cy.on('dbltap', 'node[type="Group"]', (evt) => {
      const gId = evt.target.id();
      toggleGroupCollapse(gId);
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
        ...(type.toLowerCase() === 'group' ? [`👥 Members: ${(groupMembership.groupToUsers[node.id()] || []).length}`] : []),
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
        cy.elements().removeClass('dimmed').removeClass('highlighted').removeClass('selected');
        setSelectedEdgeData(null);
        if (onNodeSelect) onNodeSelect(null);
        applyFiltersAndPathways(activeFilters, highlightedNodeIds, searchQuery, securityFilter, collapsedGroups);
      }
    });
    
    const handleReset = () => {
      cy.elements().removeClass('dimmed').removeClass('highlighted').removeClass('selected');
      cy.layout(getLayoutOptions(layoutMode, cy) as any).run();
      if (onNodeSelect) onNodeSelect(null);
      setSelectedEdgeData(null);
    };
    
    window.addEventListener('graph:reset', handleReset);

    const handleResize = () => {
      cy.resize();
    };
    window.addEventListener('resize', handleResize);

    applyFiltersAndPathways(activeFilters, highlightedNodeIds, searchQuery, securityFilter, collapsedGroups);

    cy.ready(() => {
      cy.fit(undefined, 60);
    });

    return () => {
      window.removeEventListener('graph:reset', handleReset);
      window.removeEventListener('resize', handleResize);
      cy.destroy();
      cyRef.current = null;
    };
  }, [elements, layoutMode, showLabels, showEdgeLabels, highlightRisky, onNodeSelect, getLayoutOptions, applyFiltersAndPathways, groupMembership, collapsedGroups]);

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
    a.download = 'identity-attack-graph.png';
    a.click();
  };

  const areAllGroupsCollapsed = Object.keys(groupMembership.groupToUsers).length > 0 && 
    Object.keys(groupMembership.groupToUsers).every(gId => collapsedGroups[gId]);

  return (
    <div className="w-full h-full relative bg-[#0B1120] overflow-hidden select-none">
      
      {/* Visual Architectural Layer Track (Left Guide Rail) */}
      {isLayerGuideOpen && (
        <div className="absolute left-4 top-16 z-10 hidden xl:flex flex-col gap-2 p-3 rounded-xl bg-[#0F172A]/85 backdrop-blur-md border border-gray-800 shadow-2xl pointer-events-auto">
          <div className="flex items-center justify-between gap-3 pb-1.5 border-b border-gray-800">
            <span className="text-[10px] uppercase font-bold tracking-wider text-gray-400 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-blue-400" />
              Hierarchy (Top → Bottom)
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
            {LAYER_DEFINITIONS.map(layer => (
              <div key={layer.rank} className="flex items-center gap-2 text-xs">
                <span className="w-2.5 h-2.5 rounded-full shrink-0 shadow-sm" style={{ backgroundColor: layer.color }} />
                <span className="font-mono text-[11px] font-semibold text-gray-300">{layer.title}</span>
                <span className="text-[10px] text-gray-500 ml-auto hidden 2xl:inline">({layer.description})</span>
              </div>
            ))}
          </div>

          {/* Quick Group Collapse / Expand Toggle inside Guide */}
          <div className="pt-2 mt-1 border-t border-gray-800 flex items-center justify-between gap-2">
            <span className="text-[10px] text-gray-400 font-medium">Group Nodes:</span>
            <button
              onClick={() => toggleAllGroupsCollapse(!areAllGroupsCollapsed)}
              className="flex items-center gap-1.5 px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 text-[10px] font-semibold text-blue-400 transition-colors"
            >
              {areAllGroupsCollapsed ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
              <span>{areAllGroupsCollapsed ? 'Expand All' : 'Collapse All'}</span>
            </button>
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
          <button onClick={handleExportImage} className="p-1 hover:bg-gray-700 rounded text-gray-300 transition-colors" title="Export Graph PNG"><Download className="w-4 h-4" /></button>
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
          <div className="bg-[#0F172A]/95 backdrop-blur-md border border-gray-800 rounded-xl p-4 w-52 shadow-2xl">
            <div className="flex justify-between items-center mb-3 border-b border-gray-800 pb-2">
              <h4 className="text-xs font-semibold text-gray-300 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-blue-400" />
                <span>Topology Legend</span>
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
                   <div className="w-4 h-0 border-t border-slate-500 border-dashed" />
                   <span className="text-[9px] text-gray-400 font-mono tracking-wider">Static Access</span>
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
