import { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { ZoomIn, ZoomOut, Maximize2, ChevronDown, List, Download, Layers, ShieldAlert, Sparkles } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getGraphElements } from '../api/graph';
import { formatRegion } from '../utils/regionNames';

// Register dagre extension
cytoscape.use(dagre);

export interface IdentityGraphProps {
  onNodeSelect?: (nodeData: any) => void;
  highlightedNodeIds?: string[];
  layoutMode?: 'vertical' | 'dagre' | 'breadthfirst' | 'cose';
  searchQuery?: string;
  showLabels?: boolean;
  showEdgeLabels?: boolean;
  highlightRisky?: boolean;
  securityFilter?: 'all' | 'critical' | 'high' | 'medium' | 'low' | 'attack_paths_only';
}

export const getNodeRank = (type?: string): number => {
  const t = (type || '').toLowerCase();
  if (t === 'user') return 0; // LAYER 1: USERS
  if (t === 'group') return 1; // LAYER 2: GROUPS
  if (t === 'policy') return 2; // LAYER 3: POLICIES
  if (t === 'role') return 3; // LAYER 4: ROLES
  if (t === 's3' || t === 'ec2' || t === 'lambda' || t === 'rds' || t === 'dynamodb' || t === 'resource') return 4; // LAYER 5: AWS RESOURCES
  if (t === 'secrets' || t === 'secret') return 5; // LAYER 6: SENSITIVE ASSETS
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
  if (clean.length > 20) {
    return clean.substring(0, 18) + '...';
  }
  return clean;
};

const LAYER_DEFINITIONS = [
  { rank: 0, title: '1. USERS', color: '#3B82F6', description: 'IAM Identities & Humans' },
  { rank: 1, title: '2. GROUPS', color: '#6366F1', description: 'IAM Groups' },
  { rank: 2, title: '3. POLICIES', color: '#14B8A6', description: 'Permissions & AST Rules' },
  { rank: 3, title: '4. ROLES', color: '#8B5CF6', description: 'Privileged IAM Roles' },
  { rank: 4, title: '5. RESOURCES', color: '#10B981', description: 'S3, EC2, Lambda, RDS, DynamoDB' },
  { rank: 5, title: '6. SENSITIVE ASSETS', color: '#EF4444', description: 'Secrets & High-Value Targets' }
];

export const IdentityGraph: React.FC<IdentityGraphProps> = ({
  onNodeSelect,
  highlightedNodeIds = [],
  layoutMode = 'vertical',
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
      applyFiltersAndPathways(next, highlightedNodeIds, searchQuery, securityFilter);
      return next;
    });
  };

  // Helper function to update node visibility, filters, and attack pathways
  const applyFiltersAndPathways = useCallback((
    filters: typeof activeFilters,
    pathNodeIds: string[],
    search: string,
    secFilter: typeof securityFilter
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

      // 4. Highlight attack pathway if active
      if (pathNodeIds && pathNodeIds.length > 0) {
        cy.elements().addClass('dimmed').removeClass('highlighted');

        pathNodeIds.forEach((id) => {
          const node = cy.getElementById(id);
          if (node.length > 0) {
            node.removeClass('dimmed').addClass('highlighted');
          }
        });

        // Highlight sequential edges along path
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

      // If specific search matched, focus on it
      if (q !== '' && hasSearchMatch) {
        const matches = cy.nodes('.search-match');
        if (matches.length > 0) {
          cy.animate({
            center: { eles: matches },
            zoom: Math.min(1.5, cy.zoom() * 1.1),
            duration: 350
          });
        }
      }
    });
  }, []);

  // Compute Layout Options with Strict Vertical Top-To-Bottom Flow
  const getLayoutOptions = useCallback((mode: string, cyInstance?: cytoscape.Core) => {
    const activeCy = cyInstance || cyRef.current;
    
    if (mode === 'vertical' && activeCy) {
      // STRICT 6-LAYER TOP-TO-BOTTOM PRESET POSITIONS
      const visibleNodes = activeCy.nodes().filter(n => n.style('display') !== 'none');
      const layers: cytoscape.NodeSingular[][] = [[], [], [], [], [], []];

      visibleNodes.forEach(node => {
        const type = node.data('type') || '';
        const rank = getNodeRank(type);
        layers[rank].push(node);
      });

      const layerY = [120, 280, 440, 600, 760, 920];
      const nodeSep = 95;
      const positions: Record<string, { x: number; y: number }> = {};

      layers.forEach((layerNodes, rank) => {
        const count = layerNodes.length;
        const totalWidth = (count - 1) * nodeSep;
        const startX = -totalWidth / 2;

        layerNodes.forEach((node, i) => {
          positions[node.id()] = {
            x: startX + (i * nodeSep),
            y: layerY[rank]
          };
        });
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
      case 'vertical':
        return {
          name: 'dagre',
          directed: true,
          padding: 60,
          rankDir: 'TB', // Strict Top to Bottom
          nodeSep: 60,   // Horizontal spacing
          rankSep: 150,  // Vertical layer spacing
          edgeSep: 40,   // Edge separation
          fit: true,
          spacingFactor: 1.25
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
          nodeSep: 60,
          rankSep: 150,
          edgeSep: 40,
          fit: true
        };
    }
  }, []);

  // Update visibility & pathway highlights on prop changes
  useEffect(() => {
    applyFiltersAndPathways(activeFilters, highlightedNodeIds, searchQuery, securityFilter);
  }, [highlightedNodeIds, searchQuery, activeFilters, securityFilter, applyFiltersAndPathways]);

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
              return formatShortLabel(ele.data('label'), ele.id());
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
        // Layered Entity Types Styling
        {
          selector: 'node[type="User"]',
          style: {
            'background-color': filterColors.User,
            'border-color': '#60A5FA',
            'shape': 'ellipse'
          }
        },
        {
          selector: 'node[type="Group"]',
          style: {
            'background-color': filterColors.Group,
            'border-color': '#818CF8',
            'shape': 'round-rectangle'
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
            'opacity': 0.15
          }
        },
        {
          selector: 'edge.dimmed',
          style: {
            'opacity': 0.1
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

    // Node click handler
    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      if (onNodeSelect) {
        onNodeSelect(node.data());
      }

      cy.elements().addClass('dimmed').removeClass('highlighted');
      node.removeClass('dimmed').addClass('highlighted');
      node.neighborhood().removeClass('dimmed');
      node.connectedEdges().removeClass('dimmed').addClass('highlighted');
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
      const type = node.data('type');
      const arn = node.data('arn');
      const region = node.data('region');
      const renderedPos = node.renderedPosition();
      
      const tooltipLines = [
        `${label} (${type || 'Resource'})`,
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
        applyFiltersAndPathways(activeFilters, highlightedNodeIds, searchQuery, securityFilter);
      }
    });
    
    const handleReset = () => {
      cy.elements().removeClass('dimmed').removeClass('highlighted').removeClass('selected');
      cy.layout(getLayoutOptions(layoutMode, cy) as any).run();
      if (onNodeSelect) onNodeSelect(null);
      setSelectedEdgeData(null);
    };
    
    window.addEventListener('graph:reset', handleReset);

    // Resize handler
    const handleResize = () => {
      cy.resize();
    };
    window.addEventListener('resize', handleResize);

    applyFiltersAndPathways(activeFilters, highlightedNodeIds, searchQuery, securityFilter);

    cy.ready(() => {
      cy.fit(undefined, 60);
    });

    return () => {
      window.removeEventListener('graph:reset', handleReset);
      window.removeEventListener('resize', handleResize);
      cy.destroy();
      cyRef.current = null;
    };
  }, [elements, layoutMode, showLabels, showEdgeLabels, highlightRisky, onNodeSelect, getLayoutOptions, applyFiltersAndPathways]);

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
