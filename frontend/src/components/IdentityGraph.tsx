import { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { ZoomIn, ZoomOut, Maximize2, ChevronDown, List, Download } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getGraphElements } from '../api/graph';
import { formatRegion } from '../utils/regionNames';

// Register dagre extension
cytoscape.use(dagre);

interface IdentityGraphProps {
  onNodeSelect?: (nodeData: any) => void;
  highlightedNodeIds?: string[];
  layoutMode?: 'dagre' | 'breadthfirst' | 'cose';
  searchQuery?: string;
  showLabels?: boolean;
  showEdgeLabels?: boolean;
  highlightRisky?: boolean;
}

export const IdentityGraph: React.FC<IdentityGraphProps> = ({
  onNodeSelect,
  highlightedNodeIds = [],
  layoutMode = 'dagre',
  searchQuery = '',
  showLabels = true,
  showEdgeLabels = false,
  highlightRisky = false
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [isLegendOpen, setIsLegendOpen] = useState(false);

  const { data } = useQuery({
    queryKey: ['graphElements'],
    queryFn: getGraphElements,
    refetchInterval: 10000
  });

  const elements = data || [];

  // Filter state for nodes
  const [activeFilters, setActiveFilters] = useState({
    User: true,
    Role: true,
    Policy: true,
    S3: true,
    EC2: true,
    Lambda: true,
    Secrets: true,
    RDS: true,
    DynamoDB: true
  });

  const [tooltip, setTooltip] = useState<{ x: number; y: number; text: string; visible: boolean }>({
    x: 0,
    y: 0,
    text: '',
    visible: false
  });

  const filterColors = {
    User: '#3B82F6', // Blue
    Role: '#8B5CF6', // Purple
    Policy: '#14B8A6', // Teal
    S3: '#F59E0B', // Amber
    EC2: '#10B981', // Green
    Lambda: '#EC4899', // Pink
    Secrets: '#EF4444', // Red
    RDS: '#0EA5E9', // Sky Blue
    DynamoDB: '#8B5CF6' // Purple
  };
  
  const counts = {
    User: 0,
    Role: 0,
    Policy: 0,
    S3: 0,
    EC2: 0,
    Lambda: 0,
    Secrets: 0,
    RDS: 0,
    DynamoDB: 0
  };
  
  const nodes = elements?.filter((e: any) => !e.data.source) || [];
  nodes.forEach((n: any) => {
    if (counts[n.data.type as keyof typeof counts] !== undefined) {
      counts[n.data.type as keyof typeof counts]++;
    }
  });

  const handleFilterToggle = (type: keyof typeof activeFilters) => {
    setActiveFilters((prev) => {
      const next = { ...prev, [type]: !prev[type] };
      applyFiltersAndPathways(next, highlightedNodeIds, searchQuery);
      return next;
    });
  };

  // Helper function to update node visibility and highlight path
  const applyFiltersAndPathways = (
    filters: typeof activeFilters,
    pathNodeIds: string[],
    search: string
  ) => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      // 1. Filter nodes based on active checkboxes and search
      const q = search.toLowerCase();
      cy.nodes().forEach((node) => {
        const type = node.data('type') as keyof typeof activeFilters;
        const label = (node.data('label') || '').toLowerCase();
        
        const passesFilter = filters[type] !== false;
        const passesSearch = q === '' || label.includes(q);
        
        if (passesFilter && passesSearch) {
          node.style('display', 'element');
        } else {
          node.style('display', 'none');
        }
      });

      // 2. Highlight pathway if nodes are defined
      if (pathNodeIds && pathNodeIds.length > 0) {
        cy.elements().addClass('dimmed').removeClass('highlighted');
        
        pathNodeIds.forEach((id) => {
          const node = cy.getElementById(id);
          node.removeClass('dimmed').addClass('highlighted');
        });

        // Highlight connections in path
        for (let i = 0; i < pathNodeIds.length - 1; i++) {
          const source = pathNodeIds[i];
          const target = pathNodeIds[i + 1];
          cy.edges().forEach((edge) => {
            if (edge.source().id() === source && edge.target().id() === target) {
              edge.removeClass('dimmed').addClass('highlighted');
            }
          });
        }
      } else {
        cy.elements().removeClass('dimmed').removeClass('highlighted');
      }
    });
  };

  // Layout mode configurations
  const getLayoutOptions = (mode: 'dagre' | 'breadthfirst' | 'cose') => {
    switch (mode) {
      case 'dagre':
        return {
          name: 'dagre',
          directed: true,
          padding: 50,
          rankDir: 'TB',
          nodeSep: 100, // Horizontal separation between nodes in same rank
          rankSep: 150, // Vertical separation between ranks
          fit: true,
          spacingFactor: 1.2
        };
      case 'breadthfirst':
        return {
          name: 'breadthfirst',
          directed: true,
          padding: 50,
          circle: true,
          spacingFactor: 1.8,
          fit: true
        };
      case 'cose':
        return {
          name: 'cose',
          padding: 50,
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
        return { name: 'grid', padding: 50 };
    }
  };

  // Run path highlight update whenever dependency changes
  useEffect(() => {
    applyFiltersAndPathways(activeFilters, highlightedNodeIds, searchQuery);
  }, [highlightedNodeIds, searchQuery, activeFilters]);

  // Initializing Cytoscape Graph
  useEffect(() => {
    if (!containerRef.current) return;

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: JSON.parse(JSON.stringify(elements)), // deep copy to prevent direct mutation issues
      minZoom: 0.1,
      maxZoom: 3,
      wheelSensitivity: 0.2,
      style: [
        {
          selector: 'node',
          style: {
            'content': ((ele: cytoscape.NodeSingular) => {
              if (!showLabels) return '';
              const label = ele.data('label') || ele.id();
              if (label.length > 22) {
                return label.substring(0, 19) + '...';
              }
              return label;
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
            'width': '40px',
            'height': '40px',
            'transition-property': 'background-color, border-color, border-width, opacity, width, height',
            'transition-duration': 0.25,
            // Semi-transparent background behind text to ensure readability
            'text-background-color': '#0F172A',
            'text-background-opacity': 0.75,
            'text-background-padding': '4px',
            'text-background-shape': 'roundrectangle',
            'text-border-width': 1,
            'text-border-color': '#334155',
            'text-border-opacity': 0.5
          }
        },
        // Types styling
        {
          selector: 'node[type="User"]',
          style: {
            'background-color': filterColors.User,
            'border-color': filterColors.User,
            'shape': 'ellipse'
          }
        },
        {
          selector: 'node[type="Role"]',
          style: {
            'background-color': filterColors.Role,
            'border-color': filterColors.Role,
            'shape': 'hexagon'
          }
        },
        {
          selector: 'node[type="Policy"]',
          style: {
            'background-color': filterColors.Policy,
            'border-color': filterColors.Policy,
            'shape': 'diamond'
          }
        },
        {
          selector: 'node[type="S3"]',
          style: {
            'background-color': filterColors.S3,
            'border-color': filterColors.S3,
            'shape': 'barrel'
          }
        },
        {
          selector: 'node[type="EC2"]',
          style: {
            'background-color': filterColors.EC2,
            'border-color': filterColors.EC2,
            'shape': 'round-rectangle'
          }
        },
        {
          selector: 'node[type="Lambda"]',
          style: {
            'background-color': filterColors.Lambda,
            'border-color': filterColors.Lambda,
            'shape': 'ellipse'
          }
        },
        {
          selector: 'node[type="Secrets"]',
          style: {
            'background-color': filterColors.Secrets,
            'border-color': filterColors.Secrets,
            'shape': 'ellipse'
          }
        },
        {
          selector: 'node[type="RDS"]',
          style: {
            'background-color': filterColors.RDS,
            'border-color': filterColors.RDS,
            'shape': 'database' as cytoscape.Css.NodeShape
          }
        },
        {
          selector: 'node[type="DynamoDB"]',
          style: {
            'background-color': filterColors.DynamoDB,
            'border-color': filterColors.DynamoDB,
            'shape': 'database' as cytoscape.Css.NodeShape
          }
        },
        // Edges styling
        {
          selector: 'edge',
          style: {
            'label': showEdgeLabels ? 'data(label)' : '',
            'font-family': 'Inter, sans-serif',
            'font-size': '10px',
            'color': '#9CA3AF',
            'width': 1.5,
            'line-color': '#475569',
            'line-style': 'dashed',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'text-rotation': 'autorotate',
            'text-margin-y': -10,
            'transition-property': 'line-color, target-arrow-color, width, opacity',
            'transition-duration': 0.25
          }
        },
        {
          selector: 'edge[label = "ASSUMED_ROLE"], edge[label = "MODIFIED_CONFIG"]',
          style: {
            'line-color': '#F59E0B',
            'target-arrow-color': '#F59E0B',
            'line-style': 'dashed',
            'width': 2.5,
            'label': showEdgeLabels ? 'data(label)' : ''
          }
        },
        // Highlight & Dim States
        {
          selector: 'node.highlighted',
          style: {
            'border-width': '4px',
            'border-color': '#FBBF24', // Gold Glow
            'opacity': 1
          }
        },
        {
          selector: 'edge.highlighted',
          style: {
            'line-color': '#EF4444',
            'target-arrow-color': '#EF4444',
            'width': 2.5,
            'opacity': 1,
            'line-style': 'solid'
          }
        },
        {
          selector: 'node.dimmed',
          style: {
            'opacity': 0.2
          }
        },
        {
          selector: 'edge.dimmed',
          style: {
            'opacity': 0.15
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
      ],
      layout: getLayoutOptions(layoutMode) as any
    });

    cyRef.current = cy;

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

      // Highlight clicked node & neighbors locally
      cy.elements().addClass('dimmed').removeClass('highlighted');
      node.removeClass('dimmed').addClass('highlighted');
      node.neighborhood().removeClass('dimmed');
      node.connectedEdges().removeClass('dimmed').addClass('highlighted');
    });

    // Hover tooltip events
    cy.on('mouseover', 'node', (evt) => {
      const node = evt.target;
      const label = node.data('label') || node.id();
      const region = node.data('region');
      const renderedPos = node.renderedPosition();
      const tooltipLines = [label, ...(region ? [`📍 ${formatRegion(region)}`] : [])];
      setTooltip({
        x: renderedPos.x,
        y: renderedPos.y - 30, // Offset above the node
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
        cy.elements().removeClass('dimmed').removeClass('highlighted');
        if (onNodeSelect) onNodeSelect(null);
        applyFiltersAndPathways(activeFilters, highlightedNodeIds, searchQuery);
      }
    });
    
    const handleReset = () => {
      cy.elements().removeClass('dimmed').removeClass('highlighted');
      cy.layout(getLayoutOptions(layoutMode) as any).run();
      if (onNodeSelect) onNodeSelect(null);
    };
    
    window.addEventListener('graph:reset', handleReset);

    // Apply default filters and potential highlighted paths
    applyFiltersAndPathways(activeFilters, highlightedNodeIds, searchQuery);

    // Initial viewport fit
    cy.ready(() => {
      cy.fit(undefined, 50);
    });

    return () => {
      window.removeEventListener('graph:reset', handleReset);
      cy.destroy();
      cyRef.current = null;
    };
  }, [elements, layoutMode, showLabels, showEdgeLabels]);

  // Controls API
  const handleZoomIn = () => {
    const cy = cyRef.current;
    if (!cy) return;
    const currentZoom = cy.zoom();
    const nextZoom = Math.min(3, currentZoom * 1.2);
    cy.zoom({
      level: nextZoom,
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 }
    });
  };

  const handleZoomOut = () => {
    const cy = cyRef.current;
    if (!cy) return;
    const currentZoom = cy.zoom();
    const nextZoom = Math.max(0.1, currentZoom / 1.2);
    cy.zoom({
      level: nextZoom,
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 }
    });
  };

  const handleFit = () => cyRef.current?.fit(undefined, 50);
  const handleExportImage = () => {
    if (!cyRef.current) return;
    const png = cyRef.current.png({ bg: '#0B1120', full: true });
    const a = document.createElement('a');
    a.href = png;
    a.download = 'identity-graph.png';
    a.click();
  };

  return (
    <div className="w-full h-full relative bg-[#0B1120] overflow-hidden">
      
      {/* Top Filter Pills (Floating) */}
      <div className="absolute top-4 left-4 right-4 z-10 flex flex-wrap items-center gap-3">
        {Object.keys(activeFilters).map((filterKey) => {
          const key = filterKey as keyof typeof activeFilters;
          const color = filterColors[key];
          const active = activeFilters[key];
          const count = counts[key] || 0;
          return (
            <button
              key={key}
              onClick={() => handleFilterToggle(key)}
              className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold transition-all duration-150 border ${
                active
                  ? 'bg-[#1E293B] text-white border-gray-700'
                  : 'bg-transparent text-gray-500 border-transparent hover:text-gray-300'
              }`}
            >
              <span className="w-3 h-3 rounded-full shrink-0" style={{ backgroundColor: color }} />
              <span>{key}s</span>
              <span className={`px-1.5 py-0.5 rounded-full text-[10px] ${active ? 'bg-gray-800 text-gray-300' : 'bg-transparent text-gray-600'}`}>{count}</span>
            </button>
          );
        })}
        
        <div className="flex-1" />
        
        {/* Zoom Controls */}
        <div className="flex items-center gap-1.5 bg-[#1E293B]/80 backdrop-blur border border-gray-700 rounded-lg p-1">
          <button onClick={handleZoomIn} className="p-1 hover:bg-gray-700 rounded text-gray-300" title="Zoom In"><ZoomIn className="w-4 h-4" /></button>
          <button onClick={handleZoomOut} className="p-1 hover:bg-gray-700 rounded text-gray-300" title="Zoom Out"><ZoomOut className="w-4 h-4" /></button>
          <button onClick={handleFit} className="p-1 hover:bg-gray-700 rounded text-gray-300" title="Fit to Screen"><Maximize2 className="w-4 h-4" /></button>
          <div className="w-[1px] h-4 bg-gray-700 mx-1"></div>
          <button onClick={handleExportImage} className="p-1 hover:bg-gray-700 rounded text-gray-300" title="Export Graph"><Download className="w-4 h-4" /></button>
        </div>
      </div>

      {/* Legend Overlay */}
      <div className="absolute bottom-6 left-6 z-10">
        {!isLegendOpen ? (
          <button 
            onClick={() => setIsLegendOpen(true)}
            className="flex items-center gap-2 bg-[#0F172A]/90 backdrop-blur-md border border-gray-800 hover:border-gray-600 rounded-lg px-4 py-2 text-xs font-semibold text-gray-300 shadow-xl transition-colors"
          >
            <List className="w-4 h-4" />
            <span>Show Legend</span>
          </button>
        ) : (
          <div className="bg-[#0F172A]/90 backdrop-blur-md border border-gray-800 rounded-lg p-4 w-48 shadow-2xl">
            <div className="flex justify-between items-center mb-3 border-b border-gray-800 pb-2">
              <h4 className="text-xs font-semibold text-gray-300">Legend</h4>
              <button 
                onClick={() => setIsLegendOpen(false)}
                className="text-gray-500 hover:text-gray-300 transition-colors"
              >
                <ChevronDown className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-2">
              {Object.keys(activeFilters).map((filterKey) => {
                 const key = filterKey as keyof typeof activeFilters;
                 const color = filterColors[key];
                 
                 // Define shapes based on the graph config
                 let shapeClass = "w-3 h-3 rounded-full";
                 if (key === 'Role' || key === 'Policy') shapeClass = "w-3 h-3 rotate-45 transform bg-opacity-90";
                 if (key === 'S3') shapeClass = "w-3 h-3 rounded-sm";
                 if (key === 'EC2') shapeClass = "w-3.5 h-2.5 rounded-sm";
                 
                 return (
                   <div key={key} className="flex items-center gap-2">
                     <div className={`${shapeClass}`} style={{ backgroundColor: color }} />
                     <span className="text-[10px] text-gray-400">{key}</span>
                   </div>
                 )
              })}
              
              <div className="pt-2 mt-2 border-t border-gray-800 space-y-1.5">
                <div className="flex items-center gap-2">
                   <div className="w-4 h-0 border-t border-slate-500 border-dashed" />
                   <span className="text-[9px] text-gray-400 font-mono tracking-wider">Static Relationship</span>
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

      {/* Tooltip Overlay */}
      {tooltip.visible && (
        <div
          className="absolute z-50 pointer-events-none bg-[#0F172A]/95 border border-gray-700 text-gray-200 text-xs px-3 py-1.5 rounded-lg shadow-2xl backdrop-blur-md transition-opacity duration-150 transform -translate-x-1/2 -translate-y-full flex flex-col gap-0.5"
          style={{
            left: `${tooltip.x}px`,
            top: `${tooltip.y}px`
          }}
        >
          {tooltip.text.split('\n').map((line, i) => (
            <span
              key={i}
              className={i === 0 ? 'font-semibold whitespace-nowrap' : 'text-[10px] text-gray-400 whitespace-nowrap'}
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
