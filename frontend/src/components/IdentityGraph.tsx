import { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { ZoomIn, ZoomOut, Maximize2, ChevronUp, ChevronDown, List, Download } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getGraphElements } from '../api/graph';
import { mockGraphElements } from '../data/graph';

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
  showEdgeLabels = true,
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
      style: [
        {
          selector: 'node',
          style: {
            'content': showLabels ? 'data(label)' : '',
            'font-family': 'Inter, sans-serif',
            'font-size': '12px',
            'font-weight': 'bold',
            'color': '#E5E7EB',
            'text-valign': 'bottom',
            'text-margin-y': 8,
            'background-color': '#1E293B',
            'border-width': '2px',
            'border-color': '#4B5563',
            'width': '40px',
            'height': '40px',
            'transition-property': 'background-color, border-color, border-width, opacity, width, height',
            'transition-duration': 0.25
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
      layout: {
        name: layoutMode,
        directed: true,
        padding: 60,
        grid: false,
        spacingFactor: 1.5,
        rankDir: 'TB'
      } as any
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
      cy.layout({ name: layoutMode, directed: true, padding: 60, spacingFactor: 1.5, rankDir: 'TB' } as any).run();
      if (onNodeSelect) onNodeSelect(null);
    };
    
    window.addEventListener('graph:reset', handleReset);

    // Apply default filters and potential highlighted paths
    applyFiltersAndPathways(activeFilters, highlightedNodeIds, searchQuery);

    return () => {
      window.removeEventListener('graph:reset', handleReset);
      cy.destroy();
      cyRef.current = null;
    };
  }, [elements, layoutMode, showLabels, showEdgeLabels]);

  // Controls API
  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() + 0.15);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() - 0.15);
  const handleFit = () => cyRef.current?.fit();
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
                   <div className="w-4 h-0 border-t border-gray-500 border-dashed" />
                   <span className="text-[9px] text-gray-500 font-mono tracking-wider">BELONGS_TO</span>
                </div>
                <div className="flex items-center gap-2">
                   <div className="w-4 h-0 border-t border-gray-500 border-dashed" />
                   <span className="text-[9px] text-gray-500 font-mono tracking-wider">ASSUMES</span>
                </div>
                <div className="flex items-center gap-2">
                   <div className="w-4 h-0 border-t border-gray-500 border-dashed" />
                   <span className="text-[9px] text-gray-500 font-mono tracking-wider">HAS_POLICY</span>
                </div>
                <div className="flex items-center gap-2">
                   <div className="w-4 h-0 border-t-2 border-red-500 border-solid" />
                   <span className="text-[9px] text-gray-500 font-mono tracking-wider">RISK PATH</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Graph Area */}
      <div ref={containerRef} className="w-full h-full" />
    </div>
  );
};
