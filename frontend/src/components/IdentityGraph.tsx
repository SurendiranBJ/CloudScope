import { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import { ZoomIn, ZoomOut, Maximize2, RefreshCw, Eye, EyeOff } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { getGraphElements } from '../api/graph';
import { mockGraphElements } from '../data/graph';

interface IdentityGraphProps {
  onNodeSelect?: (nodeData: any) => void;
  highlightedNodeIds?: string[];
  height?: string;
}

export const IdentityGraph: React.FC<IdentityGraphProps> = ({
  onNodeSelect,
  highlightedNodeIds = [],
  height = '500px'
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  const { data } = useQuery({
    queryKey: ['graphElements'],
    queryFn: getGraphElements,
    refetchInterval: 10000
  });

  const elements = data || mockGraphElements;

  // Filter state for nodes
  const [activeFilters, setActiveFilters] = useState({
    User: true,
    Role: true,
    Policy: true,
    S3: true,
    EC2: true,
    Lambda: true,
    Secrets: true
  });

  const filterColors = {
    User: '#3B82F6', // Blue
    Role: '#8B5CF6', // Purple
    Policy: '#14B8A6', // Teal
    S3: '#F59E0B', // Amber
    EC2: '#10B981', // Green
    Lambda: '#EC4899', // Pink
    Secrets: '#EF4444' // Red
  };

  const handleFilterToggle = (type: keyof typeof activeFilters) => {
    setActiveFilters((prev) => {
      const next = { ...prev, [type]: !prev[type] };
      applyFiltersAndPathways(next, highlightedNodeIds);
      return next;
    });
  };

  // Helper function to update node visibility and highlight path
  const applyFiltersAndPathways = (
    filters: typeof activeFilters,
    pathNodeIds: string[]
  ) => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      // 1. Filter nodes based on active checkboxes
      cy.nodes().forEach((node) => {
        const type = node.data('type') as keyof typeof activeFilters;
        if (filters[type] !== false) {
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
    applyFiltersAndPathways(activeFilters, highlightedNodeIds);
  }, [highlightedNodeIds]);

  // Initializing Cytoscape Graph
  useEffect(() => {
    if (!containerRef.current) return;

    // Destroy existing instance if active
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
            'content': 'data(label)',
            'font-family': 'Inter, sans-serif',
            'font-size': '10px',
            'color': '#E5E7EB',
            'text-valign': 'bottom',
            'text-margin-y': 4,
            'background-color': '#111827',
            'border-width': '2px',
            'border-color': '#4B5563',
            'width': '36px',
            'height': '36px',
            'transition-property': 'background-color, border-color, border-width, opacity',
            'transition-duration': 0.25
          }
        },
        // Types styling
        {
          selector: 'node[type="User"]',
          style: {
            'background-color': '#1E3A8A',
            'border-color': filterColors.User,
            'shape': 'round-rectangle'
          }
        },
        {
          selector: 'node[type="Role"]',
          style: {
            'background-color': '#4C1D95',
            'border-color': filterColors.Role,
            'shape': 'hexagon'
          }
        },
        {
          selector: 'node[type="Policy"]',
          style: {
            'background-color': '#115E59',
            'border-color': filterColors.Policy,
            'shape': 'hexagon'
          }
        },
        {
          selector: 'node[type="S3"]',
          style: {
            'background-color': '#78350F',
            'border-color': filterColors.S3,
            'shape': 'barrel'
          }
        },
        {
          selector: 'node[type="EC2"]',
          style: {
            'background-color': '#064E3B',
            'border-color': filterColors.EC2,
            'shape': 'rectangle'
          }
        },
        {
          selector: 'node[type="Lambda"]',
          style: {
            'background-color': '#831843',
            'border-color': filterColors.Lambda,
            'shape': 'diamond'
          }
        },
        {
          selector: 'node[type="Secrets"]',
          style: {
            'background-color': '#7F1D1D',
            'border-color': filterColors.Secrets,
            'shape': 'octagon'
          }
        },
        // Edges styling
        {
          selector: 'edge',
          style: {
            'label': 'data(label)',
            'font-family': 'Inter, sans-serif',
            'font-size': '8px',
            'color': '#9CA3AF',
            'width': 1.5,
            'line-color': '#374151',
            'target-arrow-color': '#4B5563',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'text-rotation': 'autorotate',
            'text-margin-y': -8,
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
            'line-color': '#FBBF24',
            'target-arrow-color': '#FBBF24',
            'width': 3,
            'opacity': 1
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
            'opacity': 0.1
          }
        }
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 40,
        grid: false
      }
    });

    cyRef.current = cy;

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
        applyFiltersAndPathways(activeFilters, highlightedNodeIds);
      }
    });

    // Apply default filters and potential highlighted paths
    applyFiltersAndPathways(activeFilters, highlightedNodeIds);

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [elements]);

  // Controls API
  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() + 0.15);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() - 0.15);
  const handleFit = () => cyRef.current?.fit();
  const handleReset = () => {
    const cy = cyRef.current;
    if (cy) {
      cy.elements().removeClass('dimmed').removeClass('highlighted');
      cy.layout({ name: 'breadthfirst', directed: true, padding: 40 }).run();
      if (onNodeSelect) onNodeSelect(null);
    }
  };

  return (
    <div className="w-full relative bg-enterprise-bg border border-enterprise-border rounded-xl overflow-hidden glow-blue flex flex-col">
      {/* Top Filter and Actions Bar */}
      <div className="p-3 bg-enterprise-card border-b border-enterprise-border flex flex-wrap items-center justify-between gap-3 z-10">
        {/* Node Filters */}
        <div className="flex items-center flex-wrap gap-2.5">
          {Object.keys(activeFilters).map((filterKey) => {
            const key = filterKey as keyof typeof activeFilters;
            const color = filterColors[key];
            const active = activeFilters[key];
            return (
              <button
                key={key}
                onClick={() => handleFilterToggle(key)}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold transition-all duration-150 border ${
                  active
                    ? 'bg-enterprise-bg/60 text-white border-enterprise-border'
                    : 'bg-transparent text-enterprise-subtext border-transparent opacity-55 hover:opacity-100'
                }`}
              >
                <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: color }} />
                <span>{key}s</span>
                {active ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
              </button>
            );
          })}
        </div>

        {/* View Controls */}
        <div className="flex items-center gap-1.5 border-l border-enterprise-border pl-3">
          <button
            onClick={handleZoomIn}
            className="p-1.5 bg-enterprise-bg hover:bg-gray-800 rounded-md border border-enterprise-border text-white transition-colors"
            title="Zoom In"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={handleZoomOut}
            className="p-1.5 bg-enterprise-bg hover:bg-gray-800 rounded-md border border-enterprise-border text-white transition-colors"
            title="Zoom Out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={handleFit}
            className="p-1.5 bg-enterprise-bg hover:bg-gray-800 rounded-md border border-enterprise-border text-white transition-colors"
            title="Fit Screen"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
          <button
            onClick={handleReset}
            className="p-1.5 bg-enterprise-bg hover:bg-gray-800 rounded-md border border-enterprise-border text-white transition-colors"
            title="Reset"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Graph Area */}
      <div ref={containerRef} style={{ height }} className="w-full relative grow" />
    </div>
  );
};
