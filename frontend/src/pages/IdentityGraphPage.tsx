import { useState } from 'react';
import { IdentityGraph } from '../components/IdentityGraph';
import { NodeDetailsPanel } from '../components/NodeDetailsPanel';
import { Network, Info } from 'lucide-react';

export const IdentityGraphPage: React.FC = () => {
  const [selectedNode, setSelectedNode] = useState<any>(null);

  return (
    <div className="flex-1 flex overflow-hidden bg-enterprise-bg select-none">
      <div className="flex-1 flex flex-col p-6 space-y-4 min-w-0">
        {/* Header */}
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              <Network className="w-6 h-6 text-enterprise-accent" />
              <span>Identity Graph Explorer</span>
            </h1>
            <p className="text-xs text-enterprise-subtext mt-1">
              Analyze relationships, trust policies, and lateral attack paths across all cloud services.
            </p>
          </div>
          <div className="hidden sm:flex items-center gap-2 text-xs text-enterprise-subtext bg-enterprise-card border border-enterprise-border px-3 py-2 rounded-lg">
            <Info className="w-4 h-4 text-enterprise-accent" />
            <span>Click on nodes to view policy definitions & permissions details.</span>
          </div>
        </div>

        {/* Graph Workspace */}
        <div className="flex-1 min-h-0 relative">
          <IdentityGraph onNodeSelect={setSelectedNode} height="100%" />
        </div>
      </div>

      {/* Details Slide-out */}
      {selectedNode && (
        <NodeDetailsPanel nodeData={selectedNode} onClose={() => setSelectedNode(null)} />
      )}
    </div>
  );
};
