import type { AttackPath } from '../types';

/**
 * Match the Attack Paths page's grouping key so dashboard totals describe the
 * same consolidated privilege vectors shown to administrators.
 */
export const getConsolidatedAttackPathCount = (paths: AttackPath[] = []): number => {
  const groupKeys = new Set<string>();

  for (const path of paths) {
    if (!path.nodes?.length) continue;

    const sourceNode = path.nodes[0];
    const targetNode = path.nodes.length > 1 ? path.nodes[path.nodes.length - 1] : null;
    const intermediateNodes = path.nodes.length > 2 ? path.nodes.slice(1, -1) : [];
    const isDirectRoleTarget = targetNode?.type === 'Role';
    const sharedChain = isDirectRoleTarget
      ? (path.nodes.length > 2 ? [...intermediateNodes, targetNode] : [targetNode])
      : intermediateNodes;
    const effectiveTarget = isDirectRoleTarget ? null : targetNode;
    const relationships = path.orderedRelationships || [];
    const relationshipKey = relationships.join('=>');
    const chainKey = sharedChain.length > 0
      ? sharedChain.map((node) => `${node.type}:${node.id || node.name}`).join('->')
      : effectiveTarget
        ? `target:${effectiveTarget.type}:${effectiveTarget.id || effectiveTarget.name}`
        : `source:${sourceNode.name}`;

    groupKeys.add(`${chainKey}|rels:${relationshipKey}`);
  }

  return groupKeys.size;
};
