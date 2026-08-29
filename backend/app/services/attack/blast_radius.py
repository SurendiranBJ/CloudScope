import logging
import networkx as nx
from typing import Dict, Any, List

logger = logging.getLogger("scanner")


def calculate_blast_radius(G: nx.DiGraph, node_id: str) -> Dict[str, Any]:
    """Calculate the blast radius and reachability of a compromised node in the graph."""
    reachable_nodes: List[str] = []
    stats = {
        "User": 0,
        "Role": 0,
        "Group": 0,
        "S3": 0,
        "EC2": 0,
        "Lambda": 0,
        "Secrets": 0,
        "RDS": 0,
        "DynamoDB": 0,
        "Policy": 0
    }
    critical_assets: List[Dict[str, Any]] = []
    max_depth = 0

    try:
        if G.has_node(node_id):
            descendants = nx.descendants(G, node_id)
            reachable_nodes = list(descendants)

            for nid in reachable_nodes:
                node_data = G.nodes[nid]
                ntype = node_data.get('type', 'Resource')
                if ntype in stats:
                    stats[ntype] += 1
                else:
                    stats[ntype] = 1

                # Calculate depth from source to this reachable node
                try:
                    depth = nx.shortest_path_length(G, node_id, nid)
                    if depth > max_depth:
                        max_depth = depth
                except Exception:
                    pass

                # Flag critical data stores & roles
                if ntype in ['Secrets', 'RDS', 'S3'] or (ntype == 'Role' and node_data.get('riskScore', 0) >= 50):
                    critical_assets.append({
                        "id": nid,
                        "name": node_data.get('label', nid),
                        "type": ntype,
                        "riskScore": node_data.get('riskScore', 0)
                    })

        total_reachable = len(reachable_nodes)
        critical_count = len(critical_assets)
        score = min(100, (total_reachable * 10) + (critical_count * 15))

        return {
            "node_id": node_id,
            "blast_score": score,
            "reachable_count": total_reachable,
            "max_depth": max_depth,
            "critical_assets_count": critical_count,
            "critical_assets": critical_assets,
            "reachable_nodes": reachable_nodes,
            "breakdown": stats
        }
    except Exception as e:
        logger.error(f"Failed to calculate blast radius for {node_id}: {e}")
        return {
            "node_id": node_id,
            "blast_score": 0,
            "reachable_count": 0,
            "max_depth": 0,
            "critical_assets_count": 0,
            "critical_assets": [],
            "reachable_nodes": [],
            "breakdown": stats
        }
