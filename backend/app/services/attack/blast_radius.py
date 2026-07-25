import logging
import networkx as nx
from typing import Dict, Any, List

logger = logging.getLogger("scanner")

def calculate_blast_radius(G: nx.DiGraph, node_id: str) -> Dict[str, Any]:
    reachable_nodes: List[str] = []
    stats = {
        "User": 0,
        "Role": 0,
        "S3": 0,
        "EC2": 0,
        "Lambda": 0,
        "Secrets": 0,
        "Policy": 0
    }
    
    try:
        if G.has_node(node_id):
            # nx.descendants finds all reachable nodes in a directed graph
            descendants = nx.descendants(G, node_id)
            reachable_nodes = list(descendants)
            
            for nid in reachable_nodes:
                ntype = G.nodes[nid].get('type')
                if ntype in stats:
                    stats[ntype] += 1
                    
        total_reachable = len(reachable_nodes)
        score = min(100, total_reachable * 15)
        
        return {
            "node_id": node_id,
            "blast_score": score,
            "reachable_count": total_reachable,
            "reachable_nodes": reachable_nodes,
            "breakdown": stats
        }
    except Exception as e:
        logger.error(f"Failed to calculate blast radius for {node_id}: {str(e)}")
        return {
            "node_id": node_id,
            "blast_score": 0,
            "reachable_count": 0,
            "reachable_nodes": [],
            "breakdown": stats
        }
