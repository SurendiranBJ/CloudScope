"""
CloudScope Graph Diff Engine.

Compares two NetworkX directed graphs (current vs desired) and produces
a structured diff: added nodes, removed nodes, added edges, removed edges.

Neither source graph is mutated.
"""

import logging
import networkx as nx
from typing import Dict, Any, List, Tuple, Set

logger = logging.getLogger("scanner")


def compute_graph_diff(
    G_current: nx.DiGraph,
    G_desired: nx.DiGraph,
) -> Dict[str, Any]:
    """Compare current and desired graphs; return a structured diff dict.

    Returns:
        {
            "added_nodes":   [...],   # nodes in desired not in current
            "removed_nodes": [...],   # nodes in current not in desired
            "added_edges":   [...],   # edges in desired not in current
            "removed_edges": [...],   # edges in current not in desired
            "unchanged_node_count": int,
            "unchanged_edge_count": int,
        }
    Each node entry: {"id": str, "label": str, "type": str}
    Each edge entry: {"source": str, "target": str, "label": str}
    """
    current_nodes: Set[str] = set(G_current.nodes())
    desired_nodes: Set[str] = set(G_desired.nodes())

    added_node_ids = desired_nodes - current_nodes
    removed_node_ids = current_nodes - desired_nodes
    unchanged_node_ids = current_nodes & desired_nodes

    def node_entry(G: nx.DiGraph, nid: str) -> dict:
        attr = G.nodes[nid]
        return {
            "id": nid,
            "label": attr.get("label", nid),
            "type": attr.get("type", "Resource"),
        }

    added_nodes = [node_entry(G_desired, nid) for nid in added_node_ids]
    removed_nodes = [node_entry(G_current, nid) for nid in removed_node_ids]

    # Edge comparison — use (source, target, label) as edge identity
    current_edges: Set[Tuple[str, str, str]] = {
        (s, t, d.get("label", ""))
        for s, t, d in G_current.edges(data=True)
    }
    desired_edges: Set[Tuple[str, str, str]] = {
        (s, t, d.get("label", ""))
        for s, t, d in G_desired.edges(data=True)
    }

    added_edge_tuples = desired_edges - current_edges
    removed_edge_tuples = current_edges - desired_edges
    unchanged_edge_count = len(current_edges & desired_edges)

    def edge_entry(tup: tuple) -> dict:
        return {"source": tup[0], "target": tup[1], "label": tup[2]}

    added_edges = [edge_entry(t) for t in added_edge_tuples]
    removed_edges = [edge_entry(t) for t in removed_edge_tuples]

    logger.info(
        f"Graph diff: +{len(added_nodes)} nodes, -{len(removed_nodes)} nodes, "
        f"+{len(added_edges)} edges, -{len(removed_edges)} edges"
    )

    return {
        "added_nodes": added_nodes,
        "removed_nodes": removed_nodes,
        "added_edges": added_edges,
        "removed_edges": removed_edges,
        "unchanged_node_count": len(unchanged_node_ids),
        "unchanged_edge_count": unchanged_edge_count,
    }


def compare_attack_paths(
    current_paths: List[Dict[str, Any]],
    desired_paths: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compare current and desired attack path lists.

    Uses (source, destination) as the path identity key.

    Returns:
        {
            "new_paths":       [...],  # in desired, not in current
            "removed_paths":   [...],  # in current, not in desired
            "unchanged_paths": [...],  # in both with same source+dest
            "changed_paths":   [...],  # in both but risk score changed
        }
    """
    def path_key(p: dict) -> str:
        return f"{p.get('source', '')}|{p.get('destination', '')}"

    current_map: Dict[str, Dict[str, Any]] = {path_key(p): p for p in current_paths}
    desired_map: Dict[str, Dict[str, Any]] = {path_key(p): p for p in desired_paths}

    current_keys = set(current_map.keys())
    desired_keys = set(desired_map.keys())

    new_keys = desired_keys - current_keys
    removed_keys = current_keys - desired_keys
    common_keys = current_keys & desired_keys

    new_paths = [desired_map[k] for k in new_keys]
    removed_paths = [current_map[k] for k in removed_keys]
    unchanged_paths = []
    changed_paths = []

    for k in common_keys:
        cp = current_map[k]
        dp = desired_map[k]
        if cp.get("riskScore", 0) != dp.get("riskScore", 0) or cp.get("severity") != dp.get("severity"):
            changed_paths.append({
                "current": cp,
                "desired": dp,
                "risk_delta": dp.get("riskScore", 0) - cp.get("riskScore", 0),
            })
        else:
            unchanged_paths.append(cp)

    logger.info(
        f"Attack path diff: +{len(new_paths)} new, -{len(removed_paths)} removed, "
        f"{len(unchanged_paths)} unchanged, {len(changed_paths)} changed"
    )

    return {
        "new_paths": new_paths,
        "removed_paths": removed_paths,
        "unchanged_paths": unchanged_paths,
        "changed_paths": changed_paths,
    }


def compare_reachable_resources(
    current_reach: Dict[str, set],
    desired_reach: Dict[str, set],
) -> Dict[str, Any]:
    """Compare reachable resource sets for identities.

    Args:
        current_reach: { "User:Alice": {"aws:s3:bucket-a", ...} }
        desired_reach: same structure for desired state

    Returns dict with new_reachable, removed_reachable lists.
    """
    all_identities = set(current_reach) | set(desired_reach)
    new_reachable: List[Dict[str, Any]] = []
    removed_reachable: List[Dict[str, Any]] = []

    for identity_key in all_identities:
        c_set = current_reach.get(identity_key, set())
        d_set = desired_reach.get(identity_key, set())
        added = d_set - c_set
        removed = c_set - d_set
        itype, iname = identity_key.split(":", 1) if ":" in identity_key else ("Unknown", identity_key)
        for res_id in added:
            new_reachable.append({"identity": iname, "identity_type": itype, "resource_id": res_id})
        for res_id in removed:
            removed_reachable.append({"identity": iname, "identity_type": itype, "resource_id": res_id})

    return {
        "new_reachable": new_reachable,
        "removed_reachable": removed_reachable,
    }
