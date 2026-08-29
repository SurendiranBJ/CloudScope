"""
CloudScope Deterministic Attack Path Engine.

Discovers, evaluates, and scores lateral movement attack paths traversing
identities, IAM policies, AssumeRole trust boundaries, and cloud resources.
Computes deterministic path scores, classifications, and exact relationship chains.
"""

import logging
import networkx as nx
from typing import List, Dict, Any
from app.services.risk.risk_constants import get_severity_label

logger = logging.getLogger("scanner")


def classify_path_type(path: List[str], G: nx.DiGraph, ordered_rels: List[str]) -> str:
    """Classify the primary security vector type for this attack path."""
    target_node = G.nodes[path[-1]]
    target_type = target_node.get('type', '')
    
    if 'CAN_ASSUME' in ordered_rels or 'ASSUMED_ROLE' in ordered_rels:
        if target_type == 'Role':
            return "privilege_escalation"
        return "lateral_movement"
    
    if target_type in ['Secrets', 'Secret', 'RDS']:
        return "sensitive_resource_access"
        
    if target_type == 'S3':
        target_details = target_node.get('details', {})
        if not target_details.get('public_blocked', True):
            return "exposed_resource_path"
        return "sensitive_resource_access"

    return "excessive_permission"


def calculate_path_risk_score(path: List[str], G: nx.DiGraph, ordered_rels: List[str]) -> Dict[str, Any]:
    """Calculate deterministic path risk score (0-100), severity, and evidence confidence."""
    source_attr = G.nodes[path[0]]
    target_attr = G.nodes[path[-1]]

    source_risk = source_attr.get('riskScore', 0)
    target_risk = target_attr.get('riskScore', 0)

    # 1. Source Identity Baseline (weighted 25%)
    # 2. Intermediate Privilege Escalation Evidence (weighted 35%)
    # 3. Target Resource Sensitivity (weighted 40%)
    
    escalation_bonus = 0
    if 'CAN_ASSUME' in ordered_rels:
        escalation_bonus += 25
    if 'ASSUMED_ROLE' in ordered_rels:
        escalation_bonus += 30  # Active observed event
    if 'ALLOWS' in ordered_rels:
        escalation_bonus += 15

    target_sensitivity_bonus = 0
    t_type = target_attr.get('type', '')
    if t_type in ['Secrets', 'Secret']:
        target_sensitivity_bonus += 35
    elif t_type == 'RDS':
        target_sensitivity_bonus += 30
    elif t_type == 'S3':
        target_sensitivity_bonus += 25
    elif t_type == 'Role' and target_risk >= 60:
        target_sensitivity_bonus += 30

    raw_score = (
        (source_risk * 0.25) +
        (target_risk * 0.35) +
        escalation_bonus +
        target_sensitivity_bonus
    )

    path_score = min(100, max(15, int(raw_score)))
    severity = get_severity_label(path_score)

    # Risk confidence based on evidence completeness (whether policies & trust are verified)
    confidence = 95 if len(ordered_rels) > 0 else 80

    return {
        "score": path_score,
        "severity": severity,
        "confidence": confidence
    }


def find_attack_paths(G: nx.DiGraph, max_hops: int = 6) -> List[Dict[str, Any]]:
    """Discover deterministic attack paths traversing identities, policies, and cloud resources."""
    paths_list = []
    if not G or G.number_of_nodes() == 0:
        return paths_list

    # Starting points (Users and Compute)
    starts = [n for n, attr in G.nodes(data=True) if attr.get('type') in ['User', 'EC2']]

    # Target points (Sensitive data stores and high-privilege roles)
    targets = [
        n for n, attr in G.nodes(data=True)
        if attr.get('type') in ['S3', 'Secrets', 'Secret', 'RDS', 'DynamoDB']
        or (attr.get('type') == 'Role' and attr.get('riskScore', 0) >= 40)
    ]

    idx = 1
    for source in starts:
        for target in targets:
            if source == target:
                continue

            try:
                if nx.has_path(G, source, target):
                    path = nx.shortest_path(G, source, target)

                    if len(path) - 1 > max_hops:
                        continue

                    source_attr = G.nodes[source]
                    target_attr = G.nodes[target]

                    # Extract ordered nodes metadata
                    nodes_details = []
                    for node_id in path:
                        attr = G.nodes[node_id]
                        nodes_details.append({
                            "id": node_id,
                            "name": attr.get('label', node_id),
                            "type": attr.get('type', 'Resource'),
                            "arn": attr.get('arn', ''),
                            "riskScore": attr.get('riskScore', 0)
                        })

                    # Extract ordered relationships along the path from graph edges
                    ordered_relationships = []
                    for i in range(len(path) - 1):
                        u, v = path[i], path[i + 1]
                        edge_data = G.get_edge_data(u, v, default={})
                        rel_label = edge_data.get('label') or edge_data.get('type') or 'CONNECTED_TO'
                        ordered_relationships.append(rel_label)

                    # Compute deterministic path score & severity
                    path_eval = calculate_path_risk_score(path, G, ordered_relationships)
                    path_type = classify_path_type(path, G, ordered_relationships)

                    # Reachable count from source
                    reachable_count = len(nx.descendants(G, source))
                    if reachable_count >= 6:
                        blast_radius_desc = f"High ({reachable_count} reachable assets)"
                    elif reachable_count >= 2:
                        blast_radius_desc = f"Medium ({reachable_count} reachable assets)"
                    else:
                        blast_radius_desc = f"Low ({reachable_count} reachable asset{'s' if reachable_count != 1 else ''})"

                    # MITRE ATT&CK mapping
                    mitre = []
                    path_types = [G.nodes[nid].get('type', '') for nid in path]
                    if 'User' in path_types:
                        mitre.append("T1078 - Valid Accounts")
                    if 'CAN_ASSUME' in ordered_relationships or 'ASSUMED_ROLE' in ordered_relationships:
                        mitre.append("T1548.003 - AssumeRole Abuse")
                    if 'S3' in path_types:
                        mitre.append("T1530 - Data from Cloud Storage")
                    if 'Secrets' in path_types or 'Secret' in path_types:
                        mitre.append("T1552.004 - Credentials in Cloud Secrets")
                    if 'RDS' in path_types or 'DynamoDB' in path_types:
                        mitre.append("T1530 - Cloud Database Access")
                    if 'EC2' in path_types:
                        mitre.append("T1078.004 - Cloud Administration via Instance Profile")

                    source_label = source_attr.get('label', source)
                    target_label = target_attr.get('label', target)
                    hop_count = len(path) - 1

                    rel_chain = " → ".join(
                        f"[{ordered_relationships[i]}] {G.nodes[path[i+1]].get('label', path[i+1])}"
                        for i in range(len(ordered_relationships))
                    )
                    description = (
                        f"Identity '{source_label}' reaches {target_attr.get('type', 'resource')} '{target_label}' "
                        f"via {hop_count} hop(s): {source_label} → {rel_chain}."
                    )

                    recommendations = []
                    if 'CAN_ASSUME' in ordered_relationships:
                        recommendations.append("Enforce MFA conditions and IP restrictions in AssumeRole trust policies")
                    if 'ALLOWS' in ordered_relationships:
                        recommendations.append("Replace wildcard actions/resources with least-privilege scoping")
                    if target_attr.get('type') == 'S3':
                        recommendations.append(f"Enable S3 Block Public Access and bucket encryption on '{target_label}'")
                    if target_attr.get('type') in ['Secrets', 'Secret']:
                        recommendations.append(f"Enable automatic secret rotation and restrict access to '{target_label}'")

                    recommendation = ". ".join(recommendations) + "." if recommendations else "Review IAM permissions and restrict access paths."

                    paths_list.append({
                        "id": f"path-{idx:03d}",
                        "name": f"Attack Path {idx}: {source_label} → {target_label}",
                        "pathType": path_type,
                        "nodes": nodes_details,
                        "orderedRelationships": ordered_relationships,
                        "hopCount": hop_count,
                        "riskScore": path_eval["score"],
                        "severity": path_eval["severity"],
                        "confidence": path_eval["confidence"],
                        "blastRadius": blast_radius_desc,
                        "mitreTechniques": mitre,
                        "description": description,
                        "recommendation": recommendation
                    })
                    idx += 1
            except Exception as e:
                logger.debug(f"Path search exception for {source} -> {target}: {e}")
                continue

    return paths_list
