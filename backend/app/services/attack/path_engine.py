import logging
import networkx as nx
from typing import List, Dict, Any

logger = logging.getLogger("scanner")


def find_attack_paths(G: nx.DiGraph, max_hops: int = 6) -> List[Dict[str, Any]]:
    """Discover deterministic attack paths traversing identities, policies, and cloud resources.

    Includes ordered nodes, ordered relationships, hop counts, risk scores,
    severities, explanations, and MITRE ATT&CK mappings.
    """
    paths_list = []

    # Starting points (Entry points / Identities / Compute)
    starts = [n for n, attr in G.nodes(data=True) if attr.get('type') in ['User', 'EC2']]

    # Target points (Sensitive data stores & high-privilege roles)
    targets = [
        n for n, attr in G.nodes(data=True)
        if attr.get('type') in ['S3', 'Secrets', 'RDS', 'DynamoDB']
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

                    # Enforce sensible max hops to avoid uninformative long walks
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

                    # Extract ordered relationships along the path
                    ordered_relationships = []
                    for i in range(len(path) - 1):
                        u, v = path[i], path[i + 1]
                        edge_data = G.get_edge_data(u, v, default={})
                        rel_label = edge_data.get('label', 'CONNECTED_TO')
                        ordered_relationships.append(rel_label)

                    # Calculate risk and likelihood metrics
                    risk_scores = [G.nodes[nid].get('riskScore', 0) for nid in path]
                    max_risk = max(risk_scores) if risk_scores else 0
                    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
                    total_risk = max(max_risk, int(avg_risk * 1.2))
                    likelihood = min(95, max(20, int(total_risk * 1.05)))

                    # Dynamic blast radius
                    try:
                        reachable_count = len(nx.descendants(G, source))
                        if reachable_count >= 6:
                            blast_radius = f"High ({reachable_count} reachable assets)"
                        elif reachable_count >= 2:
                            blast_radius = f"Medium ({reachable_count} reachable assets)"
                        else:
                            blast_radius = f"Low ({reachable_count} reachable asset{'s' if reachable_count != 1 else ''})"
                    except Exception:
                        blast_radius = "Unknown"

                    # Severity classification
                    if total_risk >= 75 or target_attr.get('type') == 'Secrets':
                        severity = "critical"
                    elif total_risk >= 50:
                        severity = "high"
                    elif total_risk >= 25:
                        severity = "medium"
                    else:
                        severity = "low"

                    # MITRE ATT&CK technique mapping
                    mitre = []
                    path_types = [G.nodes[nid].get('type', '') for nid in path]
                    if 'User' in path_types:
                        mitre.append("T1078 - Valid Accounts")
                    if 'CAN_ASSUME' in ordered_relationships:
                        mitre.append("T1548.003 - AssumeRole Abuse")
                    if 'S3' in path_types:
                        mitre.append("T1530 - Data from Cloud Storage")
                    if 'Secrets' in path_types:
                        mitre.append("T1552.004 - Credentials in Cloud Secrets")
                    if 'RDS' in path_types or 'DynamoDB' in path_types:
                        mitre.append("T1530 - Cloud Database Access")
                    if 'Lambda' in path_types:
                        mitre.append("T1059.009 - Cloud API Execution")
                    if 'EC2' in path_types:
                        mitre.append("T1078.004 - Cloud Administration via Instance Profile")
                    if not mitre:
                        mitre.append("T1078 - Valid Accounts")

                    # Structured explanation & recommendation
                    source_label = source_attr.get('label', source)
                    target_label = target_attr.get('label', target)
                    hop_count = len(path) - 1

                    rel_chain = " → ".join(
                        f"[{ordered_relationships[i]}] {G.nodes[path[i+1]].get('label', path[i+1])}"
                        for i in range(len(ordered_relationships))
                    )
                    description = (
                        f"Identity '{source_label}' can reach {target_attr.get('type', 'resource')} '{target_label}' "
                        f"via {hop_count} hop(s): {source_label} → {rel_chain}."
                    )

                    recommendations = []
                    if 'CAN_ASSUME' in ordered_relationships:
                        recommendations.append("Enforce MFA conditions and IP restrictions in AssumeRole trust policies")
                    if 'ALLOWS' in ordered_relationships:
                        recommendations.append("Replace wildcard actions/resources with least-privilege scoping")
                    if target_attr.get('type') == 'S3':
                        recommendations.append(f"Enable S3 Block Public Access and bucket encryption on '{target_label}'")
                    if target_attr.get('type') == 'Secrets':
                        recommendations.append(f"Enable automatic secret rotation and restrict access to '{target_label}'")
                    
                    recommendation = ". ".join(recommendations) + "." if recommendations else "Review IAM permissions and restrict access paths."

                    paths_list.append({
                        "id": f"path-{idx:03d}",
                        "name": f"Attack Path {idx}: {source_label} → {target_label}",
                        "source": source,
                        "destination": target,
                        "source_label": source_label,
                        "target_label": target_label,
                        "severity": severity,
                        "likelihood": likelihood,
                        "riskScore": total_risk,
                        "hopCount": hop_count,
                        "blastRadius": blast_radius,
                        "mitreTechniques": mitre,
                        "recommendation": recommendation,
                        "description": description,
                        "explanation": description,
                        "orderedRelationships": ordered_relationships,
                        "nodes": nodes_details
                    })
                    idx += 1
            except Exception as e:
                logger.debug(f"Path calculation from {source} to {target}: {e}")

    # Sort paths by risk score descending
    paths_list.sort(key=lambda p: p.get("riskScore", 0), reverse=True)
    logger.info(f"Path Engine: Discovered {len(paths_list)} attack paths")
    return paths_list
