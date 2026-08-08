import logging
import networkx as nx
from typing import List, Dict, Any

logger = logging.getLogger("scanner")


def find_attack_paths(G: nx.DiGraph) -> List[Dict[str, Any]]:
    paths_list = []

    # Starting points (Users, EC2s)
    starts = [n for n, attr in G.nodes(data=True) if attr.get('type') in ['User', 'EC2']]

    # Target points (Roles, S3, Secrets)
    targets = [n for n, attr in G.nodes(data=True) if attr.get('type') in ['Role', 'S3', 'Secrets']]

    # Mapped Paths Tracker
    idx = 1
    for source in starts:
        for target in targets:
            try:
                # Find shortest path using BFS/DFS metrics
                if nx.has_path(G, source, target):
                    path = nx.shortest_path(G, source, target)

                    # Convert to nodes metadata list matching frontend schema
                    nodes_details = []
                    for node_id in path:
                        attr = G.nodes[node_id]
                        nodes_details.append({
                            "id": node_id,
                            "name": attr.get('label', node_id),
                            "type": attr.get('type', 'Resource')
                        })

                    # Calculate aggregate risk and likelihood metric
                    risk_scores = [G.nodes[nid].get('riskScore', 0) for nid in path]
                    total_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
                    max_risk = max(risk_scores) if risk_scores else 0
                    likelihood = min(95, int(total_risk * 1.1))

                    # Compute blast radius dynamically
                    try:
                        reachable = len(nx.descendants(G, source))
                        if reachable >= 5:
                            blast_radius = f"High ({reachable} reachable nodes)"
                        elif reachable >= 2:
                            blast_radius = f"Medium ({reachable} reachable nodes)"
                        else:
                            blast_radius = f"Low ({reachable} reachable node{'s' if reachable != 1 else ''})"
                    except Exception:
                        blast_radius = "Unknown"

                    # Determine severity from actual risk scores
                    if total_risk >= 80:
                        severity = "critical"
                    elif total_risk >= 60:
                        severity = "high"
                    elif total_risk >= 40:
                        severity = "medium"
                    else:
                        severity = "low"

                    # Build MITRE techniques based on path node types
                    mitre = []
                    path_types = [G.nodes[nid].get('type', '') for nid in path]
                    if 'User' in path_types:
                        mitre.append("T1078 - Valid Accounts")
                    if 'Role' in path_types:
                        mitre.append("T1548.003 - AssumeRole Abuse")
                    if 'S3' in path_types:
                        mitre.append("T1530 - Data from Cloud Storage")
                    if 'Secrets' in path_types:
                        mitre.append("T1552.004 - Credentials in Cloud Secrets")
                    if 'Lambda' in path_types:
                        mitre.append("T1059.009 - Cloud API Execution")
                    if not mitre:
                        mitre.append("T1078 - Valid Accounts")

                    # Build dynamic recommendation
                    recommendations = []
                    source_attr = G.nodes[source]
                    target_attr = G.nodes[target]
                    if source_attr.get('type') == 'User':
                        recommendations.append(f"Review permissions for user '{source_attr.get('label')}'")
                    if 'Role' in path_types:
                        recommendations.append("Enforce MFA conditions in AssumeRole trust policies")
                    if target_attr.get('type') == 'S3':
                        recommendations.append(f"Restrict access to S3 bucket '{target_attr.get('label')}'")
                    if target_attr.get('type') == 'Secrets':
                        recommendations.append(f"Enable rotation on secret '{target_attr.get('label')}'")
                    recommendation = ". ".join(recommendations) + "." if recommendations else "Review access path and apply least-privilege policies."

                    source_label = G.nodes[source].get('label', source)
                    target_label = G.nodes[target].get('label', target)

                    paths_list.append({
                        "id": f"path-{idx:03d}",
                        "name": f"Attack Path {idx}: {source_label} → {target_label}",
                        "severity": severity,
                        "likelihood": likelihood,
                        "blastRadius": blast_radius,
                        "mitreTechniques": mitre,
                        "recommendation": recommendation,
                        "description": f"An attack path from {source_attr.get('type', 'identity')} '{source_label}' to {target_attr.get('type', 'resource')} '{target_label}' via {len(path) - 2} intermediate hop{'s' if len(path) - 2 != 1 else ''}.",
                        "nodes": nodes_details
                    })
                    idx += 1
            except Exception as e:
                logger.error(f"Path Engine calculation error from {source} to {target}: {str(e)}")

    logger.info(f"Path Engine: Discovered {len(paths_list)} attack paths")
    return paths_list
