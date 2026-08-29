"""
CloudScope Blast Radius & Lateral Impact Engine.

Calculates deterministic blast radius metrics by distinguishing between
privilege/identity abstractions (Users, Roles, Groups, Policies) and actual
cloud resources (S3, EC2, Lambda, Secrets, RDS, DynamoDB). Only actual cloud
assets strongly contribute to blast radius severity.
"""

import logging
import networkx as nx
from typing import Dict, Any, List
from app.services.risk.risk_constants import get_severity_label

logger = logging.getLogger("scanner")

CLOUD_RESOURCE_TYPES = {"S3", "EC2", "Lambda", "Secrets", "Secret", "RDS", "DynamoDB"}
PRIVILEGE_TYPES = {"Role", "Group", "Policy"}
IDENTITY_TYPES = {"User"}


def calculate_blast_radius(G: nx.DiGraph, node_id: str) -> Dict[str, Any]:
    """Calculate the blast radius and reachability of a compromised node in the graph."""
    if not G or not G.has_node(node_id):
        return {
            "node_id": node_id,
            "blast_score": 0,
            "severity": "low",
            "reachable_resource_count": 0,
            "reachable_identities_count": 0,
            "reachable_privilege_count": 0,
            "critical_asset_count": 0,
            "max_depth": 0,
            "critical_assets": [],
            "reachable_nodes": [],
            "resource_types": {},
            "evidence": []
        }

    try:
        descendants = list(nx.descendants(G, node_id))
        
        identities: List[str] = []
        privileges: List[str] = []
        resources: List[str] = []
        critical_assets: List[Dict[str, Any]] = []
        resource_types: Dict[str, int] = {}
        max_depth = 0
        evidence: List[str] = []

        for nid in descendants:
            node_data = G.nodes[nid]
            ntype = node_data.get('type', 'Resource')
            nlabel = node_data.get('label', nid)
            nrisk = node_data.get('riskScore', 0)

            # Measure shortest path depth
            try:
                d = nx.shortest_path_length(G, node_id, nid)
                if d > max_depth:
                    max_depth = d
            except Exception:
                pass

            if ntype in IDENTITY_TYPES:
                identities.append(nid)
            elif ntype in PRIVILEGE_TYPES:
                privileges.append(nid)
            else:
                resources.append(nid)
                resource_types[ntype] = resource_types.get(ntype, 0) + 1

            # Critical asset identification (Secrets, RDS, S3, or role with riskScore >= 60)
            if ntype in ['Secrets', 'Secret', 'RDS', 'S3'] or (ntype == 'Role' and nrisk >= 60):
                critical_assets.append({
                    "id": nid,
                    "name": nlabel,
                    "type": ntype,
                    "riskScore": nrisk
                })

        # Calculate blast score: based on reachable actual cloud resources and critical assets
        res_count = len(resources)
        crit_count = len(critical_assets)
        priv_count = len(privileges)

        # Evidence-based formula:
        # Base points for resources + high weighting for critical assets + minor hop complexity
        raw_score = (res_count * 12) + (crit_count * 20) + (priv_count * 5) + (max_depth * 3)
        blast_score = min(100, max(0, raw_score))
        severity = get_severity_label(blast_score)

        if crit_count > 0:
            evidence.append(f"{crit_count} critical cloud data store(s) / high-privilege role(s) directly reachable.")
        if res_count > 0:
            evidence.append(f"{res_count} total cloud infrastructure resources accessible within {max_depth} hop(s).")
        if priv_count > 0:
            evidence.append(f"{priv_count} intermediate IAM roles/groups traversed in lateral attack graph.")

        return {
            "node_id": node_id,
            "blast_score": blast_score,
            "severity": severity,
            "reachable_resource_count": res_count,
            "reachable_identities_count": len(identities),
            "reachable_privilege_count": priv_count,
            "critical_asset_count": crit_count,
            "max_depth": max_depth,
            "critical_assets": critical_assets,
            "reachable_nodes": descendants,
            "resource_types": resource_types,
            "evidence": evidence,
            "breakdown": {
                **resource_types,
                "User": len(identities),
                "Role": sum(1 for p in privileges if G.nodes[p].get('type') == 'Role'),
                "Group": sum(1 for p in privileges if G.nodes[p].get('type') == 'Group'),
                "Policy": sum(1 for p in privileges if G.nodes[p].get('type') == 'Policy')
            }
        }
    except Exception as e:
        logger.error(f"Failed to calculate blast radius for {node_id}: {e}")
        return {
            "node_id": node_id,
            "blast_score": 0,
            "severity": "low",
            "reachable_resource_count": 0,
            "reachable_identities_count": 0,
            "reachable_privilege_count": 0,
            "critical_asset_count": 0,
            "max_depth": 0,
            "critical_assets": [],
            "reachable_nodes": [],
            "resource_types": {},
            "evidence": []
        }
