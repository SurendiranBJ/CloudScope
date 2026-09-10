"""
CloudScope Deterministic Attack Path Engine.

Discovers, evaluates, and scores lateral movement attack paths traversing
identities, IAM policies, AssumeRole trust boundaries, and cloud resources.
Computes deterministic path scores, classifications, exact relationship chains,
and authoritative effective-access blast radius metrics.
"""

import logging
import networkx as nx
from typing import List, Dict, Any, Set, Tuple, Optional
from app.services.risk.risk_constants import get_severity_label
from app.services.attack.constants import MAX_ROLE_HOPS

logger = logging.getLogger("scanner")

MAX_ATTACK_PATHS = 200

# Security-Semantic Path Allowed Transitions
# Paths traversing relationships outside this table are rejected — graph connectivity is not authorization.
# Cloud resources can ONLY be reached through Policy ALLOWS (no fake direct Role->Resource edges).
RESOURCE_TYPES = {"S3", "EC2", "Lambda", "RDS", "DynamoDB", "Secrets", "Secret"}

VALID_TRANSITIONS: Dict[Tuple[str, str], Set[str]] = {
    ("User", "Group"): {"MEMBER_OF"},
    ("User", "Policy"): {"HAS_POLICY"},
    ("User", "Role"): {"CAN_ASSUME", "ASSUMED_ROLE"},
    ("Group", "Policy"): {"HAS_POLICY"},
    ("Role", "Policy"): {"HAS_POLICY"},
    ("Role", "Role"): {"CAN_ASSUME", "ASSUMED_ROLE"},
    ("EC2", "Role"): {"ATTACHED_TO"},
    ("Lambda", "Role"): {"EXECUTES_WITH"},
}

for _res in RESOURCE_TYPES:
    VALID_TRANSITIONS[("Policy", _res)] = {"ALLOWS"}


def _validate_path_security_semantics(path: List[str], G: nx.DiGraph) -> bool:
    """Validate that every successive node-type transition along path adheres
    to explicit AWS IAM security semantics.
    Graph connectivity alone is not authorization.
    """
    if len(path) < 2:
        return False

    for i in range(len(path) - 1):
        u, v = path[i], path[i + 1]
        u_type = G.nodes[u].get("type", "")
        v_type = G.nodes[v].get("type", "")

        edge_data = G.get_edge_data(u, v, default={})
        rel_label = edge_data.get("label") or edge_data.get("type") or ""

        allowed_rels = VALID_TRANSITIONS.get((u_type, v_type))
        if not allowed_rels or rel_label not in allowed_rels:
            return False

    return True


def classify_path_type(path: List[str], G: nx.DiGraph, ordered_rels: List[str]) -> str:
    """Classify the primary security vector type for this attack path based on evidence.

    Privilege escalation is only classified when the destination role or assumed role
    genuinely increases privileges over the source.
    """
    source_node = G.nodes[path[0]]
    target_node = G.nodes[path[-1]]
    source_type = source_node.get('type', '')
    target_type = target_node.get('type', '')
    source_risk = source_node.get('riskScore', 0)
    target_risk = target_node.get('riskScore', 0)

    # Check if path traverses AssumeRole
    has_assume_role = 'CAN_ASSUME' in ordered_rels or 'ASSUMED_ROLE' in ordered_rels

    if target_type == 'Role':
        if has_assume_role:
            # Genuine privilege increase: destination role has high risk or materially higher risk than source
            if target_risk >= 60 or (target_risk - source_risk) >= 15:
                return "privilege_escalation"
            return "lateral_movement"
        return "privilege_escalation" if target_risk >= 60 else "lateral_movement"

    if has_assume_role:
        # Reaching resources via AssumeRole
        if target_type in ['Secrets', 'Secret', 'RDS']:
            return "sensitive_resource_access"
        if target_type == 'S3':
            target_details = target_node.get('details', {})
            if not target_details.get('public_blocked', True):
                return "exposed_resource_path"
            return "sensitive_resource_access"
        if target_risk >= 70 or (target_risk - source_risk) >= 20:
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
    confidence = 95 if len(ordered_rels) > 0 else 80

    return {
        "score": path_score,
        "severity": severity,
        "confidence": confidence
    }


def compute_effective_blast_radius(
    source_node_id: str,
    G: nx.DiGraph,
    inventory: Any = None,
    policy_doc_map: Optional[Dict[str, str]] = None,
    precomputed_records: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[str, int]:
    """Calculate the authoritative blast radius for an identity based on actual effective access.

    Counts unique real cloud resources (S3, EC2, Lambda, RDS, DynamoDB, Secrets).
    Never counts identity/privilege nodes (User, Group, Policy, Role).
    Returns (blast_radius_desc, unique_asset_count).
    """
    unique_assets: Set[str] = set()

    # 1. Authoritative effective access engine if records or inventory available
    if precomputed_records is not None or (inventory and policy_doc_map):
        try:
            if precomputed_records is not None:
                records = precomputed_records
            else:
                from app.services.simulation.effective_access import compute_effective_access
                all_res = (
                    getattr(inventory, "s3", []) + getattr(inventory, "secrets", []) +
                    getattr(inventory, "rds", []) + getattr(inventory, "dynamodb", []) +
                    getattr(inventory, "ec2", []) + getattr(inventory, "lambdas", [])
                )
                records = compute_effective_access(inventory, policy_doc_map, all_res)

            s_name = G.nodes[source_node_id].get("label", source_node_id) if G.has_node(source_node_id) else source_node_id
            for rec in records:
                ident_name = rec.get("identity_name", "")
                ident_id = rec.get("identity_id", "")
                if ident_name == s_name or ident_id == source_node_id:
                    rid = rec.get("target_resource_id") or rec.get("target_resource_name")
                    if rid and rec.get("target_resource_type") in RESOURCE_TYPES:
                        unique_assets.add(rid)
        except Exception as e:
            logger.debug(f"Effective access computation fallback for blast radius: {e}")

    # 2. Fallback: trace valid semantic paths through G to actual cloud resources
    if not unique_assets and G and G.has_node(source_node_id):
        target_resource_nodes = [
            n for n, attr in G.nodes(data=True)
            if attr.get("type") in RESOURCE_TYPES
        ]
        for tr in target_resource_nodes:
            if not nx.has_path(G, source_node_id, tr):
                continue
            try:
                for p in nx.all_simple_paths(G, source_node_id, tr, cutoff=MAX_ROLE_HOPS):
                    if _validate_path_security_semantics(p, G):
                        canonical_id = G.nodes[tr].get("arn") or G.nodes[tr].get("label") or tr
                        unique_assets.add(canonical_id)
                        break
            except Exception:
                continue

    count = len(unique_assets)
    if count >= 5:
        desc = f"High ({count} unique cloud assets)"
    elif count >= 2:
        desc = f"Medium ({count} unique cloud assets)"
    elif count == 1:
        desc = "Low (1 unique cloud asset)"
    else:
        desc = "Low (0 unique cloud assets)"

    return desc, count


def find_attack_paths(
    G: nx.DiGraph,
    max_hops: int = MAX_ROLE_HOPS,
    inventory: Any = None,
    policy_doc_map: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Discover deterministic attack paths traversing identities, policies, and cloud resources."""
    if not G or G.number_of_nodes() == 0:
        return []

    # Starting points (Users and Compute)
    starts = [n for n, attr in G.nodes(data=True) if attr.get('type') in ['User', 'EC2']]

    # Target points (Sensitive data stores and high-privilege roles)
    targets = [
        n for n, attr in G.nodes(data=True)
        if attr.get('type') in ['S3', 'Secrets', 'Secret', 'RDS', 'DynamoDB']
        or (attr.get('type') == 'Role' and attr.get('riskScore', 0) >= 40)
    ]

    seen_paths = set()
    candidate_paths = []

    for source in starts:
        for target in targets:
            if source == target:
                continue

            try:
                if not nx.has_path(G, source, target):
                    continue

                for path in nx.all_simple_paths(G, source, target, cutoff=max_hops):
                    path_tuple = tuple(path)
                    if path_tuple in seen_paths:
                        continue
                    seen_paths.add(path_tuple)

                    if not _validate_path_security_semantics(path, G):
                        continue

                    candidate_paths.append(path)
            except Exception as e:
                logger.debug(f"Path search exception for {source} -> {target}: {e}")
                continue

    # Pre-cache effective blast radius per source node
    blast_cache: Dict[str, str] = {}
    precomputed_records = None
    if inventory and policy_doc_map:
        try:
            from app.services.simulation.effective_access import compute_effective_access
            all_res = (
                getattr(inventory, "s3", []) + getattr(inventory, "secrets", []) +
                getattr(inventory, "rds", []) + getattr(inventory, "dynamodb", []) +
                getattr(inventory, "ec2", []) + getattr(inventory, "lambdas", [])
            )
            precomputed_records = compute_effective_access(inventory, policy_doc_map, all_res)
        except Exception as e:
            logger.debug(f"Precomputing effective access for blast radius failed: {e}")

    evaluated_paths = []
    for path in candidate_paths:
        source = path[0]
        target = path[-1]
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
            rel_label = edge_data.get('label') or edge_data.get('type') or ''
            ordered_relationships.append(rel_label)

        # Compute deterministic path score & severity
        path_eval = calculate_path_risk_score(path, G, ordered_relationships)
        path_type = classify_path_type(path, G, ordered_relationships)

        # Authoritative effective-access blast radius
        if source not in blast_cache:
            desc, _ = compute_effective_blast_radius(
                source, G, inventory, policy_doc_map, precomputed_records=precomputed_records
            )
            blast_cache[source] = desc
        blast_radius_desc = blast_cache[source]

        # MITRE ATT&CK mapping based on actual security behavior
        mitre = []
        source_type = source_attr.get('type', '')
        target_type = target_attr.get('type', '')

        if source_type == 'User':
            mitre.append("T1078 - Valid Accounts")
        if source_type == 'EC2' and 'ATTACHED_TO' in ordered_relationships:
            mitre.append("T1078.004 - Cloud Administration via Instance Profile")
        if 'CAN_ASSUME' in ordered_relationships:
            mitre.append("T1548.003 - Subvert Trust Controls: AssumeRole")
        if 'ASSUMED_ROLE' in ordered_relationships:
            mitre.append("T1548.003 - Subvert Trust Controls: AssumeRole (Observed Activity)")
        if target_type == 'S3' and 'ALLOWS' in ordered_relationships:
            mitre.append("T1530 - Data from Cloud Storage Object")
        if target_type in ['Secrets', 'Secret'] and 'ALLOWS' in ordered_relationships:
            mitre.append("T1552.004 - Credentials in Cloud Secrets")
        if target_type in ['RDS', 'DynamoDB'] and 'ALLOWS' in ordered_relationships:
            mitre.append("T1530 - Data from Cloud Database")

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

        evaluated_paths.append({
            "source": source,
            "destination": target,
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
            "recommendation": recommendation,
        })

    # Deterministic sort: descending by riskScore, ascending by hopCount, then by source and destination
    evaluated_paths.sort(key=lambda p: (-p["riskScore"], p["hopCount"], p["source"], p["destination"]))

    # Cap at MAX_ATTACK_PATHS
    final_paths = evaluated_paths[:MAX_ATTACK_PATHS]

    # Assign IDs and names
    for idx, p in enumerate(final_paths, start=1):
        s_lbl = G.nodes[p["source"]].get('label', p["source"])
        t_lbl = G.nodes[p["destination"]].get('label', p["destination"])
        p["id"] = f"path-{idx:03d}"
        p["name"] = f"Attack Path {idx}: {s_lbl} → {t_lbl}"

    return final_paths
