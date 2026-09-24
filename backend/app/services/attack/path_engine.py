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
# Cloud resources can ONLY be reached through Policy ALLOWS or DB_CONNECT (no fake direct Role->Resource edges).
RESOURCE_TYPES = {"S3", "EC2", "Lambda", "RDS", "DynamoDB", "Secrets", "Secret", "AuroraDBUser"}

VALID_TRANSITIONS: Dict[Tuple[str, str], Set[str]] = {
    ("User", "Group"): {"MEMBER_OF"},
    ("User", "Policy"): {"HAS_POLICY"},
    ("User", "Role"): {"CAN_ASSUME", "ASSUMED_ROLE"},
    ("User", "RDS"): {"DB_CONNECT"},
    ("User", "AuroraDBUser"): {"DB_CONNECT"},
    ("Group", "Policy"): {"HAS_POLICY"},
    ("Role", "Policy"): {"HAS_POLICY"},
    ("Role", "Role"): {"CAN_ASSUME", "ASSUMED_ROLE"},
    ("Role", "RDS"): {"DB_CONNECT"},
    ("Role", "AuroraDBUser"): {"DB_CONNECT"},
    ("EC2", "Role"): {"ATTACHED_TO", "EXECUTES_WITH"},
    ("Lambda", "Role"): {"EXECUTES_WITH"},
    ("Policy", "AuroraDBUser"): {"DB_CONNECT"},
    ("Policy", "RDS"): {"DB_CONNECT"},
    ("AuroraDBUser", "RDS"): {"BELONGS_TO"},
}

for _res in RESOURCE_TYPES:
    if _res != "AuroraDBUser":
        VALID_TRANSITIONS[("Policy", _res)] = {"ALLOWS"}

# Standardized Target Architectural Categories
TARGET_CATEGORIES: Dict[str, str] = {
    "S3": "DATA_RESOURCE",
    "RDS": "DATA_RESOURCE",
    "DynamoDB": "DATA_RESOURCE",
    "EC2": "COMPUTE_RESOURCE",
    "Lambda": "COMPUTE_RESOURCE",
    "Secrets": "CREDENTIAL_RESOURCE",
    "Secret": "CREDENTIAL_RESOURCE",
    "AuroraDBUser": "DATABASE_AUTH",
    "Role": "IDENTITY_TARGET",
}


def get_target_category(target_type: str) -> str:
    """Classify target entity into a standardized architectural category for display/filtering."""
    return TARGET_CATEGORIES.get(target_type, "UNKNOWN")


def _is_valid_lambda_workload_start(node_id: str, G: nx.DiGraph) -> bool:
    """Determine whether a Lambda function qualifies as a workload attack-path starting point.

    Design Decision (Workload Identity Analysis):
    A serverless Lambda function is NOT considered an attack starting point simply because it exists.
    It becomes an entry/starting point for workload compromise analysis ONLY when there is explicit
    evidence of credentialed workload execution:
    1. The Lambda function has an outbound EXECUTES_WITH relationship to an active IAM Role.
    2. The execution Role exists in the graph and has attached IAM policies (HAS_POLICY).
    3. The execution Role trust policy (if present) confirms service assumption by lambda.amazonaws.com.

    This models compromised workload vectors (e.g. function code injection, SSRF, vulnerable dependencies)
    without creating phantom starts for unconfigured or dormant functions.
    """
    for _, target_id in G.out_edges(node_id):
        edge_data = G.get_edge_data(node_id, target_id, default={})
        rel = (
            edge_data.get("relationship")
            or edge_data.get("label")
            or edge_data.get("type")
            or ""
        )
        if rel == "EXECUTES_WITH" and G.has_node(target_id) and G.nodes[target_id].get("type") == "Role":
            role_attr = G.nodes[target_id]
            # Check for attached policies on the execution role
            has_policies = any(
                (
                    G.get_edge_data(target_id, p_id, default={}).get("relationship")
                    or G.get_edge_data(target_id, p_id, default={}).get("label")
                    or G.get_edge_data(target_id, p_id, default={}).get("type")
                ) == "HAS_POLICY"
                for _, p_id in G.out_edges(target_id)
            )
            if not has_policies:
                continue

            # Verify trust policy allows lambda.amazonaws.com if present
            trust_policy = role_attr.get("assume_role_policy") or role_attr.get("trustPolicy") or {}
            trusts_lambda = True
            if trust_policy:
                try:
                    import json
                    if isinstance(trust_policy, str) and trust_policy.startswith("{"):
                        trust_policy = json.loads(trust_policy)
                    from app.services.attack.policy_evaluator import parse_policy_document
                    stmts = parse_policy_document(trust_policy)
                    if stmts:
                        trusts_lambda = False
                        for stmt in stmts:
                            if stmt.get("Effect") == "Allow":
                                princ = stmt.get("Principal", {})
                                if princ == "*":
                                    trusts_lambda = True
                                    break
                                if isinstance(princ, dict):
                                    svc = princ.get("Service", "")
                                    if svc == "*" or "lambda.amazonaws.com" in svc or (
                                        isinstance(svc, list) and any("lambda.amazonaws.com" in s for s in svc)
                                    ):
                                        trusts_lambda = True
                                        break
                except Exception:
                    trusts_lambda = True

            if trusts_lambda:
                return True

    return False


def _validate_path_security_semantics(path: List[str], G: nx.DiGraph) -> bool:
    """Validate that every successive node-type transition along path adheres
    to explicit AWS IAM security semantics.
    Graph connectivity alone is not authorization.
    """
    if len(path) < 2:
        return False

    # Do not traverse alias / shadow nodes
    for n in path:
        if G.nodes[n].get("is_canonical") is False:
            return False

    source_type = G.nodes[path[0]].get("type", "")

    for i in range(len(path) - 1):
        u, v = path[i], path[i + 1]
        u_type = G.nodes[u].get("type", "")
        v_type = G.nodes[v].get("type", "")

        edge_data = G.get_edge_data(u, v, default={})
        rel_label = (
            edge_data.get("relationship")
            or edge_data.get("label")
            or edge_data.get("type")
            or ""
        )

        allowed_rels = VALID_TRANSITIONS.get((u_type, v_type))
        if not allowed_rels or rel_label not in allowed_rels:
            return False

        # Workload transitions (EC2/Lambda -> Role via ATTACHED_TO / EXECUTES_WITH)
        # are valid ONLY when the workload entity (EC2/Lambda) is the starting point of the path.
        # Once an identity path reaches a resource via ALLOWS, that resource is a terminal target,
        # not an identity bridge. An invoking user does NOT acquire the execution role's permissions.
        if rel_label in {"EXECUTES_WITH", "ATTACHED_TO"}:
            if i > 0:
                return False
            # A compute workload simply binding to its own configured execution role / instance profile
            # in 1 hop is not an attack path; it must reach a target resource or assume another role.
            if len(path) == 2 and source_type in {"EC2", "Lambda"}:
                return False

    return True


class PathEngine:
    """Wrapper class providing attack path search and evaluation helpers."""
    def find_attack_paths(self, G: nx.DiGraph, *args, **kwargs) -> List[Dict[str, Any]]:
        return find_attack_paths(G, *args, **kwargs)


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
        if target_type in ['EC2', 'Lambda']:
            return "compute_resource_access"
        if target_type in ['Secrets', 'Secret', 'RDS', 'DynamoDB', 'AuroraDBUser']:
            return "sensitive_resource_access"
        if target_type == 'S3':
            target_details = target_node.get('details', {})
            if not target_details.get('public_blocked', True):
                return "exposed_resource_path"
            return "sensitive_resource_access"
        if target_risk >= 70 or (target_risk - source_risk) >= 20:
            return "privilege_escalation"
        return "lateral_movement"

    if target_type in ['EC2', 'Lambda']:
        return "compute_resource_access"

    if target_type in ['Secrets', 'Secret', 'RDS', 'DynamoDB', 'AuroraDBUser']:
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
    if 'DB_CONNECT' in ordered_rels:
        escalation_bonus += 20

    target_sensitivity_bonus = 0
    t_type = target_attr.get('type', '')
    if t_type in ['Secrets', 'Secret']:
        target_sensitivity_bonus += 35
    elif t_type in ['RDS', 'AuroraDBUser', 'DynamoDB']:
        target_sensitivity_bonus += 30
    elif t_type == 'S3':
        target_sensitivity_bonus += 25
    elif t_type in ['EC2', 'Lambda']:
        target_sensitivity_bonus += 20
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

    factors = {
        "source_risk": int(source_risk * 0.25),
        "target_risk": int(target_risk * 0.35),
        "privilege_escalation_factor": escalation_bonus,
        "sensitive_resource_factor": target_sensitivity_bonus,
        "path_length_factor": max(0, 10 - len(ordered_rels) * 2)
    }

    return {
        "score": path_score,
        "severity": severity,
        "confidence": confidence,
        "factors": factors
    }


def _eval_passrole_for_permissions(
    G: nx.DiGraph,
    user_id: str,
    user_permissions: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    import json
    from app.services.attack.policy_evaluator import match_action, parse_policy_document

    has_passrole = False
    target_resource_specs = []
    for p in user_permissions:
        act = p.get("Action", [])
        if isinstance(act, str):
            act = [act]
        if any(match_action(a, "iam:PassRole") or match_action(a, "iam:*") or a == "*" for a in act):
            has_passrole = True
            res = p.get("Resource", "*")
            if isinstance(res, list):
                target_resource_specs.extend(res)
            else:
                target_resource_specs.append(res)

    if not has_passrole:
        return None

    for node_id, attrs in G.nodes(data=True):
        if attrs.get("type") != "Role":
            continue

        role_arn = attrs.get("arn") or node_id
        role_name = attrs.get("name") or attrs.get("label") or node_id

        matches = False
        for spec in target_resource_specs:
            if spec == "*" or spec == node_id or spec == role_arn or spec.endswith(f"/{role_name}"):
                matches = True
                break
        if not matches:
            continue

        target_risk = attrs.get("riskScore", 0)
        if target_risk < 60:
            continue

        trust_doc = attrs.get("assume_role_policy") or attrs.get("trustPolicy") or {}
        if isinstance(trust_doc, str) and trust_doc.startswith("{"):
            try:
                trust_doc = json.loads(trust_doc)
            except Exception:
                pass

        service_principal = None
        for stmt in parse_policy_document(trust_doc):
            if stmt.get("Effect") == "Allow":
                princ = stmt.get("Principal", {})
                if isinstance(princ, dict) and "Service" in princ:
                    svc = princ["Service"]
                    service_principal = svc if isinstance(svc, str) else svc[0]
                    break
                elif princ == "*":
                    service_principal = "*"
                    break

        if not service_principal:
            continue

        return {
            "is_passrole": True,
            "target_role": node_id,
            "target_role_trust_evidence": f"Target role trusts service principal '{service_principal}' (lambda.amazonaws.com / ec2.amazonaws.com)",
            "risk_elevation": f"Target role risk score: {target_risk} (elevated context >= 60)",
            "trigger_permission": "iam:PassRole",
            "service_principal": service_principal,
            "impact": f"Target role has elevated privileges (risk score: {target_risk})",
            "reason": f"Principal has iam:PassRole permission to pass role '{role_name}' to AWS service '{service_principal}'."
        }

    return None


def check_passrole_escalation(*args, **kwargs) -> Any:
    """Check whether a principal has iam:PassRole capability to an elevated target role
    that can be assumed/used by an AWS service (e.g. lambda.amazonaws.com, ec2.amazonaws.com).
    
    Supports two calling signatures:
    1. check_passrole_escalation(G, user_id, user_permissions) -> Optional[Dict]
    2. check_passrole_escalation(source_node_id, target_role_id, G, inventory=None) -> Tuple[bool, Optional[Dict]]
    """
    if len(args) >= 1 and isinstance(args[0], nx.DiGraph):
        G = args[0]
        user_id = args[1] if len(args) > 1 else kwargs.get("user_id", "")
        user_permissions = args[2] if len(args) > 2 else kwargs.get("user_permissions", [])
        return _eval_passrole_for_permissions(G, user_id, user_permissions)
    if "G" in kwargs and isinstance(kwargs["G"], nx.DiGraph) and "user_permissions" in kwargs:
        return _eval_passrole_for_permissions(kwargs["G"], kwargs.get("user_id", ""), kwargs.get("user_permissions", []))

    source_node_id = args[0] if len(args) > 0 else kwargs.get("source_node_id", "")
    target_role_id = args[1] if len(args) > 1 else kwargs.get("target_role_id", "")
    G = args[2] if len(args) > 2 else kwargs.get("G")
    inventory = args[3] if len(args) > 3 else kwargs.get("inventory")

    if not G or not (G.has_node(source_node_id) and G.has_node(target_role_id)):
        return False, None

    target_node = G.nodes[target_role_id]
    if target_node.get('type') != 'Role':
        return False, None

    target_risk = target_node.get('riskScore', 0)
    source_node = G.nodes[source_node_id]
    source_risk = source_node.get('riskScore', 0)

    # Target role must be elevated
    if target_risk < 60 and (target_risk - source_risk) < 20:
        return False, None

    # Check if principal has iam:PassRole in their attached policies
    has_passrole = False
    passrole_policy = None
    passrole_statement = None

    for _, pol_node_id in G.out_edges(source_node_id):
        if G.nodes[pol_node_id].get('type') == 'Policy':
            pol_doc_str = G.nodes[pol_node_id].get('description') or ''
            try:
                import json
                pol_doc = json.loads(pol_doc_str) if isinstance(pol_doc_str, str) and pol_doc_str.startswith('{') else {}
                from app.services.attack.policy_evaluator import parse_policy_document, match_action
                for stmt in parse_policy_document(pol_doc):
                    if stmt.get('Effect') == 'Allow':
                        actions = stmt.get('Action', [])
                        if any(match_action(a, 'iam:PassRole') or match_action(a, 'iam:*') or a == '*' for a in actions):
                            has_passrole = True
                            passrole_policy = G.nodes[pol_node_id].get('label', pol_node_id)
                            passrole_statement = stmt.get('Sid', 'PassRoleStatement')
                            break
            except Exception:
                pass
        if has_passrole:
            break

    if not has_passrole:
        return False, None

    # Target role must be assumable by / usable with a relevant AWS service
    target_trust = target_node.get('trustPolicy') or target_node.get('assume_role_policy') or ''
    usable_by_service = False
    service_principal = None
    if target_trust:
        try:
            import json
            trust_doc = json.loads(target_trust) if isinstance(target_trust, str) and target_trust.startswith('{') else target_trust
            from app.services.attack.policy_evaluator import parse_policy_document
            for stmt in parse_policy_document(trust_doc):
                if stmt.get('Effect') == 'Allow':
                    p_obj = stmt.get('Principal', {})
                    if isinstance(p_obj, dict):
                        svc = p_obj.get('Service')
                        if svc:
                            usable_by_service = True
                            service_principal = svc if isinstance(svc, str) else svc[0]
                            break
                    elif p_obj == '*':
                        usable_by_service = True
                        service_principal = '*'
                        break
        except Exception:
            pass

    if not usable_by_service:
        return False, None

    return True, {
        "trigger_permission": "iam:PassRole",
        "policy": passrole_policy,
        "statement_sid": passrole_statement,
        "target_role": target_node.get('label', target_role_id),
        "target_role_arn": target_node.get('arn', ''),
        "service_principal": service_principal,
        "target_risk": target_risk,
        "impact": f"Target role has administrator/elevated permissions (risk score: {target_risk})",
        "reason": f"Principal has iam:PassRole permission to pass role '{target_node.get('label')}' to AWS service '{service_principal}', granting elevated execution context."
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

    # Starting points (Users, EC2, and verified Lambda workloads) - canonical nodes only
    starts = [
        n for n, attr in G.nodes(data=True)
        if (
            attr.get('type') in ['User', 'EC2']
            or (attr.get('type') == 'Lambda' and _is_valid_lambda_workload_start(n, G))
        )
        and attr.get('is_canonical') is not False
    ]

    # Target points (All canonical cloud resources and elevated roles) - canonical nodes only
    targets = [
        n for n, attr in G.nodes(data=True)
        if (
            attr.get('type') in RESOURCE_TYPES
            or (attr.get('type') == 'Role' and attr.get('riskScore', 0) >= 40)
        )
        and attr.get('is_canonical') is not False
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
                    if not _validate_path_security_semantics(path, G):
                        continue

                    canonical_key = tuple(G.nodes[n].get("canonical_id") or n for n in path)
                    if canonical_key in seen_paths:
                        continue
                    seen_paths.add(canonical_key)

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
            rel_label = (
                edge_data.get('relationship')
                or edge_data.get('label')
                or edge_data.get('type')
                or ''
            )
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
        if source_type == 'Lambda' and 'EXECUTES_WITH' in ordered_relationships:
            mitre.append("T1078.004 - Cloud Administration via Lambda Execution Role")
        if 'CAN_ASSUME' in ordered_relationships:
            mitre.append("T1548.003 - Subvert Trust Controls: AssumeRole")
        if 'ASSUMED_ROLE' in ordered_relationships:
            mitre.append("T1548.003 - Subvert Trust Controls: AssumeRole (Observed Activity)")
        if target_type == 'S3' and 'ALLOWS' in ordered_relationships:
            mitre.append("T1530 - Data from Cloud Storage Object")
        if target_type in ['Secrets', 'Secret'] and 'ALLOWS' in ordered_relationships:
            mitre.append("T1552.004 - Credentials in Cloud Secrets")
        if 'DB_CONNECT' in ordered_relationships:
            mitre.append("T1078 - Valid Accounts: Database IAM Authentication")
        if target_type in ['RDS', 'DynamoDB', 'AuroraDBUser'] and ('ALLOWS' in ordered_relationships or 'DB_CONNECT' in ordered_relationships or 'BELONGS_TO' in ordered_relationships):
            mitre.append("T1530 - Data from Cloud Database")
        if target_type == 'EC2' and 'ALLOWS' in ordered_relationships:
            mitre.append("T1578 - Modify Cloud Compute Infrastructure: EC2")
        if target_type == 'Lambda' and 'ALLOWS' in ordered_relationships:
            mitre.append("T1648 - Serverless Execution: Lambda")

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
        if target_attr.get('type') == 'EC2':
            recommendations.append(f"Restrict EC2 management permissions and enforce IMDSv2 on '{target_label}'")
        if target_attr.get('type') == 'Lambda':
            recommendations.append(f"Restrict invoke permissions and apply least privilege to '{target_label}' execution role")
        if target_attr.get('type') in ['RDS', 'DynamoDB', 'AuroraDBUser']:
            recommendations.append(f"Restrict database access policies and enable encryption at rest for '{target_label}'")

        # Step-by-step transition evidence
        transition_evidence: List[Dict[str, Any]] = []
        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            rel_label = ordered_relationships[i]
            edge_data = G.get_edge_data(u, v, default={})
            u_node = G.nodes[u]
            v_node = G.nodes[v]
            u_lbl = u_node.get('label', u)
            v_lbl = v_node.get('label', v)
            u_t = u_node.get('type', 'Resource')
            v_t = v_node.get('type', 'Resource')

            prov = edge_data.get('provenance') or {}
            why = edge_data.get('why') or prov.get('why')
            if not why:
                if rel_label == 'MEMBER_OF':
                    why = f"IAM user '{u_lbl}' is a member of group '{v_lbl}'"
                elif rel_label == 'HAS_POLICY':
                    why = f"Identity '{u_lbl}' has policy '{v_lbl}' attached"
                elif rel_label == 'CAN_ASSUME':
                    why = f"Role '{v_lbl}' trust policy permits assumption by '{u_lbl}'"
                elif rel_label == 'ASSUMED_ROLE':
                    why = f"Observed CloudTrail activity: '{u_lbl}' assumed role '{v_lbl}'"
                elif rel_label == 'ATTACHED_TO':
                    why = f"EC2 instance '{u_lbl}' uses IAM instance profile role '{v_lbl}'"
                elif rel_label == 'EXECUTES_WITH':
                    why = f"Lambda function '{u_lbl}' executes with IAM role '{v_lbl}'"
                elif rel_label == 'ALLOWS':
                    act = edge_data.get('action') or prov.get('action', '*')
                    why = f"Policy '{u_lbl}' allows action '{act}' on {v_t} '{v_lbl}'"
                elif rel_label == 'DB_CONNECT':
                    why = f"Policy '{u_lbl}' grants rds-db:connect to DB user '{v_lbl}'"
                elif rel_label == 'BELONGS_TO':
                    why = f"DB user '{u_lbl}' belongs to database '{v_lbl}'"
                else:
                    why = f"Transition '{rel_label}' from '{u_lbl}' to '{v_lbl}'"

            transition_evidence.append({
                "from_node": u,
                "from_name": u_lbl,
                "from_type": u_t,
                "to_node": v,
                "to_name": v_lbl,
                "to_type": v_t,
                "relationship": rel_label,
                "why": why,
                "policy_name": edge_data.get('policy_name') or prov.get('policy_name', ''),
                "statement_sid": edge_data.get('statement_sid') or prov.get('statement_sid', ''),
                "action": edge_data.get('action') or prov.get('action', ''),
                "resource_arn": edge_data.get('resource_arn') or prov.get('resource_arn', ''),
                "decision": edge_data.get('decision') or prov.get('decision', 'ALLOWED'),
                "condition_status": edge_data.get('condition_status') or prov.get('condition_status', 'NONE'),
                "region": edge_data.get('region') or prov.get('region') or v_node.get('region', ''),
                "evidence": edge_data.get('evidence') or prov.get('evidence', {})
            })

        # Check PassRole escalation candidate
        is_passrole, passrole_ev = check_passrole_escalation(source, target, G, inventory)
        if is_passrole and passrole_ev:
            path_type = "privilege_escalation"

        priv_details = None
        lat_details = None

        if path_type == "privilege_escalation":
            trig_perm = passrole_ev["trigger_permission"] if is_passrole and passrole_ev else ("sts:AssumeRole" if 'CAN_ASSUME' in ordered_relationships or 'ASSUMED_ROLE' in ordered_relationships else "iam:AttachPolicy")
            priv_details = {
                "title": f"Potential Privilege Escalation via {trig_perm.split(':')[-1]}",
                "summary": f"Identity '{source_label}' can transition privileges to reach elevated target '{target_label}'.",
                "source_identity": source_label,
                "target_identity": target_label,
                "trigger_permission": trig_perm,
                "supporting_evidence": passrole_ev if is_passrole and passrole_ev else {
                    "ordered_relationships": ordered_relationships,
                    "source_risk": source_attr.get('riskScore', 0),
                    "target_risk": target_attr.get('riskScore', 0),
                    "target_type": target_attr.get('type', ''),
                },
                "impact": f"Target entity '{target_label}' possesses elevated privileges or high-value resource access (risk score: {target_attr.get('riskScore', 0)}).",
                "reason": f"Principal possesses {trig_perm} capability enabling privilege expansion to target.",
                "limitations": "Static configuration analysis; CloudTrail evidence is not implied."
            }
        else:
            lat_details = {
                "origin": source_label,
                "transition": " → ".join(ordered_relationships),
                "destination": target_label,
                "authorization_evidence": f"Path traverses verified IAM trust and authorization boundaries ({len(ordered_relationships)} transitions).",
                "impact": f"Identity moves laterally across account boundaries to access '{target_label}'."
            }

        target_cat = get_target_category(target_attr.get('type', ''))

        evaluated_paths.append({
            "source": source,
            "destination": target,
            "target": target,
            "pathType": path_type,
            "attack_type": path_type,
            "target_type": target_attr.get('type', ''),
            "target_category": target_cat,
            "targetCategory": target_cat,
            "nodes": nodes_details,
            "ordered_nodes": nodes_details,
            "orderedRelationships": ordered_relationships,
            "ordered_relationships": ordered_relationships,
            "hopCount": hop_count,
            "riskScore": path_eval["score"],
            "risk_score": path_eval["score"],
            "severity": path_eval["severity"],
            "confidence": path_eval["confidence"],
            "blastRadius": blast_radius_desc,
            "mitreTechniques": mitre,
            "description": description,
            "reason": description,
            "recommendation": recommendations[0] if recommendations else "Enforce principle of least privilege.",
            "recommendations": recommendations,
            "evidence": transition_evidence,
            "risk_factors": path_eval.get("factors", {}),
            "privilege_escalation_details": priv_details,
            "lateral_movement_details": lat_details,
            "region": target_attr.get("region") or source_attr.get("region") or "global",
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
