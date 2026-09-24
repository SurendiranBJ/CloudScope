"""
CloudScope Effective Access Engine.

Computes which identities (Users, Roles) have effective access to which
cloud resources, and preserves full access provenance (the chain of
identities, groups, policies, and roles that grant the access).

Uses the existing policy_evaluator module exclusively.
No name-based heuristics.

Supported access chains:
    1. User  → direct HAS_POLICY     → Policy → ALLOWS → Resource
    2. User  → MEMBER_OF → Group     → HAS_POLICY → Policy → ALLOWS → Resource
    3. User  → CAN_ASSUME → Role     → HAS_POLICY → Policy → ALLOWS → Resource
    4. Role  → HAS_POLICY → Policy   → ALLOWS → Resource
    (Inline policies for users, groups, and roles are also evaluated.)
"""

import logging
from typing import Any, Dict, List, Tuple, Optional

from app.services.attack.policy_evaluator import (
    evaluate_policy_allows_resources,
    evaluate_policy_allows_resources_with_provenance,
    evaluate_assume_role_trust,
    evaluate_assume_role_trust_with_evidence,
    check_resource_explicitly_denied,
    get_effective_identity_policy_documents,
)
from app.services.attack.constants import MAX_ROLE_HOPS

logger = logging.getLogger("scanner")

# Cloud resource types that count as effective access targets
RESOURCE_TYPES = {"S3", "EC2", "Lambda", "Secrets", "Secret", "RDS", "DynamoDB"}


def compute_effective_access(
    inventory: Any,
    policy_doc_map: Dict[str, str],
    all_resources: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Compute every effective identity→resource access relationship with provenance.

    Args:
        inventory: AWSInventory (current or desired).
        policy_doc_map: dict mapping policy_name → JSON document string.
        all_resources: list of all cloud resource dicts (S3, EC2, etc.).

    Returns:
        List of EffectiveAccess-like dicts, each with keys:
            identity_id, identity_name, identity_type,
            target_resource_id, target_resource_name, target_resource_type,
            access_path (list of labels), through_relationship (list of labels),
            policy_names, policy_arns
    """
    result: List[Dict[str, Any]] = []

    # Pre-build maps for fast lookup
    group_policy_map = _build_group_policy_map(inventory.groups, policy_doc_map)
    role_policy_map = _build_role_policy_map(inventory.roles, policy_doc_map)
    account_id = _get_account_id(inventory)

    # ── Chain 1 & 2: Users via direct policies and group memberships ──────────
    for user in inventory.users:
        uname = user["name"]
        user_applicable_docs = get_effective_identity_policy_documents(user, policy_doc_map, inventory.groups)

        # Collect (policy_name, policy_arn, access_chain, rel_chain) tuples
        access_sources: List[Tuple[str, str, List[str], List[str]]] = []

        # 1a. Direct user policies
        for pname in user.get("policies", []):
            clean_name = pname.replace("[inline] ", "")
            doc = policy_doc_map.get(pname) or policy_doc_map.get(clean_name)
            if not doc:
                continue
            parn = (user.get("attachedPolicyArns") or {}).get(clean_name, "")
            access_sources.append((pname, parn, [uname, clean_name], ["HAS_POLICY", "ALLOWS"]))

        # 1b. Inline policy docs directly on user
        for in_label, in_doc in user.get("inlinePolicyDocuments", {}).items():
            access_sources.append((in_label, "", [uname, in_label], ["HAS_POLICY", "ALLOWS"]))

        # 2. Group memberships
        for gname in user.get("groups", []):
            group = _find_group(inventory.groups, gname)
            if not group:
                continue
            for pname, doc, parn in group_policy_map.get(gname, []):
                access_sources.append(
                    (pname, parn, [uname, gname, pname], ["MEMBER_OF", "HAS_POLICY", "ALLOWS"])
                )

        # Evaluate each source against all resources
        for pname, parn, chain, rel_chain in access_sources:
            doc = policy_doc_map.get(pname) or policy_doc_map.get(pname.replace("[inline] ", ""))
            if not doc:
                continue
            matched, prov_map, _ = evaluate_policy_allows_resources_with_provenance(
                policy_name=pname,
                policy_arn=parn,
                document=doc,
                resources=all_resources,
                principal=user,
                account_id=account_id
            )
            # 1. Deny precedence: remove any resource explicitly denied by ANY of user's applicable policies
            matched = [
                res for res in matched
                if not check_resource_explicitly_denied(user_applicable_docs, res, principal=user, account_id=account_id)
            ]
            # 2. Filter through Permissions Boundary if attached to user
            matched = _filter_by_permissions_boundary(user, matched, policy_doc_map, account_id)
            for res in matched:
                item_ident = res.get('id') if res.get('type') == 'EC2' else (res.get('name') or res.get('id'))
                prov = prov_map.get(str(item_ident), {})
                ev = {
                    "principal": uname,
                    "principal_type": "User",
                    "policy_arn": parn,
                    "policy_name": pname,
                    "statement_sid": prov.get("statement_sid", ""),
                    "effect": prov.get("effect", "Allow"),
                    "action": [prov.get("action", "*")],
                    "resource": [res.get("arn", "")],
                    "matched_action": prov.get("action", "*"),
                    "matched_resource": res.get("arn", ""),
                    "relationship_type": prov.get("relationship_type", "EFFECTIVE_ACCESS"),
                    "condition_status": prov.get("condition_status", "satisfied"),
                    "decision": prov.get("decision", "ALLOWED"),
                    "source": " -> ".join(rel_chain),
                    "region": res.get("region", ""),
                    "resource_arn": res.get("arn", ""),
                    "reason": prov.get("why") or f"Matched Allow statement in policy '{pname}'",
                }
                result.append(_build_record(
                    identity_id=_user_id(uname),
                    identity_name=uname,
                    identity_type="User",
                    resource=res,
                    chain=chain + [res.get("name", res.get("id", ""))],
                    rel_chain=rel_chain,
                    policy_names=[pname],
                    policy_arns=[parn] if parn else [],
                    evidence=ev,
                ))

    # ── Chain 3: Multi-hop role assumptions (User → Role* and Role → Role*) ─
    # First, build direct CAN_ASSUME adjacency maps using definitive verified trust
    user_direct_roles: Dict[str, List[str]] = {}  # uname -> [rname]
    role_direct_roles: Dict[str, List[str]] = {}  # rname -> [rname]

    for role in inventory.roles:
        rname = role["name"]
        trust_ev = evaluate_assume_role_trust_with_evidence(
            role.get("trustPolicy", "{}"),
            rname,
            role.get("arn", ""),
            inventory.users,
            inventory.roles,
            account_id,
            policy_doc_map,
            all_groups=inventory.groups,
        )

        for entry in trust_ev.get("users", []):
            if entry.get("evidence", {}).get("trust_status") != "definitive":
                continue
            if not entry.get("evidence", {}).get("call_permission_verified"):
                continue
            trusted_user = entry["principal"]
            user_direct_roles.setdefault(trusted_user["name"], []).append(rname)

        for entry in trust_ev.get("roles", []):
            if entry.get("evidence", {}).get("trust_status") != "definitive":
                continue
            if not entry.get("evidence", {}).get("call_permission_verified"):
                continue
            trusted_role = entry["principal"]
            role_direct_roles.setdefault(trusted_role["name"], []).append(rname)

    # 3a. Users assuming roles (multi-hop BFS)
    for user in inventory.users:
        uname = user["name"]
        initial_roles = user_direct_roles.get(uname, [])
        if not initial_roles:
            continue

        # Queue contains: (current_role_name, [role1, role2, ...])
        queue: List[Tuple[str, List[str]]] = [(r, [r]) for r in initial_roles]
        visited_chains = set()

        while queue:
            curr_role, role_chain = queue.pop(0)
            chain_key = tuple(role_chain)
            if chain_key in visited_chains:
                continue
            visited_chains.add(chain_key)

            # Evaluate effective access granted by curr_role (respecting curr_role's permissions boundary and Deny)
            curr_role_obj = _find_role(inventory.roles, curr_role)
            curr_role_principal = curr_role_obj or {"name": curr_role}
            role_applicable_docs = get_effective_identity_policy_documents(curr_role_principal, policy_doc_map)
            role_docs = role_policy_map.get(curr_role, [])
            for pname, doc, parn in role_docs:
                matched, prov_map, _ = evaluate_policy_allows_resources_with_provenance(
                    policy_name=pname,
                    policy_arn=parn,
                    document=doc,
                    resources=all_resources,
                    principal=curr_role_principal,
                    account_id=account_id
                )
                # 1. Deny precedence across role's applicable policies
                matched = [
                    res for res in matched
                    if not check_resource_explicitly_denied(role_applicable_docs, res, principal=curr_role_principal, account_id=account_id)
                ]
                # 2. Permissions boundary attached to the role
                if curr_role_obj:
                    matched = _filter_by_permissions_boundary(curr_role_obj, matched, policy_doc_map, account_id)
                for res in matched:
                    # Provenance: User -> RoleA -> RoleB -> Policy -> Resource
                    full_node_path = [uname] + role_chain + [pname, res.get("name", res.get("id", ""))]
                    rel_chain = (["CAN_ASSUME"] * len(role_chain)) + ["HAS_POLICY", "ALLOWS"]
                    item_ident = res.get('id') if res.get('type') == 'EC2' else (res.get('name') or res.get('id'))
                    prov = prov_map.get(str(item_ident), {})
                    ev = {
                        "principal": uname,
                        "principal_type": "User",
                        "policy_arn": parn,
                        "policy_name": pname,
                        "statement_sid": prov.get("statement_sid", ""),
                        "effect": prov.get("effect", "Allow"),
                        "action": [prov.get("action", "*")],
                        "resource": [res.get("arn", "")],
                        "matched_action": prov.get("action", "*"),
                        "matched_resource": res.get("arn", ""),
                        "relationship_type": prov.get("relationship_type", "EFFECTIVE_ACCESS"),
                        "condition_status": prov.get("condition_status", "satisfied"),
                        "decision": prov.get("decision", "ALLOWED"),
                        "source": " -> ".join(rel_chain),
                        "region": res.get("region", ""),
                        "resource_arn": res.get("arn", ""),
                        "reason": prov.get("why") or f"Matched Allow statement in assumed role policy '{pname}'",
                    }
                    result.append(_build_record(
                        identity_id=_user_id(uname),
                        identity_name=uname,
                        identity_type="User",
                        resource=res,
                        chain=full_node_path,
                        rel_chain=rel_chain,
                        policy_names=[pname],
                        policy_arns=[parn] if parn else [],
                        evidence=ev,
                    ))

            # Expand next hops if depth < MAX_ROLE_HOPS
            if len(role_chain) < MAX_ROLE_HOPS:
                for next_role in role_direct_roles.get(curr_role, []):
                    # Cycle protection: role cannot reappear in the same assumption chain
                    if next_role not in role_chain:
                        queue.append((next_role, role_chain + [next_role]))

    # 3b. Roles assuming other roles (multi-hop BFS)
    for role in inventory.roles:
        rname = role["name"]
        initial_roles = role_direct_roles.get(rname, [])
        if not initial_roles:
            continue

        queue = [(r, [r]) for r in initial_roles]
        visited_chains = set()

        while queue:
            curr_role, role_chain = queue.pop(0)
            chain_key = tuple(role_chain)
            if chain_key in visited_chains:
                continue
            visited_chains.add(chain_key)

            curr_role_obj = _find_role(inventory.roles, curr_role)
            curr_role_principal = curr_role_obj or {"name": curr_role}
            role_applicable_docs = get_effective_identity_policy_documents(curr_role_principal, policy_doc_map)
            role_docs = role_policy_map.get(curr_role, [])
            for pname, doc, parn in role_docs:
                matched = evaluate_policy_allows_resources(doc, all_resources, principal=curr_role_principal, account_id=account_id)
                matched = [
                    res for res in matched
                    if not check_resource_explicitly_denied(role_applicable_docs, res, principal=curr_role_principal, account_id=account_id)
                ]
                if curr_role_obj:
                    matched = _filter_by_permissions_boundary(curr_role_obj, matched, policy_doc_map, account_id)
                for res in matched:
                    # Provenance: RoleA -> RoleB -> RoleC -> Policy -> Resource
                    full_node_path = [rname] + role_chain + [pname, res.get("name", res.get("id", ""))]
                    rel_chain = (["CAN_ASSUME"] * len(role_chain)) + ["HAS_POLICY", "ALLOWS"]
                    result.append(_build_record(
                        identity_id=_role_id(rname),
                        identity_name=rname,
                        identity_type="Role",
                        resource=res,
                        chain=full_node_path,
                        rel_chain=rel_chain,
                        policy_names=[pname],
                        policy_arns=[parn] if parn else [],
                    ))

            if len(role_chain) < MAX_ROLE_HOPS:
                for next_role in role_direct_roles.get(curr_role, []):
                    if next_role not in role_chain and next_role != rname:
                        queue.append((next_role, role_chain + [next_role]))

    # ── Chain 4: Roles directly ───────────────────────────────────────────────
    for role in inventory.roles:
        rname = role["name"]
        role_applicable_docs = get_effective_identity_policy_documents(role, policy_doc_map)
        for pname, doc, parn in role_policy_map.get(rname, []):
            matched, prov_map, _ = evaluate_policy_allows_resources_with_provenance(
                policy_name=pname,
                policy_arn=parn,
                document=doc,
                resources=all_resources,
                principal=role,
                account_id=account_id
            )
            matched = [
                res for res in matched
                if not check_resource_explicitly_denied(role_applicable_docs, res, principal=role, account_id=account_id)
            ]
            matched = _filter_by_permissions_boundary(role, matched, policy_doc_map, account_id)
            for res in matched:
                item_ident = res.get('id') if res.get('type') == 'EC2' else (res.get('name') or res.get('id'))
                prov = prov_map.get(str(item_ident), {})
                ev = {
                    "principal": rname,
                    "principal_type": "Role",
                    "policy_arn": parn,
                    "policy_name": pname,
                    "statement_sid": prov.get("statement_sid", ""),
                    "effect": prov.get("effect", "Allow"),
                    "action": [prov.get("action", "*")],
                    "resource": [res.get("arn", "")],
                    "matched_action": prov.get("action", "*"),
                    "matched_resource": res.get("arn", ""),
                    "relationship_type": prov.get("relationship_type", "EFFECTIVE_ACCESS"),
                    "condition_status": prov.get("condition_status", "satisfied"),
                    "decision": prov.get("decision", "ALLOWED"),
                    "source": "HAS_POLICY -> ALLOWS",
                    "region": res.get("region", ""),
                    "resource_arn": res.get("arn", ""),
                    "reason": prov.get("why") or f"Matched Allow statement in role policy '{pname}'",
                }
                result.append(_build_record(
                    identity_id=_role_id(rname),
                    identity_name=rname,
                    identity_type="Role",
                    resource=res,
                    chain=[rname, pname, res.get("name", res.get("id", ""))],
                    rel_chain=["HAS_POLICY", "ALLOWS"],
                    policy_names=[pname],
                    policy_arns=[parn] if parn else [],
                    evidence=ev,
                ))

    logger.info(f"Effective access computed: {len(result)} access records")
    return result


def compute_reachable_resources(
    inventory: Any,
    policy_doc_map: Dict[str, str],
    all_resources: List[Dict[str, Any]],
) -> Dict[str, set]:
    """Return a mapping of identity_name → set of reachable resource IDs.

    Used for diff comparison between current and desired states.
    """
    access_records = compute_effective_access(inventory, policy_doc_map, all_resources)
    reach: Dict[str, set] = {}
    for rec in access_records:
        key = f"{rec['identity_type']}:{rec['identity_name']}"
        reach.setdefault(key, set()).add(rec["target_resource_id"])
    return reach


# ─── Private helpers ────────────────────────────────────────────────────────

def _build_record(
    identity_id: str,
    identity_name: str,
    identity_type: str,
    resource: Dict[str, Any],
    chain: List[str],
    rel_chain: List[str],
    policy_names: List[str],
    policy_arns: List[str],
    evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    rname = resource.get("name") or resource.get("id", "")
    rid = resource.get("id") or resource.get("name", "")
    r_arn = resource.get("arn", rid)
    r_type = resource.get("type", "")

    ev = evidence or {
        "principal": identity_name,
        "principal_type": identity_type,
        "policy_arn": policy_arns[0] if policy_arns else "",
        "policy_name": policy_names[0] if policy_names else "",
        "statement_sid": "",
        "effect": "Allow",
        "action": [f"{r_type.lower()}:*"],
        "resource": [r_arn],
        "matched_action": f"{r_type.lower()}:*",
        "matched_resource": r_arn,
        "condition_status": "satisfied",
        "decision": "ALLOWED",
        "source": " -> ".join(rel_chain),
        "region": resource.get("region", ""),
        "resource_arn": r_arn,
        "reason": f"Matched Allow statement in policy '{policy_names[0] if policy_names else 'unknown'}'",
    }

    return {
        "identity_id": identity_id,
        "identity_name": identity_name,
        "identity_type": identity_type,
        "target_resource_id": rid,
        "target_resource_name": rname,
        "target_resource_type": r_type,
        "access_path": chain,
        "through_relationship": rel_chain,
        "policy_names": policy_names,
        "policy_arns": policy_arns,
        "evidence": ev,
    }


def explain_principal_access(
    principal_name: str,
    target_resource_id_or_arn: str,
    inventory: Any,
    policy_doc_map: Dict[str, str],
    target_action: Optional[str] = None,
) -> Dict[str, Any]:
    """Authoritatively explain why an IAM principal has or does not have access.

    Returns structured evidence answering:
        "WHY DOES THIS PRINCIPAL HAVE ACCESS?"
    """
    all_res = list(
        getattr(inventory, "s3", []) + getattr(inventory, "secrets", []) +
        getattr(inventory, "rds", []) + getattr(inventory, "dynamodb", []) +
        getattr(inventory, "ec2", []) + getattr(inventory, "lambdas", [])
    )
    target_clean = str(target_resource_id_or_arn).strip().lower()
    known_ids = {
        str(r.get("id", "")).lower() for r in all_res
    } | {
        str(r.get("name", "")).lower() for r in all_res
    } | {
        str(r.get("arn", "")).lower() for r in all_res
    }

    if target_clean and target_clean not in known_ids:
        res_type = "S3"
        if ":ec2:" in target_clean or target_clean.startswith("i-"):
            res_type = "EC2"
        elif ":lambda:" in target_clean:
            res_type = "Lambda"
        elif ":rds:" in target_clean or ":cluster:" in target_clean or ":db:" in target_clean:
            res_type = "RDS"
        elif ":dynamodb:" in target_clean:
            res_type = "DynamoDB"
        elif ":secretsmanager:" in target_clean:
            res_type = "Secrets"
        all_res.append({
            "id": target_resource_id_or_arn,
            "name": target_resource_id_or_arn.split(":")[-1].split("/")[-1],
            "arn": target_resource_id_or_arn,
            "type": res_type
        })

    records = compute_effective_access(inventory, policy_doc_map, all_res)

    target_clean = str(target_resource_id_or_arn).strip().lower()
    for rec in records:
        if rec["identity_name"].lower() == principal_name.lower():
            rid = str(rec["target_resource_id"]).lower()
            rname = str(rec["target_resource_name"]).lower()
            rarn = str(rec.get("evidence", {}).get("resource_arn", "")).lower()
            if target_clean in (rid, rname, rarn) or (rarn and target_clean == rarn):
                ev = rec.get("evidence", {})
                return {
                    "principal": rec["identity_name"],
                    "principal_type": rec["identity_type"],
                    "policy": rec["policy_names"][0] if rec["policy_names"] else "",
                    "policy_arn": rec["policy_arns"][0] if rec["policy_arns"] else "",
                    "statement_sid": ev.get("statement_sid", ""),
                    "action": target_action or ev.get("matched_action", "*"),
                    "resource": ev.get("matched_resource") or target_resource_id_or_arn,
                    "decision": "ALLOWED",
                    "reason": ev.get("reason", "Matched Allow statement"),
                    "access_path": rec["access_path"],
                    "through_relationship": rec["through_relationship"],
                    "evidence": ev,
                }

    # If no effective access found, determine why (e.g. denied or not applicable)
    return {
        "principal": principal_name,
        "policy": "",
        "action": target_action or "*",
        "resource": target_resource_id_or_arn,
        "decision": "DENIED",
        "reason": "No effective Allow statement grants access (implicit deny or blocked by boundary/explicit deny)",
        "evidence": {
            "principal": principal_name,
            "decision": "DENIED",
            "reason": "No matching Allow statement found across applicable policies",
        }
    }


def _build_group_policy_map(
    groups: List[dict], policy_doc_map: Dict[str, str]
) -> Dict[str, List[Tuple[str, str, str]]]:
    """Returns: { group_name: [(policy_name, doc, policy_arn)] }"""
    result: Dict[str, List[Tuple[str, str, str]]] = {}
    for g in groups:
        gname = g["name"]
        entries = []
        for pname in g.get("attachedPolicies", []):
            clean = pname.replace("[inline] ", "")
            doc = policy_doc_map.get(pname) or policy_doc_map.get(clean, "")
            parn = (g.get("attachedPolicyArns") or {}).get(clean, "")
            if doc:
                entries.append((pname, doc, parn))
        for in_label, in_doc in g.get("inlinePolicyDocuments", {}).items():
            entries.append((in_label, in_doc, ""))
        result[gname] = entries
    return result


def _build_role_policy_map(
    roles: List[dict], policy_doc_map: Dict[str, str]
) -> Dict[str, List[Tuple[str, str, str]]]:
    """Returns: { role_name: [(policy_name, doc, policy_arn)] }"""
    result: Dict[str, List[Tuple[str, str, str]]] = {}
    for r in roles:
        rname = r["name"]
        entries = []
        for pname in r.get("attachedPolicies", []):
            clean = pname.replace("[inline] ", "")
            doc = policy_doc_map.get(pname) or policy_doc_map.get(clean, "")
            parn = (r.get("attachedPolicyArns") or {}).get(clean, "")
            if doc:
                entries.append((pname, doc, parn))
        for in_label, in_doc in r.get("inlinePolicyDocuments", {}).items():
            entries.append((in_label, in_doc, ""))
        result[rname] = entries
    return result


def _find_group(groups: List[dict], name: str) -> dict | None:
    for g in groups:
        if g["name"] == name:
            return g
    return None


def _find_role(roles: List[dict], name: str) -> dict | None:
    for r in roles:
        if r.get("name") == name or r.get("arn", "").endswith(f"/{name}"):
            return r
    return None


def _filter_by_permissions_boundary(
    principal: Dict[str, Any],
    matched_resources: List[Dict[str, Any]],
    policy_doc_map: Dict[str, str],
    account_id: str,
) -> List[Dict[str, Any]]:
    """Filter resources by principal's permissions boundary.

    AWS authorization semantics:
    effective permissions = identity/group permissions INTERSECT permissions boundary
    subject to explicit Deny precedence.

    - If principal has no boundary attached: returns matched_resources unmodified.
    - If boundary document is unavailable/unresolved: returns [] (cannot prove Allow).
    - If boundary document exists: evaluates boundary document against matched_resources;
      only resources that boundary explicitly Allows and does NOT explicitly Deny are returned.
    """
    if not matched_resources:
        return []

    boundary_arn = principal.get("permissionsBoundary")
    if not boundary_arn:
        return matched_resources

    clean_bname = boundary_arn.split("/")[-1] if "/" in boundary_arn else boundary_arn
    b_doc = policy_doc_map.get(boundary_arn) or policy_doc_map.get(clean_bname)
    if not b_doc:
        logger.warning(
            f"Permissions boundary {boundary_arn} attached to {principal.get('name')} "
            f"could not be resolved; denying resource access."
        )
        return []

    return evaluate_policy_allows_resources(
        b_doc, matched_resources, principal=principal, account_id=account_id
    )



def _user_id(name: str) -> str:
    return f"aws:user:{name}"


def _role_id(name: str) -> str:
    return f"aws:role:{name}"


def _get_account_id(inventory: Any) -> str:
    for u in getattr(inventory, "users", []):
        owner = u.get("owner", "")
        if owner:
            return owner
    return ""
