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
from typing import Any, Dict, List, Tuple

from app.services.attack.policy_evaluator import (
    evaluate_policy_allows_resources,
    evaluate_assume_role_trust,
    evaluate_assume_role_trust_with_evidence,
)

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
            matched = evaluate_policy_allows_resources(doc, all_resources)
            for res in matched:
                result.append(_build_record(
                    identity_id=_user_id(uname),
                    identity_name=uname,
                    identity_type="User",
                    resource=res,
                    chain=chain + [res.get("name", res.get("id", ""))],
                    rel_chain=rel_chain,
                    policy_names=[pname],
                    policy_arns=[parn] if parn else [],
                ))

    # ── Chain 3: Users via CAN_ASSUME → Role ─────────────────────────────────
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
        )

        role_docs = role_policy_map.get(rname, [])  # [(pname, doc, parn)]

        for entry in trust_ev.get("users", []):
            if not entry.get("evidence", {}).get("call_permission_verified"):
                continue
            trusted_user = entry["principal"]
            uname = trusted_user["name"]
            for pname, doc, parn in role_docs:
                matched = evaluate_policy_allows_resources(doc, all_resources)
                for res in matched:
                    result.append(_build_record(
                        identity_id=_user_id(uname),
                        identity_name=uname,
                        identity_type="User",
                        resource=res,
                        chain=[uname, rname, pname, res.get("name", res.get("id", ""))],
                        rel_chain=["CAN_ASSUME", "HAS_POLICY", "ALLOWS"],
                        policy_names=[pname],
                        policy_arns=[parn] if parn else [],
                    ))

        # Also role→role trust chains (one level)
        for entry in trust_ev.get("roles", []):
            if not entry.get("evidence", {}).get("call_permission_verified"):
                continue
            trusted_role = entry["principal"]
            tr_name = trusted_role["name"]
            for pname, doc, parn in role_docs:
                matched = evaluate_policy_allows_resources(doc, all_resources)
                for res in matched:
                    result.append(_build_record(
                        identity_id=_role_id(tr_name),
                        identity_name=tr_name,
                        identity_type="Role",
                        resource=res,
                        chain=[tr_name, rname, pname, res.get("name", res.get("id", ""))],
                        rel_chain=["CAN_ASSUME", "HAS_POLICY", "ALLOWS"],
                        policy_names=[pname],
                        policy_arns=[parn] if parn else [],
                    ))

    # ── Chain 4: Roles directly ───────────────────────────────────────────────
    for role in inventory.roles:
        rname = role["name"]
        for pname, doc, parn in role_policy_map.get(rname, []):
            matched = evaluate_policy_allows_resources(doc, all_resources)
            for res in matched:
                result.append(_build_record(
                    identity_id=_role_id(rname),
                    identity_name=rname,
                    identity_type="Role",
                    resource=res,
                    chain=[rname, pname, res.get("name", res.get("id", ""))],
                    rel_chain=["HAS_POLICY", "ALLOWS"],
                    policy_names=[pname],
                    policy_arns=[parn] if parn else [],
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
) -> Dict[str, Any]:
    rname = resource.get("name") or resource.get("id", "")
    rid = resource.get("id") or resource.get("name", "")
    return {
        "identity_id": identity_id,
        "identity_name": identity_name,
        "identity_type": identity_type,
        "target_resource_id": rid,
        "target_resource_name": rname,
        "target_resource_type": resource.get("type", ""),
        "access_path": chain,
        "through_relationship": rel_chain,
        "policy_names": policy_names,
        "policy_arns": policy_arns,
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
