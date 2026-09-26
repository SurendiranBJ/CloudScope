"""
CloudScope Relationships Router.

GET  /api/v1/relationships              — full relationship model for current state
GET  /api/v1/relationships/{entity_id}  — relationships for a specific entity

Returns EXACT relationship labels from the backend model:
    MEMBER_OF, HAS_POLICY, CAN_ASSUME, ALLOWS, TRUSTS, ATTACHED_TO, EXECUTES_WITH

Never invents labels. All relationship labels are exact backend types.
"""

import logging
from fastapi import APIRouter, Query
from datetime import datetime
from typing import List, Optional, Tuple, Dict, Any

from app.schemas import APIResponse
from app.cache import cache
from app.services.attack.policy_evaluator import (
    evaluate_assume_role_trust_with_evidence,
    evaluate_policy_allows_resources,
)
from app.services.scanner.scan_manager import scan_manager

logger = logging.getLogger("scanner")
router = APIRouter(tags=["Relationships"])


def _build_raw_relationships(
    users: List[dict],
    roles: List[dict],
    policies: List[dict],
    groups: List[dict],
    resources: List[dict],
) -> List[dict]:
    """Build authoritative relationships without deduplication or filtering."""
    relationships = []

    # Map groups to their policies from authoritative scanned groups inventory
    group_map: Dict[str, List[str]] = {}
    if groups:
        for g in groups:
            gname = g.get("name")
            if gname:
                pols = g.get("attachedPolicies", []) or g.get("policies", []) or []
                group_map[gname] = list(pols)
    else:
        # Fallback to embedded user group names without fabricating policies
        for u in users:
            for gname in u.get("groups", []):
                if gname not in group_map:
                    group_map[gname] = []

    # 1. User MEMBER_OF Group
    for u in users:
        for gname in u.get("groups", []):
            relationships.append({
                "source_id": f"aws:user:{u['name']}",
                "source_label": u["name"],
                "source_type": "User",
                "relationship": "MEMBER_OF",
                "target_id": f"aws:group:{gname}",
                "target_label": gname,
                "target_type": "Group",
            })

    # 2. User HAS_POLICY (direct + inline)
    for u in users:
        u_pols = u.get("policies", []) + u.get("attachedPolicies", [])
        for pname in u_pols:
            clean = pname.replace("[inline] ", "")
            relationships.append({
                "source_id": f"aws:user:{u['name']}",
                "source_label": u["name"],
                "source_type": "User",
                "relationship": "HAS_POLICY",
                "target_id": f"aws:policy:{clean}",
                "target_label": clean,
                "target_type": "Policy",
            })

    # 3. Group HAS_POLICY (from authoritative scanned evidence)
    for gname, pols in group_map.items():
        for pname in pols:
            clean = pname.replace("[inline] ", "")
            relationships.append({
                "source_id": f"aws:group:{gname}",
                "source_label": gname,
                "source_type": "Group",
                "relationship": "HAS_POLICY",
                "target_id": f"aws:policy:{clean}",
                "target_label": clean,
                "target_type": "Policy",
            })

    # 4. Role HAS_POLICY
    for r in roles:
        r_pols = r.get("attachedPolicies", []) + r.get("policies", [])
        for pname in r_pols:
            clean = pname.replace("[inline] ", "")
            relationships.append({
                "source_id": f"aws:role:{r['name']}",
                "source_label": r["name"],
                "source_type": "Role",
                "relationship": "HAS_POLICY",
                "target_id": f"aws:policy:{clean}",
                "target_label": clean,
                "target_type": "Policy",
            })

    # 5. CAN_ASSUME via trust policies
    account_id = _get_account_id(users)
    pol_doc_map = {p["name"]: p.get("document", "{}") for p in policies}
    cached_groups = groups if groups else [{"name": gn, "attachedPolicies": gp} for gn, gp in group_map.items()]

    for r in roles:
        trust_ev = evaluate_assume_role_trust_with_evidence(
            r.get("trustPolicy", "{}"),
            r["name"],
            r.get("arn", ""),
            users,
            roles,
            account_id,
            pol_doc_map,
            all_groups=cached_groups,
        )
        for tu_entry in trust_ev.get("users", []):
            if tu_entry.get("evidence", {}).get("trust_status") != "definitive":
                continue
            if not tu_entry.get("evidence", {}).get("call_permission_verified"):
                continue
            tu = tu_entry["principal"]
            relationships.append({
                "source_id": f"aws:user:{tu['name']}",
                "source_label": tu["name"],
                "source_type": "User",
                "relationship": "CAN_ASSUME",
                "target_id": f"aws:role:{r['name']}",
                "target_label": r["name"],
                "target_type": "Role",
            })
        for tr_entry in trust_ev.get("roles", []):
            if tr_entry.get("evidence", {}).get("trust_status") != "definitive":
                continue
            if not tr_entry.get("evidence", {}).get("call_permission_verified"):
                continue
            tr = tr_entry["principal"]
            relationships.append({
                "source_id": f"aws:role:{tr['name']}",
                "source_label": tr["name"],
                "source_type": "Role",
                "relationship": "CAN_ASSUME",
                "target_id": f"aws:role:{r['name']}",
                "target_label": r["name"],
                "target_type": "Role",
            })

    # 6. Policy ALLOWS Resource
    for p in policies:
        doc = p.get("document", "{}")
        if not doc or doc == "{}":
            continue
        allowed = evaluate_policy_allows_resources(doc, resources)
        for res in allowed:
            rname = res.get("name") or res.get("id", "")
            rtype = res.get("type", "Resource")
            relationships.append({
                "source_id": f"aws:policy:{p['name']}",
                "source_label": p["name"],
                "source_type": "Policy",
                "relationship": "ALLOWS",
                "target_id": f"aws:{rtype.lower()}:{rname}",
                "target_label": rname,
                "target_type": rtype,
            })

    return relationships


def _deduplicate_relationships(relationships: List[dict]) -> List[dict]:
    """Deduplicate relationships based on canonical tuple (source_id, relationship, target_id)."""
    seen = set()
    deduped = []
    for r in relationships:
        key = (r["source_id"], r["relationship"], r["target_id"])
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    return deduped


@router.get("/relationships", response_model=APIResponse[dict])
def get_all_relationships(
    entity_type: Optional[str] = Query(None, description="Filter by entity type: User | Group | Role | Policy"),
    search: Optional[str] = Query(None, description="Search by entity name"),
    limit: int = Query(1000, ge=1, le=5000),
):
    """Return the full relationship model for the current AWS state.

    Relationships are built from scanned inventory — not inferred.
    All relationship labels are exact backend types.
    """
    users = cache.get("v1:users")
    roles = cache.get("v1:roles")
    policies = cache.get("v1:policies")

    # If cache is cold after startup, trigger scan
    if users is None and roles is None and policies is None:
        if not scan_manager.is_running:
            scan_manager.trigger_async_scan()
        users = cache.get("v1:users")
        roles = cache.get("v1:roles")
        policies = cache.get("v1:policies")

    users = users or getattr(scan_manager.inventory, "users", []) or []
    roles = roles or getattr(scan_manager.inventory, "roles", []) or []
    policies = policies or getattr(scan_manager.inventory, "policies", []) or []
    groups = cache.get("v1:groups") or getattr(scan_manager.inventory, "groups", []) or []
    resources = cache.get("v1:resources") or getattr(scan_manager.inventory, "resources", []) or []

    # Build raw relationships
    raw_relationships = _build_raw_relationships(users, roles, policies, groups, resources)

    # Deduplicate by canonical tuple
    relationships = _deduplicate_relationships(raw_relationships)

    # Apply entity_type filter across source_type or target_type
    if entity_type:
        et = entity_type.strip().lower()
        singular = et[:-1] if et.endswith('s') and et not in ['secrets'] else et
        valid_types = {et, singular}
        relationships = [
            r for r in relationships
            if r["source_type"].lower() in valid_types or r["target_type"].lower() in valid_types
        ]

    # Apply search filter
    if search:
        q = search.strip().lower()
        relationships = [
            r for r in relationships
            if q in r["source_label"].lower() or q in r["target_label"].lower()
        ]

    relationships = relationships[:limit]

    # Calculate real entity counts
    group_count = len(groups)
    if group_count == 0:
        extracted = set()
        for u in users:
            for g in u.get("groups", []):
                extracted.add(g)
        group_count = len(extracted)

    return APIResponse(
        success=True,
        message=f"Relationships: {len(relationships)} records returned",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={
            "total": len(relationships),
            "relationships": relationships,
            "entity_counts": {
                "users": len(users),
                "roles": len(roles),
                "policies": len(policies),
                "groups": group_count,
                "resources": len(resources),
            },
        },
    )


@router.get("/relationships/{entity_id}", response_model=APIResponse[dict])
def get_entity_relationships(
    entity_id: str,
    direction: Optional[str] = Query("both", description="incoming | outgoing | both"),
):
    """Return all relationships for a specific entity (user/group/role/policy).

    entity_id can be canonical (aws:user:name, aws:role:name, aws:group:name, aws:policy:name)
    or type:name (User:name) or raw name.
    """
    users = cache.get("v1:users") or getattr(scan_manager.inventory, "users", []) or []
    roles = cache.get("v1:roles") or getattr(scan_manager.inventory, "roles", []) or []
    policies = cache.get("v1:policies") or getattr(scan_manager.inventory, "policies", []) or []
    groups = cache.get("v1:groups") or getattr(scan_manager.inventory, "groups", []) or []
    resources = cache.get("v1:resources") or getattr(scan_manager.inventory, "resources", []) or []

    # Parse entity ID cleanly
    if entity_id.startswith("aws:"):
        sub = entity_id[4:]
        sub_parts = sub.split(":", 1)
        if len(sub_parts) == 2:
            raw_type, entity_name = sub_parts[0], sub_parts[1]
            type_map = {
                "user": "User", "role": "Role", "group": "Group", "policy": "Policy",
                "s3": "S3", "ec2": "EC2", "lambda": "Lambda", "rds": "RDS",
                "dynamodb": "DynamoDB", "secrets": "Secrets"
            }
            entity_type = type_map.get(raw_type.lower(), raw_type.capitalize())
        else:
            entity_name = sub
            entity_type = _infer_entity_type(entity_name, users, roles, policies, groups)
    elif ":" in entity_id:
        parts = entity_id.split(":", 1)
        entity_type, entity_name = parts[0], parts[1]
    else:
        entity_name = entity_id
        entity_type = _infer_entity_type(entity_name, users, roles, policies, groups)

    entity_node_id = f"aws:{entity_type.lower()}:{entity_name}"

    # Build authoritative relationships directly
    all_rels = _deduplicate_relationships(
        _build_raw_relationships(users, roles, policies, groups, resources)
    )

    outgoing = [
        r for r in all_rels
        if r["source_id"] == entity_node_id or (r["source_type"].lower() == entity_type.lower() and r["source_label"] == entity_name)
    ]
    incoming = [
        r for r in all_rels
        if r["target_id"] == entity_node_id or (r["target_type"].lower() == entity_type.lower() and r["target_label"] == entity_name)
    ]

    if direction == "outgoing":
        filtered = outgoing
    elif direction == "incoming":
        filtered = incoming
    else:
        filtered = _deduplicate_relationships(outgoing + incoming)

    # Build access provenance for this entity
    provenance = _build_provenance(entity_name, entity_type, users, roles, policies, groups, resources)

    return APIResponse(
        success=True,
        message=f"Relationships for {entity_type} '{entity_name}'",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={
            "entity_id": entity_node_id,
            "entity_name": entity_name,
            "entity_type": entity_type,
            "relationships": filtered,
            "outgoing_count": len(outgoing),
            "incoming_count": len(incoming),
            "provenance": provenance,
        },
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_account_id(users: List[dict]) -> str:
    for u in users:
        owner = u.get("owner", "")
        if owner:
            return owner
    return ""


def _infer_entity_type(name: str, users: list, roles: list, policies: list, groups: list) -> str:
    for u in users:
        if u.get("name") == name:
            return "User"
    for r in roles:
        if r.get("name") == name:
            return "Role"
    for g in groups:
        if g.get("name") == name:
            return "Group"
    for p in policies:
        if p.get("name") == name:
            return "Policy"
    return "Unknown"


def _get_group_policies(gname: str, groups: List[dict]) -> List[str]:
    """Extract policies for a group from authoritative group inventory."""
    for g in groups:
        if g.get("name") == gname:
            return list(g.get("attachedPolicies", []) or g.get("policies", []) or [])
    return []


def _build_provenance(
    entity_name: str,
    entity_type: str,
    users: List[dict],
    roles: List[dict],
    policies: List[dict],
    groups: List[dict],
    resources: List[dict],
) -> List[dict]:
    """Build access provenance chains for an entity using real scanned data."""
    chains = []

    if entity_type == "User":
        user = next((u for u in users if u.get("name") == entity_name), None)
        if not user:
            return chains

        # Direct policy chains
        user_pols = user.get("policies", []) + user.get("attachedPolicies", [])
        for pname in user_pols:
            clean = pname.replace("[inline] ", "")
            pol = next((p for p in policies if p.get("name") == clean or p.get("name") == pname), None)
            if pol:
                doc = pol.get("document", "{}")
                allowed = evaluate_policy_allows_resources(doc, resources)
                for res in allowed:
                    rname = res.get("name") or res.get("id", "")
                    chains.append({
                        "chain": [entity_name, clean, rname],
                        "relationships": ["HAS_POLICY", "ALLOWS"],
                    })

        # Group chains
        for gname in user.get("groups", []):
            group_pols = _get_group_policies(gname, groups)
            for pname in group_pols:
                clean = pname.replace("[inline] ", "")
                pol = next((p for p in policies if p.get("name") == clean or p.get("name") == pname), None)
                if pol:
                    doc = pol.get("document", "{}")
                    allowed = evaluate_policy_allows_resources(doc, resources)
                    for res in allowed:
                        rname = res.get("name") or res.get("id", "")
                        chains.append({
                            "chain": [entity_name, gname, clean, rname],
                            "relationships": ["MEMBER_OF", "HAS_POLICY", "ALLOWS"],
                        })

    return chains[:50]  # Cap provenance chains for performance
