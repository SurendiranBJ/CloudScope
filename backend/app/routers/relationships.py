"""
CloudScope Relationships Router.

GET  /api/v1/relationships              — full relationship model for current state
GET  /api/v1/relationships/{entity_id}  — relationships for a specific entity

Returns EXACT relationship labels from the backend model:
    MEMBER_OF, HAS_POLICY, CAN_ASSUME, ALLOWS, TRUSTS, ATTACHED_TO, EXECUTES_WITH

Never invents labels. Uses UNKNOWN when label cannot be determined.
"""

import logging
from fastapi import APIRouter, Query
from datetime import datetime
from typing import List, Optional

from app.schemas import APIResponse
from app.cache import cache
from app.services.attack.policy_evaluator import (
    evaluate_assume_role_trust,
    evaluate_assume_role_trust_with_evidence,
)

logger = logging.getLogger("scanner")
router = APIRouter(tags=["Relationships"])


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
    users = cache.get("v1:users") or []
    roles = cache.get("v1:roles") or []
    policies = cache.get("v1:policies") or []

    # Groups come embedded in users
    groups = _extract_groups_from_users(users)

    relationships = []

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

    # 2. User HAS_POLICY (direct)
    for u in users:
        for pname in u.get("policies", []):
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

    # 3. Group HAS_POLICY
    for gname, pols in groups.items():
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
        for pname in r.get("attachedPolicies", []):
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
    cached_groups = cache.get("v1:groups") or groups
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

    # 6. Policy ALLOWS Resource (from cached graph edges)
    resources = cache.get("v1:resources") or []
    from app.services.attack.policy_evaluator import evaluate_policy_allows_resources
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

    # Apply filters
    if entity_type:
        et = entity_type.lower()
        relationships = [
            r for r in relationships
            if r["source_type"].lower() == et or r["target_type"].lower() == et
        ]
    if search:
        q = search.lower()
        relationships = [
            r for r in relationships
            if q in r["source_label"].lower() or q in r["target_label"].lower()
        ]

    relationships = relationships[:limit]

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
                "groups": len(groups),
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

    entity_id should be: type:name (e.g. User:alice or Role:AdminRole)
    """
    users = cache.get("v1:users") or []
    roles = cache.get("v1:roles") or []
    policies = cache.get("v1:policies") or []

    # Parse entity
    parts = entity_id.split(":", 1)
    if len(parts) == 2:
        entity_type, entity_name = parts[0], parts[1]
    else:
        entity_name = entity_id
        entity_type = _infer_entity_type(entity_name, users, roles, policies)

    # Get all relationships and filter for this entity
    from fastapi.testclient import TestClient
    all_rel_response = get_all_relationships(search=entity_name)
    all_rels = all_rel_response.data.get("relationships", [])

    entity_node_id = f"aws:{entity_type.lower()}:{entity_name}"

    outgoing = [r for r in all_rels if r["source_id"] == entity_node_id]
    incoming = [r for r in all_rels if r["target_id"] == entity_node_id]

    if direction == "outgoing":
        filtered = outgoing
    elif direction == "incoming":
        filtered = incoming
    else:
        filtered = outgoing + incoming

    # Build access provenance for this entity
    provenance = _build_provenance(entity_name, entity_type, users, roles, policies)

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

def _extract_groups_from_users(users: List[dict]) -> dict:
    """Extract group→policies mapping from user data."""
    groups = {}
    for u in users:
        for g in u.get("groups", []):
            if g not in groups:
                groups[g] = []
    return groups


def _get_account_id(users: List[dict]) -> str:
    for u in users:
        owner = u.get("owner", "")
        if owner:
            return owner
    return ""


def _infer_entity_type(name: str, users, roles, policies) -> str:
    for u in users:
        if u.get("name") == name:
            return "User"
    for r in roles:
        if r.get("name") == name:
            return "Role"
    for p in policies:
        if p.get("name") == name:
            return "Policy"
    return "Unknown"


def _build_provenance(entity_name: str, entity_type: str, users, roles, policies) -> List[dict]:
    """Build access provenance chains for an entity."""
    chains = []
    resources = cache.get("v1:resources") or []
    from app.services.attack.policy_evaluator import evaluate_policy_allows_resources

    if entity_type == "User":
        user = next((u for u in users if u["name"] == entity_name), None)
        if not user:
            return chains

        # Direct policy chains
        for pname in user.get("policies", []):
            clean = pname.replace("[inline] ", "")
            pol = next((p for p in policies if p["name"] == clean), None)
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
            group_pols = _get_group_policies(gname, users)
            for pname in group_pols:
                clean = pname.replace("[inline] ", "")
                pol = next((p for p in policies if p["name"] == clean), None)
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


def _get_group_policies(gname: str, users: List[dict]) -> List[str]:
    """Extract policies for a group from user data."""
    # Groups are discovered as user membership — need to look them up
    # This is approximate; real group policies come from IAM group scan
    return []
