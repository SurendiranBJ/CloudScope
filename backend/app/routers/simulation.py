"""
CloudScope Simulation Router.

Endpoints:
    GET    /api/v1/simulation/state          — current pending simulation changes
    POST   /api/v1/simulation/changes        — add a simulation change
    DELETE /api/v1/simulation/changes/{id}   — remove one change
    POST   /api/v1/simulation/reset          — clear all changes
    POST   /api/v1/simulation/preview        — preview impact WITHOUT persisting
    GET    /api/v1/simulation/diff           — graph diff: current vs desired
    GET    /api/v1/simulation/risk           — risk comparison: current vs desired
    GET    /api/v1/simulation/attack-paths   — attack path comparison
    GET    /api/v1/simulation/blast-radius   — blast radius comparison

SIMULATION SAFETY:
    - NO AWS IAM mutation APIs are called anywhere in this module.
    - All changes are application-side only.
    - Neo4j is never written during simulation.
"""

import logging
from fastapi import APIRouter, HTTPException
from datetime import datetime
from typing import List

from app.schemas import (
    APIResponse,
    SimulationChangeRequest,
    SimulationPreviewRequest,
)
from app.cache import cache
from app.services.simulation.simulation_state import simulation_state
from app.services.simulation.simulation_analyzer import (
    build_desired_analysis,
    build_policy_preview_analysis,
)
from app.services.scanner.scan_manager import scan_manager

logger = logging.getLogger("scanner")
router = APIRouter(tags=["Simulation"])


def _get_current_inventory():
    """Return current inventory from scan_manager or raise if unavailable."""
    inv = scan_manager.inventory
    if not inv or (not inv.users and not inv.roles and not inv.policies):
        return None
    return inv


def _get_policy_doc_map() -> dict:
    """Build policy document map from cached current-state policies."""
    policies = cache.get("v1:policies") or []
    doc_map = {}
    for p in policies:
        doc = p.get("document")
        if doc and doc != "{}":
            doc_map[p["name"]] = doc
    return doc_map


def _build_analysis():
    """Run full desired-state analysis."""
    inv = _get_current_inventory()
    if not inv:
        return None, "No scan data available. Run a scan first."

    policy_doc_map = _get_policy_doc_map()
    current_attack_paths = cache.get("v1:attack-paths") or []
    current_global_posture = cache.get("v1:global_posture")

    # Build desired inventory
    desired_inv = simulation_state.get_desired_inventory(inv)

    # Ensure policy documents are available for newly simulated policies
    desired_doc_map = dict(policy_doc_map)
    _enrich_desired_policy_docs(desired_inv, desired_doc_map)

    analysis = build_desired_analysis(
        desired_inventory=desired_inv,
        desired_policy_doc_map=desired_doc_map,
        current_inventory=inv,
        current_policy_doc_map=policy_doc_map,
        current_attack_paths=current_attack_paths,
        current_global_posture=current_global_posture,
    )
    return analysis, None


def _enrich_desired_policy_docs(desired_inv, doc_map: dict):
    """Fetch missing policy documents for any policies added by simulation."""
    for p in desired_inv.policies:
        if p.get("name") and p.get("name") not in doc_map:
            arn = p.get("arn", "")
            if arn:
                cached = cache.get(f"v1:policy_doc:{arn}")
                if cached:
                    doc_map[p["name"]] = cached
                else:
                    try:
                        from app.services.aws.iam_service import fetch_policy_document_by_arn
                        fetched = fetch_policy_document_by_arn(arn)
                        if fetched:
                            doc_map[fetched["name"]] = fetched["document"]
                            cache.set(f"v1:policy_doc:{arn}", fetched["document"])
                    except Exception as e:
                        logger.warning(f"Could not fetch policy doc for {arn}: {e}")


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/simulation/state", response_model=APIResponse[dict])
def get_simulation_state():
    """Return the current list of pending simulation changes."""
    changes = simulation_state.get_changes()
    return APIResponse(
        success=True,
        message=f"Simulation state: {len(changes)} pending change(s). "
                "SIMULATION ONLY — NOT APPLIED TO AWS.",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={
            "simulation_active": simulation_state.has_changes(),
            "pending_changes": len(changes),
            "changes": changes,
        },
    )


@router.post("/simulation/changes", response_model=APIResponse[dict])
def add_simulation_change(body: SimulationChangeRequest):
    """Add a pending simulation change (ATTACH_POLICY or DETACH_POLICY).

    This does NOT modify AWS. This does NOT modify Neo4j.
    Changes are stored in application memory only.
    """
    action = body.action.upper()
    if action not in {"ATTACH_POLICY", "DETACH_POLICY"}:
        raise HTTPException(status_code=400, detail=f"Unsupported action: {action}")

    ptype = body.principal_type.upper()
    if ptype not in {"USER", "GROUP", "ROLE"}:
        raise HTTPException(status_code=400, detail=f"Unsupported principal_type: {ptype}")

    # Resolve policy name from catalog
    policy_name = _resolve_policy_name(body.policy_arn)

    try:
        if action == "ATTACH_POLICY":
            change = simulation_state.attach_policy(
                ptype, body.principal_id, body.policy_arn, policy_name
            )
        else:
            change = simulation_state.detach_policy(
                ptype, body.principal_id, body.policy_arn, policy_name
            )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return APIResponse(
        success=True,
        message=f"Simulation change added: {action} '{policy_name}' to {ptype} '{body.principal_id}'. "
                "SIMULATION ONLY — NOT APPLIED TO AWS.",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=change.to_dict(),
    )


@router.delete("/simulation/changes/{change_id}", response_model=APIResponse[dict])
def remove_simulation_change(change_id: str):
    """Remove a single pending simulation change by ID."""
    removed = simulation_state.remove_change(change_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Change '{change_id}' not found")
    return APIResponse(
        success=True,
        message=f"Simulation change '{change_id}' removed.",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={"change_id": change_id, "removed": True},
    )


@router.post("/simulation/reset", response_model=APIResponse[dict])
def reset_simulation():
    """Clear all pending simulation changes. Returns to real AWS current state."""
    count = simulation_state.change_count()
    simulation_state.reset()
    return APIResponse(
        success=True,
        message=f"Simulation reset: {count} change(s) cleared. "
                "Application now reflects real AWS current state.",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={"cleared_changes": count, "simulation_active": False},
    )


@router.post("/simulation/preview", response_model=APIResponse[dict])
def preview_simulation_change(body: SimulationPreviewRequest):
    """Preview the security impact of a proposed change WITHOUT persisting it.

    Returns risk comparison, new reachable resources, new attack paths, etc.
    The change is NOT saved — this is purely analytical.
    """
    inv = _get_current_inventory()
    if not inv:
        raise HTTPException(status_code=503, detail="No scan data available. Run a scan first.")

    policy_doc_map = _get_policy_doc_map()
    current_attack_paths = cache.get("v1:attack-paths") or []
    current_global_posture = cache.get("v1:global_posture")

    proposed_change = {
        "action": body.action.upper(),
        "principal_type": body.principal_type.upper(),
        "principal_id": body.principal_id,
        "policy_arn": body.policy_arn,
    }

    analysis = build_policy_preview_analysis(
        proposed_change=proposed_change,
        current_inventory=inv,
        current_policy_doc_map=policy_doc_map,
        current_attack_paths=current_attack_paths,
        current_global_posture=current_global_posture,
    )

    return APIResponse(
        success=True,
        message="Preview analysis complete. This is a simulation — no AWS changes made.",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={
            **analysis,
            "simulation_note": "This is a simulation. No changes will be applied to AWS.",
        },
    )


@router.get("/simulation/diff", response_model=APIResponse[dict])
def get_simulation_diff():
    """Return the graph diff between current and desired state."""
    if not simulation_state.has_changes():
        return APIResponse(
            success=True,
            message="No simulation active.",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data={"simulation_active": False, "graph_diff": None},
        )

    analysis, err = _build_analysis()
    if err:
        raise HTTPException(status_code=503, detail=err)

    return APIResponse(
        success=True,
        message="Graph diff: current vs desired state",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={
            "simulation_active": True,
            "pending_changes": simulation_state.change_count(),
            "graph_diff": analysis.get("graph_diff"),
        },
    )


@router.get("/simulation/risk", response_model=APIResponse[dict])
def get_simulation_risk():
    """Return risk comparison between current and desired state."""
    if not simulation_state.has_changes():
        posture = cache.get("v1:global_posture") or {}
        score = posture.get("overall_score", 0)
        return APIResponse(
            success=True,
            message="No simulation active.",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data={
                "simulation_active": False,
                "current_score": score,
                "desired_score": score,
                "delta": 0,
            },
        )

    analysis, err = _build_analysis()
    if err:
        raise HTTPException(status_code=503, detail=err)

    return APIResponse(
        success=True,
        message="Risk comparison: current vs desired",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={
            "simulation_active": True,
            "pending_changes": simulation_state.change_count(),
            **analysis.get("risk_comparison", {}),
        },
    )


@router.get("/simulation/attack-paths", response_model=APIResponse[dict])
def get_simulation_attack_paths():
    """Return attack path comparison between current and desired state."""
    if not simulation_state.has_changes():
        current_paths = cache.get("v1:attack-paths") or []
        return APIResponse(
            success=True,
            message="No simulation active.",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data={
                "simulation_active": False,
                "current_paths": current_paths,
                "new_paths": [],
                "removed_paths": [],
                "unchanged_paths": current_paths,
                "changed_paths": [],
            },
        )

    analysis, err = _build_analysis()
    if err:
        raise HTTPException(status_code=503, detail=err)

    return APIResponse(
        success=True,
        message="Attack path comparison: current vs desired",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={
            "simulation_active": True,
            "pending_changes": simulation_state.change_count(),
            "current_paths": cache.get("v1:attack-paths") or [],
            **analysis.get("attack_path_comparison", {}),
        },
    )


@router.get("/simulation/blast-radius", response_model=APIResponse[dict])
def get_simulation_blast_radius():
    """Return blast radius comparison between current and desired state."""
    if not simulation_state.has_changes():
        return APIResponse(
            success=True,
            message="No simulation active.",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data={"simulation_active": False},
        )

    analysis, err = _build_analysis()
    if err:
        raise HTTPException(status_code=503, detail=err)

    return APIResponse(
        success=True,
        message="Blast radius comparison: current vs desired",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={
            "simulation_active": True,
            "pending_changes": simulation_state.change_count(),
            **analysis.get("blast_radius_comparison", {}),
        },
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _resolve_policy_name(policy_arn: str) -> str:
    """Try to resolve a policy name from ARN using cached catalog."""
    if "/" in policy_arn:
        name = policy_arn.split("/")[-1]
    else:
        name = policy_arn

    # Check catalog for canonical name
    catalog = cache.get("v1:policy_catalog") or []
    for p in catalog:
        if p.get("arn") == policy_arn:
            return p.get("name", name)
    return name
