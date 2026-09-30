from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional, Dict, Any
from datetime import datetime
from app.schemas import APIResponse, AttackPath
from app.services.scanner.scan_manager import scan_manager
from app.services.scanner.current_snapshot import (
    get_current_attack_paths,
    get_current_snapshot_id,
    get_current_snapshot_published_at,
    has_published_snapshot,
)
from app.security.dependencies import require_viewer

router = APIRouter(tags=["Attack Paths"], dependencies=[Depends(require_viewer)])

VALID_SEVERITIES = {"critical", "high", "medium", "low"}


@router.get("/attack-paths", response_model=APIResponse[List[AttackPath]])
def get_attack_paths(
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low"),
    source: Optional[str] = Query(None, description="Filter by source identity"),
    target_type: Optional[str] = Query(None, description="Filter by target resource type: S3, Role, RDS, etc."),
    region: Optional[str] = Query(None, description="Filter by AWS region"),
    limit: Optional[int] = Query(None, description="Maximum number of paths to return (1-200)"),
    offset: Optional[int] = Query(None, description="Pagination offset (>= 0)"),
    page: Optional[int] = Query(None, description="Page number (1-indexed)"),
    page_size: Optional[int] = Query(None, description="Page size (1-200)")
):
    """Retrieve attack paths with optional filtering and safe pagination."""
    if severity and severity.lower() not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity '{severity}'. Allowed values: {sorted(VALID_SEVERITIES)}"
        )
    if limit is not None and (limit < 1 or limit > 200):
        raise HTTPException(status_code=400, detail="Query parameter 'limit' must be between 1 and 200.")
    if offset is not None and offset < 0:
        raise HTTPException(status_code=400, detail="Query parameter 'offset' must be >= 0.")
    if page is not None and page < 1:
        raise HTTPException(status_code=400, detail="Query parameter 'page' must be >= 1.")
    if page_size is not None and (page_size < 1 or page_size > 200):
        raise HTTPException(status_code=400, detail="Query parameter 'page_size' must be between 1 and 200.")

    data = get_current_attack_paths()
    if not data and not has_published_snapshot() and not scan_manager.is_running:
        scan_manager.trigger_async_scan()
        data = []

    filtered = data or []

    if severity:
        sev_lower = severity.lower()
        filtered = [p for p in filtered if str(p.get("severity", "")).lower() == sev_lower]

    if source:
        src_lower = source.lower()
        filtered = [
            p for p in filtered
            if src_lower in str(p.get("source", "")).lower()
            or src_lower in str(p.get("name", "")).lower()
        ]

    if target_type:
        t_lower = target_type.lower()
        filtered = [
            p for p in filtered
            if str(p.get("target_type", "")).lower() == t_lower
            or str(p.get("targetCategory", "")).lower() == t_lower
            or str(p.get("target_category", "")).lower() == t_lower
        ]

    if region:
        reg_lower = region.lower()
        filtered = [
            p for p in filtered
            if str(p.get("region", "")).lower() == reg_lower
        ]

    # Apply pagination
    if page is not None and page_size is not None:
        start = (page - 1) * page_size
        end = start + page_size
        paginated = filtered[start:end]
    elif limit is not None:
        start = offset or 0
        end = start + limit
        paginated = filtered[start:end]
    elif offset is not None:
        paginated = filtered[offset:]
    else:
        paginated = filtered

    return APIResponse(
        success=True,
        message="Attack Paths threat pathways retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        snapshot_id=get_current_snapshot_id(),
        snapshot_published_at=get_current_snapshot_published_at(),
        data=paginated
    )


@router.get("/attack-paths/{id}", response_model=APIResponse[AttackPath])
def get_attack_path_by_id(id: str):
    """Retrieve detailed information for a specific attack path by path id or canonical id."""
    data = get_current_attack_paths()
    match_path = next(
        (p for p in data if p.get('id') == id or p.get('canonical_id') == id or p.get('path_id') == id),
        None
    )
    if not match_path:
        raise HTTPException(status_code=404, detail=f"Attack path with id '{id}' not found")
        
    return APIResponse(
        success=True,
        message=f"Attack path details for '{id}' retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        snapshot_id=get_current_snapshot_id(),
        snapshot_published_at=get_current_snapshot_published_at(),
        data=match_path
    )


@router.get("/attack-paths/{id}/evidence", response_model=APIResponse[Dict[str, Any]])
def get_attack_path_evidence(id: str):
    """Retrieve structured transition evidence, reachability details, and provenance for an attack path."""
    data = get_current_attack_paths()
    match_path = next(
        (p for p in data if p.get('id') == id or p.get('canonical_id') == id or p.get('path_id') == id),
        None
    )
    if not match_path:
        raise HTTPException(status_code=404, detail=f"Attack path with id '{id}' not found")

    evidence_payload = {
        "path_id": match_path.get("id"),
        "canonical_id": match_path.get("canonical_id") or match_path.get("path_id"),
        "name": match_path.get("name"),
        "source": match_path.get("source"),
        "target": match_path.get("target") or match_path.get("destination"),
        "target_type": match_path.get("target_type"),
        "path_type": match_path.get("pathType") or match_path.get("attack_type"),
        "severity": match_path.get("severity"),
        "risk_score": match_path.get("riskScore") or match_path.get("risk_score"),
        "risk_model_version": match_path.get("risk_model_version") or "phase3-v1",
        "source_snapshot_id": match_path.get("source_snapshot_id") or get_current_snapshot_id(),
        "ordered_relationships": match_path.get("ordered_relationships") or match_path.get("orderedRelationships", []),
        "ordered_nodes": match_path.get("ordered_nodes") or match_path.get("nodes", []),
        "transition_evidence": match_path.get("evidence", []),
        "blast_radius": match_path.get("blastRadius") or match_path.get("blast_radius"),
        "downstream_reachable_assets": match_path.get("downstream_reachable_assets") or match_path.get("downstreamReachableAssets", []),
        "privilege_escalation_details": match_path.get("privilege_escalation_details"),
        "lateral_movement_details": match_path.get("lateral_movement_details"),
        "risk_factors": match_path.get("risk_factors", {}),
        "mitre_techniques": match_path.get("mitreTechniques", []),
        "recommendations": match_path.get("recommendations", [match_path.get("recommendation")]),
    }

    return APIResponse(
        success=True,
        message=f"Transition evidence for attack path '{id}' retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        snapshot_id=get_current_snapshot_id(),
        snapshot_published_at=get_current_snapshot_published_at(),
        data=evidence_payload
    )

