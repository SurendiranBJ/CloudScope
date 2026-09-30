from fastapi import APIRouter, Depends
from typing import List
from app.schemas import APIResponse, RiskFinding
from app.services.scanner.scan_manager import scan_manager
from app.services.scanner.current_snapshot import (
    get_current_risks,
    get_current_findings,
    get_current_snapshot_id,
    get_current_snapshot_published_at,
    has_published_snapshot,
)
from datetime import datetime
from app.security.dependencies import require_viewer

router = APIRouter(tags=["Risk"], dependencies=[Depends(require_viewer)])


@router.get("/risk-assessment", response_model=APIResponse[List[RiskFinding]])
def get_risk_assessment_findings():
    raw_risks = get_current_risks()
    if raw_risks:
        data = [
            RiskFinding(**d) if isinstance(d, dict) else d
            for d in raw_risks
        ]
    else:
        # Fall back to canonical findings store from published snapshot
        findings = get_current_findings()
        if findings:
            data = [
                RiskFinding(
                    id=f.get("id", ""),
                    identity=f.get("principal") or f.get("resource") or "unknown",
                    identityType=f.get("principalType") or f.get("resourceType") or "Resource",
                    issue=f.get("description") or f.get("title", ""),
                    severity=f.get("severity", "medium"),
                    riskScore=f.get("riskScore", 0),
                    recommendation=f.get("remediation", {}).get("title") if isinstance(f.get("remediation"), dict) else (f.get("recommendation") or "Review configuration")
                )
                for f in findings
                if f.get("status") == "OPEN" and f.get("riskScore", 0) >= 40
            ]
            data.sort(key=lambda x: x.riskScore, reverse=True)
        elif not has_published_snapshot() and not scan_manager.is_running:
            scan_manager.trigger_async_scan()
            data = []
        else:
            data = []

    snapshot_id = get_current_snapshot_id()
    snapshot_published_at = get_current_snapshot_published_at()

    return APIResponse(
        success=True,
        message="Risk assessment findings retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        snapshot_id=snapshot_id,
        snapshot_published_at=snapshot_published_at,
        data=data
    )


@router.get("/risk-explanation/{entity_id}", response_model=APIResponse[dict])
def get_risk_explanation(entity_id: str):
    """Retrieve detailed, deterministic risk score explanation and factor breakdown for an entity."""
    from app.services.risk.risk_constants import RISK_MODEL_VERSION, get_severity_label
    from app.cache import cache

    # Check users, roles, resources in cache
    target_obj = None
    entity_type = "Resource"

    for u in (cache.get("v1:users") or []):
        if isinstance(u, dict) and (u.get("name") == entity_id or u.get("arn") == entity_id):
            target_obj = u
            entity_type = "User"
            break

    if not target_obj:
        for r in (cache.get("v1:roles") or []):
            if isinstance(r, dict) and (r.get("name") == entity_id or r.get("arn") == entity_id):
                target_obj = r
                entity_type = "Role"
                break

    if not target_obj:
        for res in (cache.get("v1:resources") or []):
            if isinstance(res, dict) and (res.get("name") == entity_id or res.get("arn") == entity_id or res.get("id") == entity_id):
                target_obj = res
                entity_type = res.get("type", "Resource")
                break

    score = target_obj.get("riskScore", 0) if target_obj else 0
    assessment = target_obj.get("riskAssessment", {}) if target_obj else {}
    factors = assessment.get("factors", []) if isinstance(assessment, dict) else []

    explanation = {
        "entity_id": entity_id,
        "entity_type": entity_type,
        "risk_score": score,
        "severity": get_severity_label(score),
        "risk_model_version": RISK_MODEL_VERSION,
        "factors": factors,
        "confidence": 95 if target_obj else 50,
        "snapshot_id": get_current_snapshot_id(),
        "snapshot_published_at": get_current_snapshot_published_at(),
        "assessment_details": assessment,
    }

    return APIResponse(
        success=True,
        message=f"Risk score explanation for '{entity_id}' retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        snapshot_id=get_current_snapshot_id(),
        snapshot_published_at=get_current_snapshot_published_at(),
        data=explanation
    )
