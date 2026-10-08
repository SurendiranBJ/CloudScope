"""
CloudScope Reports Router.

Derives real, verified security control coverage scores across 5 core security domains.
No fake certifications or fabricated percentages.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Request, Query
from app.schemas import APIResponse
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from app.services.risk.risk_constants import (
    SEVERITY_CRITICAL_THRESHOLD,
    SEVERITY_HIGH_THRESHOLD,
    SEVERITY_MEDIUM_THRESHOLD
)
from app.security.dependencies import require_viewer, require_security_officer
from app.security.models import AuthenticatedUser
from app.security.rate_limiter import rate_limit
from app.services.audit.audit_service import audit_service
from app.services.scanner.current_snapshot import get_published_snapshot

logger = logging.getLogger("backend")
router = APIRouter(tags=["Reports"])


def _compute_reports_from_cache() -> dict:
    """Derive real security control coverage scores from cached scan inventory data.
    Returns a dict matching the frontend's ReportsSummary shape.
    """
    snap = get_published_snapshot()
    if snap is not None:
        users = list(snap.users)
        roles = list(snap.roles)
        risks = list(snap.risks)
        findings = list(snap.findings)
        alerts = list(snap.alerts)
        resources = list(snap.resources)
        paths = list(snap.attack_paths)
        global_posture = snap.dashboard.get("globalPosture")
    else:
        users = cache.get("v1:users") or []
        roles = cache.get("v1:roles") or []
        risks = cache.get("v1:risks") or []
        findings = cache.get("v1:findings") or []
        alerts = cache.get("v1:alerts") or []
        resources = cache.get("v1:resources") or []
        paths = cache.get("v1:attack-paths") or []
        global_posture = cache.get("v1:global_posture")

    # If completely cold with zero scan data, return explicit empty data coverage state
    if not users and not roles and not resources and not risks and not paths and not findings:
        return {
            "has_data": False,
            "compliance": [],
            "summary": {
                "score": None,
                "grade": "No scan data available",
                "findings_count": 0,
                "status": "No scan data available"
            },
            "findings_by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "findings_by_category": {},
            "findings": []
        }

    # 1. MFA Enforcement Coverage
    total_users = len(users)
    mfa_enabled = sum(1 for u in users if u.get('mfaEnabled', False))
    mfa_score = round((mfa_enabled / total_users) * 100) if total_users else 100
    mfa_failed = total_users - mfa_enabled
    mfa_details = f"Verified: {mfa_enabled} users with MFA active | Non-compliant: {mfa_failed} users without MFA"

    # 2. IAM Least Privilege Compliance
    all_identities = users + roles
    total_identities = len(all_identities)
    least_priv = sum(1 for i in all_identities if i.get('riskScore', 0) < SEVERITY_HIGH_THRESHOLD)
    least_priv_failed = total_identities - least_priv
    least_priv_score = round((least_priv / total_identities) * 100) if total_identities else 100
    least_priv_details = (
        f"Verified: {least_priv} identities adhering to scoped access | "
        f"Elevated: {least_priv_failed} identities with broad administrative permissions"
    )

    # 3. Public Resource Exposure Protection
    s3_resources = [r for r in resources if r.get('type') == 'S3']
    rds_resources = [r for r in resources if r.get('type') == 'RDS']
    exposable = s3_resources + rds_resources
    total_exposable = len(exposable)
    not_public = sum(
        1 for r in exposable
        if (r.get('type') == 'S3' and r.get('details', {}).get('public_blocked', True))
        or (r.get('type') == 'RDS' and not r.get('details', {}).get('publicly_accessible', False))
    )
    public_failed = total_exposable - not_public
    exposure_score = round((not_public / total_exposable) * 100) if total_exposable else 100
    exposure_details = (
        f"Protected: {not_public} data stores with public access blocked | "
        f"Exposed: {public_failed} resources accessible without restriction"
    )

    # 4. AssumeRole Trust Boundary Scoping
    total_roles = len(roles)
    clean_trust = sum(
        1 for r in roles
        if '*' not in str(r.get('trustPolicy', ''))
    )
    trust_failed = total_roles - clean_trust
    trust_score = round((clean_trust / total_roles) * 100) if total_roles else 100
    trust_details = (
        f"Scoped: {clean_trust} roles with explicit principal ARNs | "
        f"Wildcard: {trust_failed} roles with broad trust policies"
    )

    # 5. Attack Path & Lateral Movement Defense
    total_paths = len(paths)
    critical_paths = sum(1 for p in paths if p.get('severity') == 'critical')
    path_defense_score = max(0, min(100, 100 - (critical_paths * 20 + total_paths * 3)))
    path_details = f"Detected: {total_paths} lateral movement vector(s) | {critical_paths} critical attack chain(s)"

    compliance = [
        {"name": "MFA Enforcement Coverage", "score": mfa_score, "details": mfa_details},
        {"name": "IAM Least Privilege Scoping", "score": least_priv_score, "details": least_priv_details},
        {"name": "Public Resource Access Block", "score": exposure_score, "details": exposure_details},
        {"name": "AssumeRole Trust Boundary Control", "score": trust_score, "details": trust_details},
        {"name": "Attack Path Defense & Isolation", "score": path_defense_score, "details": path_details}
    ]

    if global_posture and "overall_score" in global_posture:
        overall_score = global_posture["overall_score"]
    else:
        overall_score = round(
            (mfa_score * 0.20) +
            (least_priv_score * 0.25) +
            (exposure_score * 0.25) +
            (trust_score * 0.15) +
            (path_defense_score * 0.15)
        )

    if overall_score >= 90:
        grade = "Excellent (A)"
    elif overall_score >= 75:
        grade = "Good (B)"
    elif overall_score >= 60:
        grade = "Fair (C)"
    else:
        grade = "Action Required (F)"

    # Severity and Category breakdowns from canonical findings
    active_findings = [f for f in findings if f.get("status") == "OPEN"] if findings else risks
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_cat: dict = {}
    for f in active_findings:
        sev = (f.get("severity") or "medium").lower()
        if sev in by_sev:
            by_sev[sev] += 1
        cat = f.get("category") or "IAM"
        by_cat[cat] = by_cat.get(cat, 0) + 1

    return {
        "has_data": True,
        "compliance": compliance,
        "summary": {
            "score": overall_score,
            "grade": grade,
            "findings_count": len(active_findings)
        },
        "findings_by_severity": by_sev,
        "findings_by_category": by_cat,
        "findings": active_findings[:50]
    }


@router.get("/reports/summary")
def get_reports_summary(
    current_user: AuthenticatedUser = Depends(require_viewer)
):
    """Return verified security control coverage report. Accessible to VIEWER role."""
    snap = get_published_snapshot()
    users = list(snap.users) if snap is not None else (cache.get("v1:users") or [])
    if not users and not scan_manager.is_running:
        pass

    report_data = _compute_reports_from_cache()

    return APIResponse(
        success=True,
        message="Verified security control report summary retrieved",
        timestamp=datetime.now(timezone.utc).isoformat(),
        data=report_data
    )


@router.get("/reports/export/json", dependencies=[Depends(rate_limit("export"))])
def export_security_report_json(
    request: Request,
    max_findings: int = Query(500, ge=1, le=2000, description="Maximum number of findings to include in export"),
    current_user: AuthenticatedUser = Depends(require_security_officer)
):
    """
    Export complete security report as structured JSON.
    Restricted to SECURITY_OFFICER and ADMINISTRATOR roles.
    Includes bounded export limits to prevent memory exhaustion.
    """
    report = _compute_reports_from_cache()
    snap = get_published_snapshot()
    scan_meta = dict(snap.scan_metadata) if snap is not None else (cache.get("v1:scan_metadata") or {})
    findings = list(snap.findings) if snap is not None else (cache.get("v1:findings") or [])

    bounded_findings = [
        f if isinstance(f, dict) else f.model_dump()
        for f in findings[:max_findings]
    ]

    export_payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "exported_by": current_user.subject,
        "platform": "CloudScope AWS Security Analysis",
        "scan_information": {
            "scan_id": scan_meta.get("scanId"),
            "scan_status": scan_meta.get("scanStatus"),
            "scanned_regions": scan_meta.get("scannedRegions", []),
            "duration_seconds": scan_meta.get("durationSeconds"),
            "last_completed_scan_at": scan_meta.get("lastCompletedScanAt"),
            "last_successful_scan_at": scan_meta.get("lastSuccessfulScanAt"),
        },
        "security_summary": report.get("summary", {}),
        "control_coverage": report.get("compliance", []),
        "findings_by_severity": report.get("findings_by_severity", {}),
        "canonical_findings": bounded_findings
    }

    client_ip = request.client.host if request.client else None
    audit_service.log(
        action="REPORT_EXPORTED",
        actor_id=current_user.subject,
        actor_role=current_user.highest_role.value if current_user.highest_role else "UNKNOWN",
        resource_type="report",
        resource_id="json_export",
        result="SUCCESS",
        ip_address=client_ip,
        metadata={"finding_count": len(bounded_findings), "format": "JSON"}
    )

    return APIResponse(
        success=True,
        message="Security report exported successfully",
        timestamp=datetime.now(timezone.utc).isoformat(),
        data=export_payload
    )

