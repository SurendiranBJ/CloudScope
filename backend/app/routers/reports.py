"""
CloudScope Reports Router.

Derives real, verified security control coverage scores across 5 core security domains.
No fake certifications or fabricated percentages.
"""

import json
import logging
from fastapi import APIRouter
from app.schemas import APIResponse
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from app.services.risk.risk_constants import (
    SEVERITY_CRITICAL_THRESHOLD,
    SEVERITY_HIGH_THRESHOLD,
    SEVERITY_MEDIUM_THRESHOLD
)
from datetime import datetime

logger = logging.getLogger("backend")
router = APIRouter(tags=["Reports"])


def _compute_reports_from_cache() -> dict:
    """Derive real security control coverage scores from cached scan inventory data.
    Returns a dict matching the frontend's ReportsSummary shape.
    """
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
def get_reports_summary():
    """Return verified security control coverage report."""
    users = cache.get("v1:users") or []
    if not users and not scan_manager.is_running:
        scan_manager.trigger_async_scan()

    report_data = _compute_reports_from_cache()

    return APIResponse(
        success=True,
        message="Verified security control report summary retrieved",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=report_data
    )
