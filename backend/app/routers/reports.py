import json
import logging
from fastapi import APIRouter
from app.schemas import APIResponse
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from datetime import datetime

logger = logging.getLogger("backend")

router = APIRouter(tags=["Reports"])


def _compute_reports_from_cache() -> dict:
    """Derive real compliance-category scores from cached scan inventory data.

    Returns a dict matching the frontend's ReportsSummary shape:
        { compliance: [...], summary: { score, grade, findings_count } }
    """
    users = cache.get("v1:users") or []
    roles = cache.get("v1:roles") or []
    risks = cache.get("v1:risks") or []
    alerts = cache.get("v1:alerts") or []
    resources = cache.get("v1:resources") or []

    # --- Category 1: MFA Coverage ---
    total_users = len(users)
    mfa_enabled = sum(1 for u in users if u.get('mfaEnabled', False))
    mfa_score = round((mfa_enabled / total_users) * 100) if total_users else 100
    mfa_failed = total_users - mfa_enabled
    mfa_details = f"Passed: {mfa_enabled} users with MFA | Failed: {mfa_failed} users without MFA"

    # --- Category 2: IAM Least Privilege ---
    # Count identities (users + roles) whose riskScore is below the wildcard
    # threshold (< 55 means no wildcard bonus was applied by risk_engine.py).
    all_identities = users + roles
    total_identities = len(all_identities)
    least_priv = sum(1 for i in all_identities if i.get('riskScore', 0) < 55)
    least_priv_failed = total_identities - least_priv
    least_priv_score = round((least_priv / total_identities) * 100) if total_identities else 100
    least_priv_details = (
        f"Passed: {least_priv} identities below wildcard threshold | "
        f"Failed: {least_priv_failed} identities with elevated permissions"
    )

    # --- Category 3: Public Resource Exposure ---
    s3_resources = [r for r in resources if r.get('type') == 'S3']
    rds_resources = [r for r in resources if r.get('type') == 'RDS']
    exposable = s3_resources + rds_resources
    total_exposable = len(exposable)
    not_public = sum(
        1 for r in exposable
        if r.get('type') == 'S3' and r.get('details', {}).get('public_blocked', True)
        or r.get('type') == 'RDS' and not r.get('details', {}).get('publicly_accessible', False)
    )
    public_failed = total_exposable - not_public
    exposure_score = round((not_public / total_exposable) * 100) if total_exposable else 100
    exposure_details = (
        f"Passed: {not_public} resources not publicly exposed | "
        f"Failed: {public_failed} resources with public access"
    )

    # --- Category 4: Trust Policy Hygiene ---
    total_roles = len(roles)
    clean_trust = sum(
        1 for r in roles
        if '"Principal": "*"' not in r.get('trustPolicy', '')
        and '"AWS": "*"' not in r.get('trustPolicy', '')
    )
    trust_failed = total_roles - clean_trust
    trust_score = round((clean_trust / total_roles) * 100) if total_roles else 100
    trust_details = (
        f"Passed: {clean_trust} roles with scoped trust principals | "
        f"Failed: {trust_failed} roles with wildcard trust"
    )

    compliance = [
        {"name": "MFA Coverage", "score": mfa_score, "details": mfa_details},
        {"name": "IAM Least Privilege", "score": least_priv_score, "details": least_priv_details},
        {"name": "Public Resource Exposure", "score": exposure_score, "details": exposure_details},
        {"name": "Trust Policy Hygiene", "score": trust_score, "details": trust_details},
    ]

    # --- Summary aggregate ---
    # Overall score: weighted average of the four category scores.
    overall_score = round(
        (mfa_score * 0.30)
        + (least_priv_score * 0.30)
        + (exposure_score * 0.25)
        + (trust_score * 0.15)
    )

    if overall_score >= 90:
        grade = "Excellent"
    elif overall_score >= 75:
        grade = "Good"
    elif overall_score >= 60:
        grade = "Fair"
    else:
        grade = "Poor"

    findings_count = len(risks) + len(alerts)

    return {
        "compliance": compliance,
        "summary": {
            "score": f"{overall_score}%",
            "grade": grade,
            "findings_count": findings_count,
        },
    }


@router.get("/reports", response_model=APIResponse[dict])
def get_reports_summary():
    # Check if any scan data exists in the cache yet.
    users = cache.get("v1:users")
    if users is None:
        # Cache is cold — trigger async scan (non-blocking) and return placeholder.
        if not scan_manager.is_running:
            scan_manager.trigger_async_scan()
        placeholder = {
            "compliance": [],
            "summary": {
                "score": "-- %",
                "grade": "Scanning",
                "findings_count": 0,
            },
        }
        return APIResponse(
            success=True,
            message="Scan in progress — reports will populate after the first scan completes.",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data=placeholder,
        )

    reports_data = _compute_reports_from_cache()

    return APIResponse(
        success=True,
        message="Compliance audits and reports summary retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=reports_data,
    )
