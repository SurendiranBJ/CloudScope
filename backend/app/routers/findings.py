"""
CloudScope Canonical Security Findings Router.

Provides query endpoints with multi-attribute filtering and lifecycle mutation endpoints.
"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query
from app.schemas import APIResponse, SecurityFinding
from app.services.findings.finding_service import finding_service
from app.services.scanner.scan_manager import scan_manager
from app.cache import cache

router = APIRouter(prefix="/findings", tags=["Security Findings"])


VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_STATUSES = {"open", "acknowledged", "resolved", "suppressed"}
VALID_CATEGORIES = {
    "iam",
    "resource",
    "privilege_escalation",
    "lateral_movement",
    "cloudtrail",
    "credential",
    "configuration",
    "data_access",
    "monitoring",
    "identity_excessive_privilege",
    "data_exposure",
    "network_exposure",
    "secrets_management",
    "attack_path_risk",
    "runtime_activity",
    "security_hygiene"
}
VALID_SOURCES = {
    "static_iam",
    "resource_configuration",
    "attack_path",
    "cloudtrail",
    "correlation",
    "static_analysis",
    "runtime_activity"
}


@router.get("", response_model=APIResponse[List[SecurityFinding]])
def get_security_findings(
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low"),
    category: Optional[str] = Query(None, description="Filter by category: IAM, RESOURCE, PRIVILEGE_ESCALATION, etc."),
    status: Optional[str] = Query(None, description="Filter by lifecycle status: OPEN, ACKNOWLEDGED, RESOLVED, SUPPRESSED"),
    resourceType: Optional[str] = Query(None, description="Filter by resource type: S3, EC2, User, Role, RDS, etc."),
    region: Optional[str] = Query(None, description="Filter by AWS region"),
    principal: Optional[str] = Query(None, description="Filter by affected principal"),
    source: Optional[str] = Query(None, description="Filter by source: STATIC_IAM, RESOURCE_CONFIGURATION, ATTACK_PATH, CLOUDTRAIL, CORRELATION"),
    search: Optional[str] = Query(None, description="Full text search on title, description, principal, and resource"),
    limit: Optional[int] = Query(None, description="Maximum number of findings to return (1-200)"),
    offset: Optional[int] = Query(None, description="Pagination offset (>= 0)")
):
    """Retrieve unified security findings with strict multi-attribute validation and filtering."""
    # 1. Parameter Validation (Reject invalid inputs with HTTP 400)
    if severity and severity.lower() not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity '{severity}'. Allowed values: {sorted(VALID_SEVERITIES)}"
        )
    if status and status.lower() not in VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{status}'. Allowed values: {sorted(VALID_STATUSES)}"
        )
    if category and category.lower() not in VALID_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category '{category}'. Allowed values: {sorted(VALID_CATEGORIES)}"
        )
    if source and source.lower() not in VALID_SOURCES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid source '{source}'. Allowed values: {sorted(VALID_SOURCES)}"
        )
    if limit is not None and (limit < 1 or limit > 200):
        raise HTTPException(status_code=400, detail="Query parameter 'limit' must be between 1 and 200.")
    if offset is not None and offset < 0:
        raise HTTPException(status_code=400, detail="Query parameter 'offset' must be greater than or equal to 0.")

    findings = finding_service.get_all_findings()

    if not findings and not scan_manager.is_running:
        scan_manager.trigger_async_scan()

    filtered = findings

    if severity:
        sev_lower = severity.lower()
        filtered = [f for f in filtered if f.severity.lower() == sev_lower]

    if category:
        cat_upper = category.upper()
        filtered = [f for f in filtered if f.category.upper() == cat_upper]

    if status:
        st_upper = status.upper()
        filtered = [f for f in filtered if f.status.upper() == st_upper]

    if resourceType:
        rt_lower = resourceType.lower()
        filtered = [f for f in filtered if (f.resourceType and f.resourceType.lower() == rt_lower) or (f.principalType and f.principalType.lower() == rt_lower)]

    if region:
        reg_lower = region.lower()
        filtered = [f for f in filtered if f.region and f.region.lower() == reg_lower]

    if principal:
        p_lower = principal.lower()
        filtered = [f for f in filtered if f.principal and p_lower in f.principal.lower()]

    if source:
        src_upper = source.upper()
        filtered = [f for f in filtered if f.source.upper() == src_upper]

    if search:
        s_lower = search.lower()
        filtered = [
            f for f in filtered
            if (s_lower in f.title.lower())
            or (s_lower in f.description.lower())
            or (f.principal and s_lower in f.principal.lower())
            or (f.resource and s_lower in f.resource.lower())
            or (f.remediation and s_lower in f.remediation.title.lower())
        ]

    # Apply pagination
    start = offset or 0
    end = start + limit if limit is not None else None
    paginated = filtered[start:end]

    return APIResponse(
        success=True,
        message="Unified security findings retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=paginated
    )


@router.get("/{finding_id}", response_model=APIResponse[SecurityFinding])
def get_finding_by_id(finding_id: str):
    """Retrieve detailed information for a specific security finding."""
    finding = finding_service.get_finding_by_id(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")

    return APIResponse(
        success=True,
        message="Finding retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=finding
    )


@router.post("/{finding_id}/acknowledge", response_model=APIResponse[SecurityFinding])
def acknowledge_finding(finding_id: str):
    """Transition finding status to ACKNOWLEDGED."""
    try:
        updated = finding_service.acknowledge_finding(finding_id)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))

    if not updated:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")

    return APIResponse(
        success=True,
        message=f"Finding '{finding_id}' acknowledged",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=updated
    )


@router.post("/{finding_id}/resolve", response_model=APIResponse[SecurityFinding])
def resolve_finding(finding_id: str):
    """Transition finding status to RESOLVED."""
    try:
        updated = finding_service.resolve_finding(finding_id)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))

    if not updated:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")

    return APIResponse(
        success=True,
        message=f"Finding '{finding_id}' marked as resolved",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=updated
    )


@router.post("/{finding_id}/suppress", response_model=APIResponse[SecurityFinding])
def suppress_finding(finding_id: str):
    """Transition finding status to SUPPRESSED."""
    try:
        updated = finding_service.suppress_finding(finding_id)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))

    if not updated:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")

    return APIResponse(
        success=True,
        message=f"Finding '{finding_id}' suppressed",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=updated
    )


@router.post("/{finding_id}/reopen", response_model=APIResponse[SecurityFinding])
def reopen_finding(finding_id: str):
    """Transition finding status back to OPEN."""
    try:
        updated = finding_service.reopen_finding(finding_id)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))

    if not updated:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")

    return APIResponse(
        success=True,
        message=f"Finding '{finding_id}' reopened",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=updated
    )
