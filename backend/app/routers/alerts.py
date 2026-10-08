from fastapi import APIRouter, Depends, Query, HTTPException
from typing import List, Optional
from app.schemas import APIResponse, SecurityAlert, CorrelatedRiskFinding
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from app.services.scanner.current_snapshot import (
    get_current_alerts,
    get_current_correlated_risks,
    get_current_snapshot_id,
    get_current_snapshot_published_at,
    has_published_snapshot,
)
from datetime import datetime
from app.security.dependencies import require_viewer

router = APIRouter(tags=["Security Alerts & Activity"], dependencies=[Depends(require_viewer)])


@router.get("/alerts", response_model=APIResponse[List[SecurityAlert]])
def get_security_alerts(
    principal: Optional[str] = Query(None, description="Filter by principal or actor"),
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low"),
    region: Optional[str] = Query(None, description="Filter by AWS region"),
    limit: Optional[int] = Query(None, description="Max items to return (1-200)"),
    offset: Optional[int] = Query(None, description="Pagination offset (>= 0)"),
    page: Optional[int] = Query(None, description="Page number (>= 1)"),
    page_size: Optional[int] = Query(None, description="Page size (1-200)")
):
    """Retrieve security audit alerts discovered from CloudTrail and security configurations."""
    if limit is not None and (limit < 1 or limit > 200):
        raise HTTPException(status_code=400, detail="limit must be between 1 and 200.")
    if offset is not None and offset < 0:
        raise HTTPException(status_code=400, detail="offset must be >= 0.")
    if page is not None and page < 1:
        raise HTTPException(status_code=400, detail="page must be >= 1.")
    if page_size is not None and (page_size < 1 or page_size > 200):
        raise HTTPException(status_code=400, detail="page_size must be between 1 and 200.")

    raw_alerts = get_current_alerts()
    data = []
    if raw_alerts:
        import json
        for a in raw_alerts:
            if isinstance(a, dict):
                norm = dict(a)
                if "details" not in norm or norm["details"] is None:
                    norm["details"] = "{}"
                elif not isinstance(norm["details"], str):
                    norm["details"] = json.dumps(norm["details"])
                data.append(SecurityAlert(**norm))
            else:
                data.append(a)
    elif not has_published_snapshot() and not scan_manager.is_running:
        pass

    filtered = data
    if principal:
        p_lower = principal.lower()
        filtered = [a for a in filtered if p_lower in str(getattr(a, "actor", "")).lower() or p_lower in str(getattr(a, "resource", "")).lower()]
    if severity:
        s_lower = severity.lower()
        filtered = [a for a in filtered if str(getattr(a, "severity", "")).lower() == s_lower]
    if region:
        r_lower = region.lower()
        filtered = [a for a in filtered if str(getattr(a, "region", "")).lower() == r_lower]

    # Pagination
    if page is not None and page_size is not None:
        start = (page - 1) * page_size
        paginated = filtered[start:start + page_size]
    elif limit is not None:
        start = offset or 0
        paginated = filtered[start:start + limit]
    elif offset is not None:
        paginated = filtered[offset:]
    else:
        paginated = filtered

    return APIResponse(
        success=True,
        message="Threat alerts and config drift logs retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        snapshot_id=get_current_snapshot_id(),
        snapshot_published_at=get_current_snapshot_published_at(),
        data=paginated
    )


@router.get("/correlated-risks", response_model=APIResponse[List[CorrelatedRiskFinding]])
def get_correlated_risks(
    principal: Optional[str] = Query(None, description="Filter by principal or actor"),
    event_name: Optional[str] = Query(None, description="Filter by event name (e.g. AssumeRole)"),
    confidence: Optional[str] = Query(None, description="Filter by confidence: EXACT, HIGH, MEDIUM, LOW"),
    limit: Optional[int] = Query(None, description="Max items to return (1-200)"),
    offset: Optional[int] = Query(None, description="Pagination offset (>= 0)"),
    page: Optional[int] = Query(None, description="Page number (>= 1)"),
    page_size: Optional[int] = Query(None, description="Page size (1-200)")
):
    """Retrieve security findings correlating observed CloudTrail runtime activity with static IAM attack paths."""
    if limit is not None and (limit < 1 or limit > 200):
        raise HTTPException(status_code=400, detail="limit must be between 1 and 200.")
    if offset is not None and offset < 0:
        raise HTTPException(status_code=400, detail="offset must be >= 0.")
    if page is not None and page < 1:
        raise HTTPException(status_code=400, detail="page must be >= 1.")
    if page_size is not None and (page_size < 1 or page_size > 200):
        raise HTTPException(status_code=400, detail="page_size must be between 1 and 200.")

    data = get_current_correlated_risks()
    if not data and not has_published_snapshot():
        if not has_published_snapshot() and not scan_manager.is_running:
            pass

    filtered = data or []
    if principal:
        p_lower = principal.lower()
        filtered = [r for r in filtered if p_lower in str(r.get("actor", "")).lower() or p_lower in str(r.get("principal", "")).lower()]
    if event_name:
        e_lower = event_name.lower()
        filtered = [r for r in filtered if e_lower in str(r.get("event_name", "")).lower() or e_lower in str(r.get("eventName", "")).lower()]
    if confidence:
        c_upper = confidence.upper()
        filtered = [r for r in filtered if str(r.get("confidence_classification", "")).upper() == c_upper]

    # Pagination
    if page is not None and page_size is not None:
        start = (page - 1) * page_size
        paginated = filtered[start:start + page_size]
    elif limit is not None:
        start = offset or 0
        paginated = filtered[start:start + limit]
    elif offset is not None:
        paginated = filtered[offset:]
    else:
        paginated = filtered

    return APIResponse(
        success=True,
        message="Correlated security activity findings retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        snapshot_id=get_current_snapshot_id(),
        snapshot_published_at=get_current_snapshot_published_at(),
        data=paginated
    )
