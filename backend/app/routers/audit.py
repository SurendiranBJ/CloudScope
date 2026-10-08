"""
Administrative Audit Trail API router.
Enforces role-based authorization (SECURITY_OFFICER or ADMINISTRATOR),
server-side filtering, and bounded results.
"""

from typing import Optional, List, Any, Dict
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, Request

from app.schemas import APIResponse
from app.security.dependencies import require_security_officer
from app.security.models import AuthenticatedUser
from app.security.rate_limiter import rate_limit
from app.services.audit.audit_service import audit_service

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("", response_model=APIResponse[Dict[str, Any]], dependencies=[Depends(rate_limit("audit"))])
def get_audit_trail(
    request: Request,
    actor_id: Optional[str] = Query(None, description="Filter by actor user ID"),
    action: Optional[str] = Query(None, description="Filter by audit action name"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    resource_id: Optional[str] = Query(None, description="Filter by resource identifier"),
    scan_id: Optional[str] = Query(None, description="Filter by scan execution ID"),
    limit: int = Query(50, ge=1, le=200, description="Max audit events to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    current_user: AuthenticatedUser = Depends(require_security_officer)
):
    """
    Retrieve server-side filtered administrative audit log events.
    Restricted to SECURITY_OFFICER and ADMINISTRATOR roles.
    """
    events = audit_service.get_events(
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        scan_id=scan_id,
        limit=limit,
        offset=offset
    )

    return APIResponse(
        success=True,
        message=f"Retrieved {len(events)} audit events",
        timestamp=datetime.now(timezone.utc).isoformat(),
        data={
            "events": events,
            "count": len(events),
            "limit": limit,
            "offset": offset
        }
    )
