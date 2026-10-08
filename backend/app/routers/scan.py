from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, HTTPException
from app.schemas import APIResponse
from app.security.dependencies import require_admin, require_viewer
from app.security.models import AuthenticatedUser
from app.security.rate_limiter import rate_limit
from app.services.scanner.scan_coordinator import scan_coordinator

router = APIRouter(tags=["Scan"])


@router.post("/scan", response_model=APIResponse[dict], dependencies=[Depends(rate_limit("scan"))])
def trigger_manual_scan(
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin)
):
    """
    Trigger scan orchestration.
    Restricted to ADMINISTRATOR role.
    Uses distributed scan locking to ensure single execution.
    """
    result = scan_coordinator.request_scan(
        trigger_type="MANUAL",
        created_by=current_user.subject
    )
    if result.get("status") == "UNAVAILABLE":
        raise HTTPException(status_code=503, detail=result["message"])
    is_started = result.get("status") == "STARTED"
    return APIResponse(
        success=is_started,
        message=result.get("message", "Scan status updated"),
        timestamp=datetime.now(timezone.utc).isoformat(),
        data=result
    )


@router.get("/scan/status", response_model=APIResponse[dict])
def get_scan_status(
    current_user: AuthenticatedUser = Depends(require_viewer)
):
    """Poll endpoint for checking scan progress. Accessible to VIEWER role."""
    status = scan_coordinator.get_status()
    return APIResponse(
        success=True,
        message="Scan status",
        timestamp=datetime.now(timezone.utc).isoformat(),
        data=status
    )
