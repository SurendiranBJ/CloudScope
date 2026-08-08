from fastapi import APIRouter
from app.schemas import APIResponse
from app.services.scanner.scan_manager import scan_manager
from datetime import datetime

router = APIRouter(tags=["Scan"])

@router.post("/scan", response_model=APIResponse[dict])
def trigger_manual_scan():
    """Trigger scan asynchronously — returns immediately."""
    result = scan_manager.trigger_async_scan()
    return APIResponse(
        success=True,
        message="Scan triggered",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=result
    )

@router.get("/scan/status", response_model=APIResponse[dict])
def get_scan_status():
    """Poll endpoint for frontend to check if a scan is in progress."""
    status = scan_manager.get_status()
    return APIResponse(
        success=True,
        message="Scan status",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=status
    )
