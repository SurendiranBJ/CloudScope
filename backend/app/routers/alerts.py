from fastapi import APIRouter
from typing import List
from app.schemas import APIResponse, SecurityAlert
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from datetime import datetime

router = APIRouter(tags=["AWS Resources"])

@router.get("/alerts", response_model=APIResponse[List[SecurityAlert]])
def get_security_alerts():
    data = cache.get("v1:alerts")
    if not data:
        # Cache is cold — trigger async scan if not already running and
        # return an empty list immediately so the frontend can poll.
        if not scan_manager.is_running:
            scan_manager.trigger_async_scan()
        data = []
        
    return APIResponse(
        success=True,
        message="Threat alerts and config drift logs retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data
    )
