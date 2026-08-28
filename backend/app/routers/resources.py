from fastapi import APIRouter
from typing import List
from app.schemas import APIResponse, CloudResource
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from datetime import datetime

router = APIRouter(tags=["AWS Resources"])

@router.get("/resources", response_model=APIResponse[List[CloudResource]])
def get_cloud_resources():
    data = cache.get("v1:resources")
    if not data:
        # Cache is cold — trigger async scan if not already running (matches dashboard.py pattern)
        if not scan_manager.is_running:
            scan_manager.trigger_async_scan()
        # Return empty list — frontend will get data on next poll
        data = []

    return APIResponse(
        success=True,
        message="Cloud Resources catalog retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data
    )
