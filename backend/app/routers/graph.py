from fastapi import APIRouter
from typing import List
from app.schemas import APIResponse, CytoscapeElement
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from datetime import datetime

router = APIRouter(tags=["Graph"])

@router.get("/graph", response_model=APIResponse[List[CytoscapeElement]])
def get_graph_elements():
    data = cache.get("v1:graph")
    if not data:
        # Cache is cold — trigger async scan if not already running
        if not scan_manager.is_running:
            scan_manager.trigger_async_scan()
        # Return empty list — frontend will get data on next poll
        data = []

    return APIResponse(
        success=True,
        message="Graph nodes and edges elements retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data
    )

@router.post("/graph/rebuild", response_model=APIResponse[dict])
def rebuild_graph():
    """Trigger scan asynchronously — returns immediately so the frontend doesn't time out."""
    result = scan_manager.trigger_async_scan()
    return APIResponse(
        success=True,
        message="Scan triggered",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=result
    )
