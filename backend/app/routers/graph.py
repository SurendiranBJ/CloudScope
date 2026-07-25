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
        scan_manager.run_scan()
        data = cache.get("v1:graph") or []
        
    return APIResponse(
        success=True,
        message="Graph nodes and edges elements retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data
    )

@router.post("/graph/rebuild", response_model=APIResponse[dict])
def rebuild_graph():
    logger_result = scan_manager.run_scan()
    return APIResponse(
        success=True if logger_result.get("status") == "success" else False,
        message="Graph structure sync rebuild complete",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=logger_result
    )
