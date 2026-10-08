from fastapi import APIRouter, Depends
from typing import List
from datetime import datetime
from app.schemas import APIResponse, CytoscapeElement
from app.services.scanner.scan_manager import scan_manager
from app.services.scanner.current_snapshot import (
    get_current_graph,
    get_current_effective_access,
    get_current_snapshot_id,
    get_current_snapshot_published_at,
    has_published_snapshot,
)
from app.security.dependencies import require_viewer, require_admin
from app.security.rate_limiter import rate_limit

router = APIRouter(tags=["Graph"], dependencies=[Depends(require_viewer)])

@router.get("/graph", response_model=APIResponse[List[CytoscapeElement]])
def get_graph_elements():
    data = get_current_graph()
    if not data and not has_published_snapshot() and not scan_manager.is_running:
        scan_manager.trigger_async_scan()

    return APIResponse(
        success=True,
        message="Graph nodes and edges elements retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        snapshot_id=get_current_snapshot_id(),
        snapshot_published_at=get_current_snapshot_published_at(),
        data=data
    )

@router.post("/graph/rebuild", response_model=APIResponse[dict], dependencies=[Depends(rate_limit("scan"))])
def rebuild_graph(current_user=Depends(require_admin)):
    """Trigger scan asynchronously — returns immediately so the frontend doesn't time out."""
    result = scan_manager.trigger_async_scan()
    if result.get("status") == "UNAVAILABLE":
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail=result["message"])
    return APIResponse(
        success=True,
        message=result.get("message", "Scan started"),
        timestamp=datetime.utcnow().isoformat() + "Z",
        snapshot_id=get_current_snapshot_id(),
        snapshot_published_at=get_current_snapshot_published_at(),
        data=result
    )

@router.get("/graph/effective-access", response_model=APIResponse[list])
def get_effective_access():
    """Return backend-computed authoritative effective-access relationships from current published snapshot."""
    records = get_current_effective_access()
    return APIResponse(
        success=True,
        message="Effective access records retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        snapshot_id=get_current_snapshot_id(),
        snapshot_published_at=get_current_snapshot_published_at(),
        data=records or []
    )


