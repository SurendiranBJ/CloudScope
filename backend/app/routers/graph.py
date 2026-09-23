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

@router.get("/graph/effective-access", response_model=APIResponse[list])
def get_effective_access():
    """Return backend-computed authoritative effective-access relationships."""
    records = cache.get("v1:effective_access")
    if records is None:
        try:
            from app.services.simulation.effective_access import compute_effective_access
            from app.services.aws.ec2_service import is_running_ec2
            inv = scan_manager.inventory
            running_ec2 = [e for e in inv.ec2 if is_running_ec2(e)]
            all_res = (
                inv.s3 + inv.secrets + inv.rds +
                inv.dynamodb + running_ec2 + inv.lambdas
            )
            policy_doc_map = {
                p.get('name', ''): p.get('document', '{}')
                for p in inv.policies if p.get('name')
            }
            policy_doc_map.update({
                p.get('arn', ''): p.get('document', '{}')
                for p in inv.policies if p.get('arn')
            })
            records = compute_effective_access(inv, policy_doc_map, all_res)
            cache.set("v1:effective_access", records)
        except Exception:
            records = []
    return APIResponse(
        success=True,
        message="Effective access records retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=records or []
    )

