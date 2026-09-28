from fastapi import APIRouter
from typing import List
from datetime import datetime
from app.schemas import APIResponse, IAMRole
from app.services.scanner.scan_manager import scan_manager
from app.services.scanner.current_snapshot import (
    get_current_roles,
    get_current_snapshot_id,
    get_current_snapshot_published_at,
    has_published_snapshot,
)

router = APIRouter(tags=["AWS Resources"])

@router.get("/roles", response_model=APIResponse[List[IAMRole]])
def get_iam_roles():
    raw_data = get_current_roles()
    if not raw_data and not has_published_snapshot() and not scan_manager.is_running:
        scan_manager.trigger_async_scan()

    return APIResponse(
        success=True,
        message="IAM Roles collection retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        snapshot_id=get_current_snapshot_id(),
        snapshot_published_at=get_current_snapshot_published_at(),
        data=raw_data
    )

