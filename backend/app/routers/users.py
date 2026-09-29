from fastapi import APIRouter, Depends
from typing import List
from datetime import datetime
from app.schemas import APIResponse, IAMUser
from app.services.scanner.scan_manager import scan_manager
from app.services.scanner.current_snapshot import (
    get_current_users,
    get_current_snapshot_id,
    get_current_snapshot_published_at,
    has_published_snapshot,
)
from app.security.dependencies import require_viewer

router = APIRouter(tags=["AWS Resources"], dependencies=[Depends(require_viewer)])

@router.get("/users", response_model=APIResponse[List[IAMUser]])
def get_iam_users():
    raw_data = get_current_users()
    if not raw_data and not has_published_snapshot() and not scan_manager.is_running:
        scan_manager.trigger_async_scan()

    return APIResponse(
        success=True,
        message="IAM Users collection retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        snapshot_id=get_current_snapshot_id(),
        snapshot_published_at=get_current_snapshot_published_at(),
        data=raw_data
    )

