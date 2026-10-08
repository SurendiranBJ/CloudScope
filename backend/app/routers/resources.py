from fastapi import APIRouter, Depends
from typing import List
from app.schemas import APIResponse, CloudResource
from app.services.scanner.scan_manager import scan_manager
from app.services.scanner.current_snapshot import (
    get_current_resources,
    get_current_snapshot_id,
    get_current_snapshot_published_at,
    has_published_snapshot,
)
from datetime import datetime
from app.security.dependencies import require_viewer

router = APIRouter(tags=["AWS Resources"], dependencies=[Depends(require_viewer)])


@router.get("/resources", response_model=APIResponse[List[CloudResource]])
def get_cloud_resources():
    raw_data = get_current_resources()
    if raw_data:
        data = []
        for d in raw_data:
            if isinstance(d, dict):
                norm = dict(d)
                if "owner" not in norm:
                    norm["owner"] = norm.get("account_id") or "AWS"
                if "riskScore" not in norm:
                    norm["riskScore"] = norm.get("risk_score") or 0
                data.append(CloudResource(**norm))
            else:
                data.append(d)
    elif not has_published_snapshot() and not scan_manager.is_running:
        pass
        data = []
    else:
        data = []

    return APIResponse(
        success=True,
        message="Cloud Resources catalog retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        snapshot_id=get_current_snapshot_id(),
        snapshot_published_at=get_current_snapshot_published_at(),
        data=data
    )
