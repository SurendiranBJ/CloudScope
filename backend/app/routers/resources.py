from app.utils.time import utc_now_iso
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
                norm.setdefault("name", norm.get("id") or norm.get("arn") or "Unnamed resource")
                norm.setdefault("type", "Unknown")
                norm.setdefault("region", "global")
                norm.setdefault("status", norm.get("state") or (norm.get("details") or {}).get("state") or "configured")
                if "owner" not in norm:
                    norm["owner"] = norm.get("account_id") or "AWS"
                if "riskScore" not in norm:
                    norm["riskScore"] = norm.get("risk_score", 0)
                norm.setdefault("arn", norm.get("id") or norm["name"])
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
        timestamp=utc_now_iso(),
        snapshot_id=get_current_snapshot_id(),
        snapshot_published_at=get_current_snapshot_published_at(),
        data=data
    )
