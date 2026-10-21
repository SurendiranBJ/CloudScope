"""Read-only access to retained published scan snapshots."""

from fastapi import APIRouter, Depends, HTTPException

from app.schemas import APIResponse
from app.security.dependencies import require_analyst
from app.security.models import AuthenticatedUser
from app.persistence.repository import DatabaseQueryError, get_recent_snapshots
from app.services.scanner.snapshot_store import snapshot_store
from app.utils.time import utc_now_iso

router = APIRouter(prefix="/snapshots", tags=["Snapshots"], dependencies=[Depends(require_analyst)])


@router.get("/history", response_model=APIResponse[dict])
def snapshot_history(current_user: AuthenticatedUser = Depends(require_analyst)):
    """List up to ten retained full snapshots available to this account/project."""
    try:
        snapshots = get_recent_snapshots(limit=10)
    except DatabaseQueryError as exc:
        raise HTTPException(status_code=503, detail="Snapshot history is temporarily unavailable.") from exc
    current = snapshot_store.get_current()
    current_id = current.snapshot_id if current else None
    for item in snapshots:
        item["is_current"] = item.get("snapshot_id") == current_id
    return APIResponse(
        success=True,
        message=f"Loaded {len(snapshots)} retained snapshot(s).",
        timestamp=utc_now_iso(),
        data={"snapshots": snapshots, "retention_limit": 10},
    )
