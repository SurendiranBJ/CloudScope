from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from app.schemas import APIResponse
from app.utils.scheduler import reschedule_scan_job
from app.cache import cache
from datetime import datetime

router = APIRouter(tags=["Settings"])


class ScanIntervalRequest(BaseModel):
    minutes: int = Field(..., ge=1, le=1440, description="Scan interval in minutes (1 – 1440)")


class ScanIntervalResponse(BaseModel):
    minutes: int
    message: str


@router.post(
    "/settings/scan-interval",
    response_model=APIResponse[ScanIntervalResponse],
    summary="Update the background scan interval at runtime",
    description=(
        "Reschedules the running APScheduler job to fire every `minutes` minutes. "
        "Takes effect immediately without restarting the server. "
        "The change is not persisted across server restarts — update SCAN_INTERVAL_MINUTES "
        "in .env to make it permanent."
    )
)
def update_scan_interval(body: ScanIntervalRequest):
    try:
        reschedule_scan_job(body.minutes)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reschedule job: {str(e)}")

    return APIResponse(
        success=True,
        message=f"Scan interval updated to {body.minutes} minute(s)",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=ScanIntervalResponse(
            minutes=body.minutes,
            message=f"Background scan job rescheduled to run every {body.minutes} minute(s). "
                    f"Update SCAN_INTERVAL_MINUTES in .env to persist across restarts."
        )
    )


@router.post(
    "/settings/clear-cache",
    response_model=APIResponse[dict],
    summary="Manually clear the Redis and memory cache",
    description="Flushes all cached scanner data and dashboard layouts."
)
def clear_cache():
    try:
        cache.clear()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear cache: {str(e)}")

    return APIResponse(
        success=True,
        message="Cache cleared successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={"cleared": True}
    )
