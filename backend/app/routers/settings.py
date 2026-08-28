from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from app.schemas import APIResponse
from app.utils.scheduler import reschedule_scan_job
from app.utils.region_names import REGION_FRIENDLY_NAMES
from app.services.aws import region_cache
from app.services.scanner.scan_manager import scan_manager
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


# ---------------------------------------------------------------------------
# Region scanning endpoints
# ---------------------------------------------------------------------------

class ScanRegionRequest(BaseModel):
    mode: str = Field(..., description="Scan mode: 'single' or 'global'")
    region: Optional[str] = Field(None, description="AWS region code — required when mode is 'single'")


class ScanRegionResponse(BaseModel):
    mode: str
    region: Optional[str]
    scan_regions: list
    message: str


@router.post(
    "/settings/scan-region",
    response_model=APIResponse[ScanRegionResponse],
    summary="Change the active scan region at runtime",
    description=(
        "Updates the region(s) that the next scan will collect data from. "
        "'single' restricts collection to one region; 'global' sweeps all enabled AWS regions "
        "(significantly slower). "
        "Takes effect immediately — a new scan is triggered automatically after the mode change. "
        "The change is NOT persisted across server restarts — update SCAN_REGIONS in .env to make it permanent."
    )
)
def update_scan_region(body: ScanRegionRequest):
    if body.mode not in ("single", "global"):
        raise HTTPException(status_code=400, detail="mode must be 'single' or 'global'")

    if body.mode == "single" and not body.region:
        raise HTTPException(
            status_code=400,
            detail="region is required when mode is 'single'"
        )

    try:
        region_cache.set_scan_mode(body.mode, body.region)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update scan mode: {str(e)}")

    # Invalidate stale cache keys so the next poll gets fresh data
    for key in [
        "v1:dashboard", "v1:graph", "v1:risks", "v1:attack-paths",
        "v1:alerts", "v1:users", "v1:roles", "v1:policies", "v1:resources"
    ]:
        cache.invalidate(key)

    # Kick off a rescan immediately so the change is reflected without waiting
    scan_manager.trigger_async_scan()

    resolved = region_cache.get_all_regions()
    return APIResponse(
        success=True,
        message=f"Scan region updated to {body.mode} mode" + (f" ({body.region})" if body.region else ""),
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=ScanRegionResponse(
            mode=body.mode,
            region=body.region,
            scan_regions=resolved,
            message=(
                f"Scanning {body.region!r} only. Update SCAN_REGIONS in .env to persist across restarts."
                if body.mode == "single"
                else "Scanning all enabled AWS regions. Update SCAN_REGIONS in .env or omit it to persist across restarts."
            )
        )
    )


class RegionOption(BaseModel):
    code: str
    friendly_name: str


@router.get(
    "/settings/available-regions",
    response_model=APIResponse[list[RegionOption]],
    summary="List available AWS regions for the scan-region selector",
    description=(
        "Returns a static list of well-known AWS region codes with friendly display names, "
        "plus a 'global' pseudo-option. Intended to populate the frontend region dropdown "
        "without requiring an AWS API call."
    )
)
def get_available_regions():
    options: list[RegionOption] = [
        RegionOption(code="global", friendly_name="🌍 Global — All Regions")
    ]
    for code, friendly in REGION_FRIENDLY_NAMES.items():
        options.append(RegionOption(code=code, friendly_name=friendly))

    return APIResponse(
        success=True,
        message="Available regions retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=options
    )
