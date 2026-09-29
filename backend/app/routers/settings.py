from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone

from app.schemas import APIResponse
from app.utils.scheduler import reschedule_scan_job
from app.utils.region_names import REGION_FRIENDLY_NAMES
from app.services.aws import region_cache
from app.services.scanner.scan_coordinator import scan_coordinator
from app.cache import cache
from app.security.dependencies import require_admin, require_viewer
from app.security.models import AuthenticatedUser
from app.services.audit.audit_service import audit_service

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
    description="Reschedules the running scan job. Restricted to ADMINISTRATOR."
)
def update_scan_interval(
    body: ScanIntervalRequest,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin)
):
    try:
        reschedule_scan_job(body.minutes)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reschedule job: {str(e)}")

    client_ip = request.client.host if request.client else None
    audit_service.log(
        action="SCAN_INTERVAL_CHANGED",
        actor_id=current_user.subject,
        actor_role=current_user.highest_role.value if current_user.highest_role else "UNKNOWN",
        resource_type="settings",
        resource_id="scan_interval",
        result="SUCCESS",
        ip_address=client_ip,
        metadata={"new_interval_minutes": body.minutes}
    )

    return APIResponse(
        success=True,
        message=f"Scan interval updated to {body.minutes} minute(s)",
        timestamp=datetime.now(timezone.utc).isoformat(),
        data=ScanIntervalResponse(
            minutes=body.minutes,
            message=f"Background scan job rescheduled to run every {body.minutes} minute(s)."
        )
    )


@router.post(
    "/settings/clear-cache",
    response_model=APIResponse[dict],
    summary="Manually clear the Redis and memory cache",
    description="Restricted to ADMINISTRATOR."
)
def clear_cache(
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin)
):
    try:
        cache.clear()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear cache: {str(e)}")

    client_ip = request.client.host if request.client else None
    audit_service.log(
        action="CACHE_CLEARED",
        actor_id=current_user.subject,
        actor_role=current_user.highest_role.value if current_user.highest_role else "UNKNOWN",
        resource_type="cache",
        resource_id="all",
        result="SUCCESS",
        ip_address=client_ip
    )

    return APIResponse(
        success=True,
        message="Cache cleared successfully",
        timestamp=datetime.now(timezone.utc).isoformat(),
        data={"cleared": True}
    )


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
    description="Restricted to ADMINISTRATOR."
)
def update_scan_region(
    body: ScanRegionRequest,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin)
):
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

    client_ip = request.client.host if request.client else None
    audit_service.log(
        action="REGION_CONFIGURATION_CHANGED",
        actor_id=current_user.subject,
        actor_role=current_user.highest_role.value if current_user.highest_role else "UNKNOWN",
        resource_type="settings",
        resource_id="scan_region",
        result="SUCCESS",
        ip_address=client_ip,
        metadata={"mode": body.mode, "region": body.region}
    )

    # Kick off rescan via coordinator
    scan_coordinator.request_scan(trigger_type="REGION_CHANGE", created_by=current_user.subject)

    resolved = region_cache.get_all_regions()
    return APIResponse(
        success=True,
        message=f"Scan region updated to {body.mode} mode" + (f" ({body.region})" if body.region else ""),
        timestamp=datetime.now(timezone.utc).isoformat(),
        data=ScanRegionResponse(
            mode=body.mode,
            region=body.region,
            scan_regions=resolved,
            message=(
                f"Scanning {body.region!r} only."
                if body.mode == "single"
                else "Scanning all enabled AWS regions."
            )
        )
    )


class RegionOption(BaseModel):
    code: str
    friendly_name: str


@router.get(
    "/settings/available-regions",
    response_model=APIResponse[list[RegionOption]],
    summary="List available AWS regions for the scan-region selector"
)
def get_available_regions(
    current_user: AuthenticatedUser = Depends(require_viewer)
):
    options: list[RegionOption] = [
        RegionOption(code="global", friendly_name="🌍 Global — All Regions")
    ]
    for code, friendly in REGION_FRIENDLY_NAMES.items():
        options.append(RegionOption(code=code, friendly_name=friendly))

    return APIResponse(
        success=True,
        message="Available regions retrieved successfully",
        timestamp=datetime.now(timezone.utc).isoformat(),
        data=options
    )
