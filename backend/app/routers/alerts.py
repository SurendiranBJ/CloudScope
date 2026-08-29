from fastapi import APIRouter
from typing import List
from app.schemas import APIResponse, SecurityAlert, CorrelatedRiskFinding
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from datetime import datetime

router = APIRouter(tags=["Security Alerts & Activity"])


@router.get("/alerts", response_model=APIResponse[List[SecurityAlert]])
def get_security_alerts():
    """Retrieve security audit alerts discovered from CloudTrail and security configurations."""
    data = cache.get("v1:alerts")
    if not data:
        if not scan_manager.is_running:
            scan_manager.trigger_async_scan()
        data = []

    return APIResponse(
        success=True,
        message="Threat alerts and config drift logs retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data
    )


@router.get("/correlated-risks", response_model=APIResponse[List[CorrelatedRiskFinding]])
def get_correlated_risks():
    """Retrieve security findings correlating observed CloudTrail runtime activity with static IAM attack paths."""
    data = cache.get("v1:correlated_risks")
    if data is None:
        if not scan_manager.is_running:
            scan_manager.trigger_async_scan()
        data = []

    return APIResponse(
        success=True,
        message="Correlated security activity findings retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data
    )
