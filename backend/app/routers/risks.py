from fastapi import APIRouter
from typing import List
from app.schemas import APIResponse, RiskFinding
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from datetime import datetime

router = APIRouter(tags=["Risk"])

@router.get("/risk-assessment", response_model=APIResponse[List[RiskFinding]])
def get_risk_assessment_findings():
    data = cache.get("v1:risks")
    if not data:
        # Cache is cold — trigger async scan if not already running and
        # return an empty list immediately so the frontend can poll.
        if not scan_manager.is_running:
            scan_manager.trigger_async_scan()
        data = []
        
    return APIResponse(
        success=True,
        message="Risk assessment findings retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data
    )
