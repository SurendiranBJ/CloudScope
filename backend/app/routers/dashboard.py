from fastapi import APIRouter
from app.schemas import APIResponse, DashboardData
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from datetime import datetime

router = APIRouter(tags=["Dashboard"])

@router.get("/dashboard", response_model=APIResponse[DashboardData])
def get_dashboard_summary():
    data = cache.get("v1:dashboard")
    if not data:
        # If cache is cold, run scan manager to rebuild
        scan_manager.run_scan()
        data = cache.get("v1:dashboard")
        
    return APIResponse(
        success=True,
        message="Dashboard summary retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data
    )
