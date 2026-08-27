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
        # Cache is cold — trigger async scan if not already running
        if not scan_manager.is_running:
            scan_manager.trigger_async_scan()
        # Return a minimal placeholder so the frontend doesn't crash
        data = {
            "securityScore": "-- / 100",
            "stats": {"users": 0, "roles": 0, "policies": 0, "risks": 0, "paths": 0, "resources": 0},
            "riskDistribution": [
                {"name": "Critical", "value": 0, "color": "#EF4444"},
                {"name": "High", "value": 0, "color": "#F59E0B"},
                {"name": "Medium", "value": 0, "color": "#3B82F6"},
                {"name": "Low", "value": 0, "color": "#10B981"}
            ],
            "recentAlerts": [],
            "criticalPaths": [],
            "recommendations": [{"title": "Scanning...", "desc": "Your AWS environment is being scanned. Data will appear shortly."}],
            "lastScan": None,
            "topRiskyIdentities": [],
            "resourceBreakdown": []
        }

    return APIResponse(
        success=True,
        message="Dashboard summary retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data
    )
