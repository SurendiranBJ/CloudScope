from fastapi import APIRouter
from app.schemas import APIResponse, DashboardData
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from datetime import datetime

router = APIRouter(tags=["Dashboard"])


@router.get("/dashboard", response_model=APIResponse[DashboardData])
def get_dashboard_summary():
    status_info = scan_manager.get_status()
    is_scanning = status_info.get("is_scanning", False)
    current_scan_status = status_info.get("scan_status", "IDLE")
    last_error = status_info.get("last_error")
    scan_id = status_info.get("scan_id")
    last_successful_at = status_info.get("last_successful_scan_at")
    last_successful_id = status_info.get("last_successful_scan_id")
    service_status = status_info.get("service_status", {})

    cached_dashboard = cache.get("v1:dashboard")
    if (
        cached_dashboard 
        and isinstance(cached_dashboard, dict) 
        and "stats" in cached_dashboard 
        and "riskDistribution" in cached_dashboard
        and "resourceBreakdown" in cached_dashboard
        and "topRiskyIdentities" in cached_dashboard
    ):
        data = dict(cached_dashboard)
        if is_scanning:
            data["scanStatus"] = "SCANNING"
        elif current_scan_status == "FAILED":
            data["scanStatus"] = "FAILED"
            data["lastError"] = last_error
        elif current_scan_status == "PARTIAL":
            data["scanStatus"] = "PARTIAL"
        else:
            data["scanStatus"] = cached_dashboard.get("scanStatus", "SUCCESS")

        data["scanId"] = scan_id or data.get("scanId")
        data["lastSuccessfulScanAt"] = last_successful_at or data.get("lastSuccessfulScanAt")
        data["lastSuccessfulScanId"] = last_successful_id or data.get("lastSuccessfulScanId")
        data["lastError"] = last_error if current_scan_status == "FAILED" else data.get("lastError")
        data["serviceStatus"] = service_status or data.get("serviceStatus")
        data["failedRegions"] = status_info.get("failed_regions") or data.get("failedRegions") or []
        data["successfulRegions"] = status_info.get("successful_regions") or data.get("successfulRegions") or []
        data["scanMode"] = status_info.get("scan_mode") or data.get("scanMode")
        data["resolvedRegions"] = status_info.get("resolved_regions") or data.get("resolvedRegions") or data.get("scannedRegions") or []

        return APIResponse(
            success=True,
            message="Dashboard summary retrieved successfully",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data=data
        )

    # Cache is empty (no completed scan yet)
    effective_status = "NO_SCAN"
    if is_scanning:
        effective_status = "SCANNING"
    elif current_scan_status == "FAILED":
        effective_status = "FAILED"
    else:
        # Trigger initial async scan if idle
        scan_manager.trigger_async_scan()
        effective_status = "SCANNING"

    empty_data = {
        "securityScore": "Scanning..." if effective_status == "SCANNING" else "N/A",
        "stats": {
            "users": 0,
            "roles": 0,
            "policies": 0,
            "risks": 0,
            "paths": 0,
            "resources": 0
        },
        "riskDistribution": [
            {"name": "Critical", "value": 0, "color": "#EF4444"},
            {"name": "High", "value": 0, "color": "#F59E0B"},
            {"name": "Medium", "value": 0, "color": "#3B82F6"},
            {"name": "Low", "value": 0, "color": "#10B981"}
        ],
        "activityMetrics": {
            "staticAttackPaths": 0,
            "observedSecurityEvents": 0,
            "correlatedFindings": 0,
            "observedAttackActivity": 0
        },
        "recentAlerts": [],
        "criticalPaths": [],
        "recommendations": [
            {"title": "Security Scan In Progress", "desc": "Live cloud scan is gathering inventory and calculating risk posture."}
        ] if effective_status == "SCANNING" else [],
        "lastScan": None,
        "topRiskyIdentities": [],
        "resourceBreakdown": [],
        "scanId": scan_id,
        "scanStatus": effective_status,
        "lastSuccessfulScanAt": last_successful_at,
        "lastSuccessfulScanId": last_successful_id,
        "lastError": last_error,
        "serviceStatus": service_status
    }

    return APIResponse(
        success=True,
        message="Dashboard status retrieved",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=empty_data
    )
