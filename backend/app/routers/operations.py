"""
Operations & System Health Overview router.
Restricted to ADMINISTRATOR role.
Provides real-time visibility into scanner locks, scheduler state, durable history,
recent audit events, and service health without exposing credentials.
"""

from typing import Dict, Any
from fastapi import APIRouter, Depends, Request
from datetime import datetime, timezone

from app.schemas import APIResponse
from app.security.dependencies import require_admin
from app.security.models import AuthenticatedUser
from app.services.scanner.distributed_lock import scan_lock
from app.services.scanner.scan_coordinator import scan_coordinator
from app.persistence.repository import get_recent_scan_runs, get_latest_snapshot
from app.services.audit.audit_service import audit_service
from app.services.aws.region_cache import get_scan_mode_state
from app.database import get_driver
from app.cache import cache
from app.persistence.database import check_db_connectivity
from app.routers.health import APP_VERSION, BUILD_VERSION, COMMIT_HASH, START_TIME

router = APIRouter(prefix="/operations", tags=["Operations"])


@router.get("/overview", response_model=APIResponse[Dict[str, Any]])
def get_operations_overview(
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin)
):
    """
    Administrator operational health dashboard endpoint.
    Aggregates distributed lock status, scanner state, durable scan runs,
    system health, and audit trail highlights.
    """
    # Scanner status and lock details
    coord_status = scan_coordinator.get_status()
    lock_info = scan_lock.get_lock_info()

    # Durable scan runs
    recent_runs = get_recent_scan_runs(limit=10)
    latest_snapshot = get_latest_snapshot()

    # Health checks
    neo4j_ok = False
    try:
        driver = get_driver()
        driver.verify_connectivity()
        neo4j_ok = True
    except Exception:
        neo4j_ok = False

    redis_ok = cache.is_redis
    db_ok = check_db_connectivity()

    # Recent audit events (last 5)
    recent_audits = audit_service.get_events(limit=5)

    # Collector summary & failure statistics from recent runs
    collector_failures = 0
    failed_regions_set = set()
    last_run_duration = None
    last_run_status = None

    if recent_runs:
        latest_run = recent_runs[0]
        last_run_duration = latest_run.get("duration_seconds")
        last_run_status = latest_run.get("status")
        for run in recent_runs:
            for r in run.get("failed_regions", []):
                failed_regions_set.add(r)
            completed_c = run.get("completed_collectors", 0)
            total_c = run.get("total_collectors", 0)
            if total_c > completed_c:
                collector_failures += (total_c - completed_c)

    try:
        mode_state = get_scan_mode_state()
    except Exception:
        mode_state = {"mode": "unknown", "selected_region": None, "resolved_regions": []}

    overview_data = {
        "version_info": {
            "version": APP_VERSION,
            "build_version": BUILD_VERSION,
            "commit_sha": COMMIT_HASH,
            "uptime_started_at": START_TIME,
        },
        "system_health": {
            "overall": "healthy" if (neo4j_ok and redis_ok and db_ok) else "degraded",
            "neo4j": "connected" if neo4j_ok else "disconnected",
            "redis": "connected" if redis_ok else "in-memory fallback",
            "database": "connected" if db_ok else "error",
        },
        "scan_coordination": {
            "is_scanning": coord_status["is_scanning"],
            "current_scan_id": coord_status["current_scan_id"],
            "current_snapshot_id": coord_status["current_snapshot_id"],
            "active_phase": coord_status["active_phase"],
            "scan_mode": mode_state.get("mode"),
            "resolved_regions": mode_state.get("resolved_regions", []),
        },
        "distributed_lock": {
            "is_locked": lock_info["is_locked"],
            "owner_token": lock_info["owner_token"][:8] + "..." if lock_info["owner_token"] else None,
            "time_to_live_seconds": lock_info["ttl"],
        },
        "metrics_summary": {
            "last_scan_duration_seconds": last_run_duration,
            "last_scan_status": last_run_status,
            "historical_failed_regions": sorted(list(failed_regions_set)),
            "recent_collector_failure_count": collector_failures,
        },
        "durable_state": {
            "latest_published_snapshot": latest_snapshot,
            "recent_scan_runs": recent_runs,
        },
        "recent_audit_events": recent_audits,
    }

    return APIResponse(
        success=True,
        message="Operations overview retrieved successfully",
        timestamp=datetime.now(timezone.utc).isoformat(),
        data=overview_data
    )
