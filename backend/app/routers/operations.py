"""
Operations & System Health Overview router.
Restricted to ADMINISTRATOR role.
Provides real-time visibility into scanner locks, scheduler state, durable history,
recent audit events, and service health without exposing credentials.
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from datetime import datetime, timezone

from app.schemas import APIResponse
from app.security.dependencies import require_admin
from app.security.models import AuthenticatedUser
from app.services.scanner.distributed_lock import scan_lock
from app.services.scanner.scan_coordinator import scan_coordinator
from app.persistence.repository import (
    get_recent_scan_runs,
    get_latest_snapshot,
    DatabaseQueryError,
)
from app.services.audit.audit_service import audit_service
from app.services.aws.region_cache import get_scan_mode_state
from app.database import get_driver
from app.cache import cache
from app.persistence.database import check_db_connectivity
from app.routers.health import (
    APP_VERSION,
    BUILD_VERSION,
    COMMIT_HASH,
    START_TIME,
    START_DATETIME,
)

router = APIRouter(prefix="/operations", tags=["Operations"])


class ScannerInfoSchema(BaseModel):
    is_scanning: bool
    active_phase: str
    mode: str
    current_scan_id: Optional[str] = None
    current_snapshot_id: Optional[str] = None
    progress: int = 0
    resolved_regions: List[str] = []


class LockInfoSchema(BaseModel):
    locked: bool
    owner_instance_id: Optional[str] = None
    acquired_at: Optional[str] = None
    ttl_seconds: int = 0
    stale: bool = False


class DependencyStatusSchema(BaseModel):
    neo4j: bool
    redis: bool
    database: bool


class MetricsSummarySchema(BaseModel):
    last_scan_duration_seconds: Optional[float] = None
    last_scan_status: Optional[str] = None
    historical_failed_regions: List[str] = []
    recent_collector_failure_count: int = 0


class ScanRunItemSchema(BaseModel):
    scan_id: str
    snapshot_id: Optional[str] = None
    status: str
    started_at: str
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    scan_mode: str = "global"
    resolved_regions: List[str] = []
    successful_regions: List[str] = []
    failed_regions: List[str] = []
    active_phase: str = "IDLE"
    total_collectors: int = 12
    completed_collectors: int = 0
    error_summary: Optional[str] = None
    created_by: str = "system"
    trigger_type: str = "MANUAL"


class AuditEventItemSchema(BaseModel):
    id: Optional[str] = None
    event_id: Optional[str] = None
    event_time: Optional[str] = None
    timestamp: Optional[str] = None
    actor_id: str
    actor_role: str
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    scan_id: Optional[str] = None
    snapshot_id: Optional[str] = None
    result: str = "SUCCESS"
    error_code: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = {}


class OperationsOverviewData(BaseModel):
    timestamp: str
    commit_hash: str
    build_version: str
    app_version: str
    uptime_seconds: float
    scanner: ScannerInfoSchema
    distributed_lock: LockInfoSchema
    dependencies: DependencyStatusSchema
    metrics_summary: MetricsSummarySchema
    recent_scans: List[ScanRunItemSchema]
    latest_snapshot: Optional[Dict[str, Any]] = None
    recent_audit_events: List[AuditEventItemSchema] = []
    system_status: str
    database_status: str
    database_error: Optional[str] = None

    # Legacy nested fields
    version_info: Optional[Dict[str, Any]] = None
    system_health: Optional[Dict[str, Any]] = None
    scan_coordination: Optional[Dict[str, Any]] = None
    durable_state: Optional[Dict[str, Any]] = None


@router.get("/overview", response_model=APIResponse[OperationsOverviewData])
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

    # Health checks
    neo4j_ok = False
    try:
        driver = get_driver()
        driver.verify_connectivity()
        neo4j_ok = True
    except Exception:
        neo4j_ok = False

    redis_ok = cache.is_redis

    # Database connectivity and durable scan runs
    db_ok = False
    db_error = None
    recent_runs: List[Dict[str, Any]] = []
    latest_snapshot = None

    try:
        db_ok = check_db_connectivity()
        if db_ok:
            recent_runs = get_recent_scan_runs(limit=10)
            latest_snapshot = get_latest_snapshot()
        else:
            db_error = "Database connectivity check failed"
    except Exception as e:
        db_ok = False
        db_error = f"Database query failed: {str(e)}"

    # Audit events
    recent_audits = []
    if db_ok:
        try:
            raw_audits = audit_service.get_events(limit=5)
            recent_audits = [
                {
                    "id": a.get("event_id"),
                    "event_id": a.get("event_id"),
                    "event_time": a.get("timestamp"),
                    "timestamp": a.get("timestamp"),
                    "actor_id": a.get("actor_id", "system"),
                    "actor_role": a.get("actor_role", "SYSTEM"),
                    "action": a.get("action", ""),
                    "resource_type": a.get("resource_type"),
                    "resource_id": a.get("resource_id"),
                    "scan_id": a.get("scan_id"),
                    "snapshot_id": a.get("snapshot_id"),
                    "result": a.get("result", "SUCCESS"),
                    "error_code": a.get("error_code"),
                    "ip_address": a.get("ip_address"),
                    "user_agent": a.get("user_agent"),
                    "metadata": a.get("metadata", {}),
                }
                for a in raw_audits
            ]
        except Exception:
            recent_audits = []

    # Calculate real uptime
    uptime_sec = max(0.0, (datetime.now(timezone.utc) - START_DATETIME).total_seconds())

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

    completed_c = coord_status.get("completed_collectors", 0)
    total_c = coord_status.get("total_collectors", 12) or 12
    progress_pct = int(round((completed_c / total_c) * 100)) if total_c > 0 else 0

    scanner_info = {
        "is_scanning": bool(coord_status.get("is_scanning", False)),
        "active_phase": coord_status.get("active_phase") or ("SCANNING" if coord_status.get("is_scanning") else "READY"),
        "mode": mode_state.get("mode") or "global",
        "current_scan_id": coord_status.get("current_scan_id"),
        "current_snapshot_id": coord_status.get("current_snapshot_id"),
        "progress": progress_pct,
        "resolved_regions": mode_state.get("resolved_regions", []),
    }

    owner = lock_info.get("owner_token")
    lock_data = {
        "locked": bool(lock_info.get("is_locked", False)),
        "owner_instance_id": f"{owner[:8]}..." if owner else None,
        "acquired_at": None,
        "ttl_seconds": int(lock_info.get("ttl_seconds", lock_info.get("ttl", 0)) or 0),
        "stale": False,
    }

    dep_data = {
        "neo4j": neo4j_ok,
        "redis": redis_ok,
        "database": db_ok,
    }

    metrics_data = {
        "last_scan_duration_seconds": last_run_duration,
        "last_scan_status": last_run_status,
        "historical_failed_regions": sorted(list(failed_regions_set)),
        "recent_collector_failure_count": collector_failures,
    }

    system_status = "HEALTHY" if (neo4j_ok and redis_ok and db_ok) else "DEGRADED"
    database_status = "HEALTHY" if db_ok else "ERROR"

    overview_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "commit_hash": COMMIT_HASH,
        "build_version": BUILD_VERSION,
        "app_version": APP_VERSION,
        "uptime_seconds": uptime_sec,
        "scanner": scanner_info,
        "distributed_lock": lock_data,
        "dependencies": dep_data,
        "metrics_summary": metrics_data,
        "recent_scans": recent_runs,
        "latest_snapshot": latest_snapshot,
        "recent_audit_events": recent_audits,
        "system_status": system_status,
        "database_status": database_status,
        "database_error": db_error,

        # Backward compatibility namespaces
        "version_info": {
            "version": APP_VERSION,
            "build_version": BUILD_VERSION,
            "commit_sha": COMMIT_HASH,
            "uptime_started_at": START_TIME,
        },
        "system_health": {
            "overall": "healthy" if system_status == "HEALTHY" else "degraded",
            "neo4j": "connected" if neo4j_ok else "disconnected",
            "redis": "connected" if redis_ok else "in-memory fallback",
            "database": "connected" if db_ok else "error",
        },
        "scan_coordination": {
            "is_scanning": scanner_info["is_scanning"],
            "current_scan_id": scanner_info["current_scan_id"],
            "current_snapshot_id": scanner_info["current_snapshot_id"],
            "active_phase": scanner_info["active_phase"],
            "scan_mode": scanner_info["mode"],
            "resolved_regions": scanner_info["resolved_regions"],
        },
        "durable_state": {
            "latest_published_snapshot": latest_snapshot,
            "recent_scan_runs": recent_runs,
        },
        "distributed_lock": lock_data,
        "metrics_summary": metrics_data,
    }

    return APIResponse(
        success=True,
        message="Operations overview retrieved successfully",
        timestamp=datetime.now(timezone.utc).isoformat(),
        data=overview_data
    )
