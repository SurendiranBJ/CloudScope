"""
Health, Readiness, Liveness, and Metrics endpoints for CloudScope.
Adheres strictly to Phase 2 operations requirements:
- /live: memory-only liveness check (fast, no AWS/Neo4j/Redis)
- /ready: dependency readiness check (Neo4j, Redis, Relational DB)
- /health/aws: STS-based AWS connectivity diagnostic
- /health/dependencies: comprehensive dependency inspection
- /health: application version, commit SHA, build version, and runtime status
- /metrics: Prometheus-compatible telemetry endpoint
"""

import os
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, Response, Request
from fastapi.responses import PlainTextResponse

from app.schemas import APIResponse
from app.database import get_driver
from app.cache import cache
from app.persistence.database import check_db_connectivity
from app.services.aws.session import get_aws_diagnostic_info
from app.services.aws.region_cache import get_scan_mode_state
from app.metrics import get_metrics_output

router = APIRouter(tags=["Health & Operations"])

# Startup time and commit identification
START_TIME = datetime.now(timezone.utc).isoformat()
APP_VERSION = "2.0.0"
BUILD_VERSION = os.getenv("BUILD_VERSION", "2.0.0-phase2")

try:
    COMMIT_HASH = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        stderr=subprocess.DEVNULL
    ).decode("utf-8").strip()
except Exception:
    COMMIT_HASH = os.getenv("GIT_COMMIT", os.getenv("COMMIT_SHA", os.getenv("APP_VERSION", os.getenv("IMAGE_TAG", "unknown"))))


@router.get("/live", summary="Liveness probe for orchestrators/containers")
def get_liveness():
    """
    Memory-only liveness check.
    Must return 200 instantly without checking AWS, Neo4j, or Redis.
    """
    return {
        "status": "alive",
        "service": "CloudScope",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get("/ready", summary="Readiness probe for backend dependencies")
def get_readiness():
    """
    Readiness probe verifying core backend services (Neo4j, Redis, Relational DB).
    Container readiness does NOT depend on AWS API availability.
    """
    neo4j_ready = False
    try:
        driver = get_driver()
        driver.verify_connectivity()
        neo4j_ready = True
    except Exception:
        neo4j_ready = False

    redis_ready = cache.is_redis
    db_ready = check_db_connectivity()

    # Backend is considered ready if core services respond
    is_ready = neo4j_ready and redis_ready and db_ready

    data = {
        "ready": is_ready,
        "backend": "ok",
        "neo4j": "connected" if neo4j_ready else "disconnected",
        "redis": "connected" if redis_ready else "in-memory fallback",
        "database": "connected" if db_ready else "error",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    return APIResponse(
        success=is_ready,
        message="Backend dependencies ready" if is_ready else "One or more core dependencies unready",
        timestamp=datetime.now(timezone.utc).isoformat(),
        data=data
    )


def _get_aws_diag() -> dict:
    try:
        import app.main as main_mod
        if hasattr(main_mod, "get_aws_diagnostic_info"):
            return main_mod.get_aws_diagnostic_info()
    except Exception:
        pass
    return get_aws_diagnostic_info()


@router.get("/health/aws", summary="AWS STS diagnostic check")
def get_aws_health():
    """
    STS-based AWS credential and connectivity diagnostic.
    """
    diag = _get_aws_diag()
    return APIResponse(
        success=diag.get("authenticated", False),
        message="AWS connection verified" if diag.get("authenticated") else "AWS connection failed",
        timestamp=datetime.now(timezone.utc).isoformat(),
        data=diag
    )


@router.get("/health/dependencies", summary="Detailed multi-dependency health report")
def get_dependencies_health():
    """
    Detailed inspection of Redis, Neo4j, DB, and AWS.
    """
    neo4j_connected = False
    try:
        driver = get_driver()
        driver.verify_connectivity()
        neo4j_connected = True
    except Exception:
        pass

    db_connected = check_db_connectivity()
    aws_diag = get_aws_diagnostic_info()

    return APIResponse(
        success=True,
        message="Dependency status report",
        timestamp=datetime.now(timezone.utc).isoformat(),
        data={
            "redis": {
                "connected": cache.is_redis,
                "type": "redis" if cache.is_redis else "memory"
            },
            "neo4j": {
                "connected": neo4j_connected
            },
            "database": {
                "connected": db_connected
            },
            "aws": aws_diag
        }
    )


@router.get("/health", summary="Application version and runtime information")
def get_health():
    """
    Exposes build version, commit SHA, app version, and current scan configuration.
    Does NOT block on external AWS inventory scans.
    """
    try:
        mode_state = get_scan_mode_state()
    except Exception:
        mode_state = {"mode": "unknown", "selected_region": None, "resolved_regions": []}

    return APIResponse(
        success=True,
        message="CloudScope API is running",
        timestamp=datetime.now(timezone.utc).isoformat(),
        data={
            "status": "healthy",
            "service": "CloudScope API",
            "version": APP_VERSION,
            "build_version": BUILD_VERSION,
            "commit": COMMIT_HASH,
            "start_time": START_TIME,
            "scan_mode": mode_state.get("mode"),
            "selected_region": mode_state.get("selected_region"),
            "resolved_regions": mode_state.get("resolved_regions", []),
        }
    )


@router.get("/metrics", summary="Prometheus application metrics")
def get_metrics():
    """
    Prometheus text exposition format.
    """
    output, content_type = get_metrics_output()
    return PlainTextResponse(output.decode("utf-8"), media_type=content_type)
