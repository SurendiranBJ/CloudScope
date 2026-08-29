import logging
import subprocess
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime

from app.config import settings
from app.database import get_driver, close_driver
from app.utils.scheduler import start_scheduler, stop_scheduler
from app.schemas import APIResponse
from app.cache import cache
from app.services.aws.region_cache import get_all_regions, get_scan_mode_state

# Set up logging reference
logger = logging.getLogger("backend")

# Retrieve git commit hash at startup
try:
    commit_hash = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], 
        stderr=subprocess.DEVNULL
    ).decode("utf-8").strip()
except Exception:
    commit_hash = os.getenv("GIT_COMMIT", "unknown")

start_time = datetime.utcnow().isoformat() + "Z"

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    logger.info("Initializing IdentityScope Backend Engine Server")
    
    # Proactively clear cache on startup to prevent serving stale layout shapes
    try:
        logger.info("Clearing cache at engine startup")
        cache.clear()
    except Exception as cache_err:
        logger.warning(f"Cache clear during startup failed: {str(cache_err)}")

    try:
        get_driver()  # Initialize Neo4j pool
        start_scheduler()  # Start APScheduler cron scan job
    except Exception as e:
        logger.critical(f"Server startup failed: {str(e)}")
    
    yield
    
    # Shutdown actions
    logger.info("De-initializing IdentityScope Backend Engine Server")
    stop_scheduler()
    close_driver()

app = FastAPI(
    title="IdentityScope REST API",
    description="Backend API mapping AWS IAM configuration vulnerabilities and lateral privilege escalation paths.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Policy configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API v1 Router group
api_v1_router = APIRouter(prefix="/api/v1")

# Import Routers
from app.routers import (
    dashboard,
    users,
    roles,
    resources,
    graph,
    attack_paths,
    alerts,
    reports,
    scan,
    copilot,
    risks,
    settings
)

# Mount Routers
api_v1_router.include_router(dashboard.router)
api_v1_router.include_router(users.router)
api_v1_router.include_router(roles.router)
api_v1_router.include_router(resources.router)
api_v1_router.include_router(graph.router)
api_v1_router.include_router(attack_paths.router)
api_v1_router.include_router(alerts.router)
api_v1_router.include_router(reports.router)
api_v1_router.include_router(scan.router)
api_v1_router.include_router(copilot.router)
api_v1_router.include_router(risks.router)
api_v1_router.include_router(settings.router)

app.include_router(api_v1_router)

from app.services.aws.session import get_aws_diagnostic_info

# Health & Metrics Endpoints
@api_v1_router.get("/health/aws", tags=["Health"], response_model=APIResponse[dict])
def get_api_v1_aws_health():
    diag = get_aws_diagnostic_info()
    return APIResponse(
        success=diag["authenticated"],
        message="AWS connection verified" if diag["authenticated"] else "AWS connection failed",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=diag
    )

@app.get("/health/aws", tags=["Health"], response_model=APIResponse[dict])
def get_aws_health():
    diag = get_aws_diagnostic_info()
    return APIResponse(
        success=diag["authenticated"],
        message="AWS connection verified" if diag["authenticated"] else "AWS connection failed",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=diag
    )

@api_v1_router.get("/health", tags=["Health"], response_model=APIResponse[dict])
def get_api_v1_health():
    try:
        regions = get_all_regions()
        mode_state = get_scan_mode_state()
    except Exception:
        regions = "unavailable (check AWS credentials)"
        mode_state = {"mode": "unknown", "selected_region": None}

    aws_diag = get_aws_diagnostic_info()

    return APIResponse(
        success=True,
        message="Service is running normally",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={
            "status": "healthy",
            "service": "CloudScope API",
            "commit": commit_hash,
            "start_time": start_time,
            "scan_regions": regions,
            "scan_mode": mode_state["mode"],
            "selected_region": mode_state["selected_region"],
            "aws_authenticated": aws_diag["authenticated"],
            "aws_account_id": aws_diag["account_id"],
            "aws_arn": aws_diag["arn"]
        }
    )

@app.get("/health", tags=["Health"], response_model=APIResponse[dict])
def get_health():
    aws_diag = get_aws_diagnostic_info()
    return APIResponse(
        success=True,
        message="Service is running normally",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={
            "status": "healthy",
            "service": "CloudScope API",
            "aws_authenticated": aws_diag["authenticated"]
        }
    )

@app.get("/ready", tags=["Health"], response_model=APIResponse[dict])
@api_v1_router.get("/ready", tags=["Health"], response_model=APIResponse[dict])
def get_readiness():
    neo4j_ready = False
    try:
        driver = get_driver()
        driver.verify_connectivity()
        neo4j_ready = True
    except Exception:
        pass

    aws_diag = get_aws_diagnostic_info()

    return APIResponse(
        success=aws_diag["authenticated"],
        message="Readiness check finished",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={
            "backend": "ok",
            "aws": "ok" if aws_diag["authenticated"] else "failed",
            "neo4j": "connected" if neo4j_ready else "disconnected",
            "redis": "connected" if cache.is_redis else "in-memory fallback",
            "aws_account": aws_diag.get("account_id"),
            "aws_arn": aws_diag.get("arn"),
            "ready": aws_diag["authenticated"]
        }
    )
