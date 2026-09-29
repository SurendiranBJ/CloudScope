import logging
import os
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, APIRouter, Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import get_driver, close_driver
from app.persistence.database import init_db
from app.utils.scheduler import start_scheduler, stop_scheduler
from app.utils.logging_config import configure_logging
from app.middleware.request_id import RequestCorrelationMiddleware, get_current_request_id
from app.metrics import http_requests_total, http_request_duration_seconds, rate_limit_rejections_total
from app.services.aws.session import get_aws_diagnostic_info

# Configure structured logging
configure_logging()
logger = logging.getLogger("backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    logger.info("Initializing CloudScope Production Backend Engine Server")

    # 1. Enforce centralized startup configuration validation
    from app.security.config_validator import validate_startup_configuration
    validate_startup_configuration()

    # Display DEV_AUTH_MODE security warning if enabled
    dev_auth = os.getenv("DEV_AUTH_MODE", "false").lower() == "true"
    if dev_auth:
        logger.warning(
            "*** SECURITY WARNING: DEV_AUTH_MODE IS ENABLED. "
            "AUTHENTICATION TOKENS ARE BYPASSED VIA X-DEV-ROLE. "
            "DO NOT RUN WITH DEV_AUTH_MODE=true IN PRODUCTION ENVIRONMENTS! ***"
        )

    try:
        # Initialize relational database schemas (SQLite / PostgreSQL)
        init_db()

        # Recover authoritative published snapshot from durable SQL
        from app.services.scanner.snapshot_store import snapshot_store
        recovered = snapshot_store.recover_from_sql()
        if recovered:
            logger.info(f"Durable snapshot {recovered.snapshot_id} successfully restored from SQL on startup.")
        else:
            logger.info("No prior durable snapshot found in SQL.")

        # Initialize Neo4j driver
        get_driver()
        # Start distributed-safe scheduler
        start_scheduler()
    except Exception as e:
        logger.critical(f"Server startup failed: {str(e)}", exc_info=True)
        if os.getenv("ENVIRONMENT", "").lower() == "production":
            raise

    yield

    # Shutdown actions
    logger.info("De-initializing CloudScope Backend Engine Server")
    stop_scheduler()
    close_driver()


app = FastAPI(
    title="CloudScope REST API",
    description="Production-grade cloud security posture and lateral movement analysis engine.",
    version="2.0.0",
    lifespan=lifespan
)

# 1. Mount Request Correlation Middleware
app.add_middleware(RequestCorrelationMiddleware)

# 2. CORS Policy configuration
# Ensure credentials cannot be combined with wildcard origin
cors_origins = [o.strip() for o in settings.CORS_ORIGINS if o.strip()]
allow_creds = True
if "*" in cors_origins:
    if os.getenv("ENVIRONMENT", "development").lower() == "production":
        logger.warning("CORS wildcard '*' with credentials detected in production. Restricting wildcard credentials.")
        allow_creds = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=allow_creds,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "Retry-After"],
)


# Telemetry middleware for Prometheus HTTP metrics
@app.middleware("http")
async def prometheus_metrics_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration = time.perf_counter() - start

    path = request.url.path
    # Group parameterized IDs for Prometheus labels to avoid high cardinality
    if not (path == "/metrics" or path == "/live"):
        route_label = path
        if "/findings/find-" in path:
            route_label = "/api/v1/findings/{id}"
        elif "/simulation/changes/" in path:
            route_label = "/api/v1/simulation/changes/{id}"
        elif "/policies/arn:" in path:
            route_label = "/api/v1/policies/{id}"

        http_requests_total.labels(
            method=request.method,
            endpoint=route_label,
            status_code=str(response.status_code)
        ).inc()

        http_request_duration_seconds.labels(
            method=request.method,
            endpoint=route_label
        ).observe(duration)

    return response


# ---------------------------------------------------------------------------
# Global Exception Handlers (Standardized & Sanitized Response Format)
# ---------------------------------------------------------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    req_id = getattr(request.state, "request_id", None) or get_current_request_id()

    headers = dict(exc.headers or {})
    if req_id:
        headers["X-Request-ID"] = req_id

    if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
        rate_limit_rejections_total.labels(category="general").inc()

    # Detail might already be a dict from rate_limiter or a simple string
    if isinstance(exc.detail, dict):
        body = {
            "success": False,
            "detail": exc.detail.get("error", {}).get("message", str(exc.detail)),
            "error": exc.detail.get("error", {
                "code": f"HTTP_{exc.status_code}",
                "message": str(exc.detail)
            }),
            "request_id": req_id
        }
        if "retry_after" in exc.detail:
            body["retry_after"] = exc.detail["retry_after"]
    else:
        body = {
            "success": False,
            "detail": exc.detail,
            "error": {
                "code": f"HTTP_{exc.status_code}",
                "message": exc.detail
            },
            "request_id": req_id
        }

    return JSONResponse(status_code=exc.status_code, content=body, headers=headers)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    req_id = getattr(request.state, "request_id", None) or get_current_request_id()
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "success": False,
            "detail": exc.errors(),
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Invalid request parameter or payload",
                "details": exc.errors()
            },
            "request_id": req_id
        },
        headers={"X-Request-ID": req_id} if req_id else None
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    req_id = getattr(request.state, "request_id", None) or get_current_request_id()
    logger.error(f"Internal server error processing {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected server error occurred. Please contact your administrator."
            },
            "request_id": req_id
        },
        headers={"X-Request-ID": req_id} if req_id else None
    )


# ---------------------------------------------------------------------------
# API Routers Mount
# ---------------------------------------------------------------------------
api_v1_router = APIRouter(prefix="/api/v1")

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
    settings as settings_router,
    policies,
    simulation,
    relationships,
    findings,
    audit,
    operations,
    health
)

# Mount Routers under /api/v1
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
api_v1_router.include_router(settings_router.router)
api_v1_router.include_router(policies.router)
api_v1_router.include_router(simulation.router)
api_v1_router.include_router(relationships.router)
api_v1_router.include_router(findings.router)
api_v1_router.include_router(audit.router)
api_v1_router.include_router(operations.router)
api_v1_router.include_router(health.router)

app.include_router(api_v1_router)

# Mount root health and liveness endpoints for Docker/Kubernetes/Prometheus
app.include_router(health.router)
