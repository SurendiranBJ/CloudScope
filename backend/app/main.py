import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime

from app.config import settings
from app.database import get_driver, close_driver
from app.utils.scheduler import start_scheduler, stop_scheduler
from app.schemas import APIResponse

# Set up logging reference
logger = logging.getLogger("backend")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    logger.info("Initializing IdentityScope Backend Engine Server")
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
    risks
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

app.include_router(api_v1_router)

# Health & Metrics Endpoints
@app.get("/health", tags=["Health"], response_model=APIResponse[dict])
def get_health():
    return APIResponse(
        success=True,
        message="Service is running normally",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={"status": "healthy", "service": "IdentityScope API"}
    )

@app.get("/ready", tags=["Health"], response_model=APIResponse[dict])
def get_readiness():
    neo4j_ready = False
    try:
        driver = get_driver()
        driver.verify_connectivity()
        neo4j_ready = True
    except Exception:
        pass

    return APIResponse(
        success=neo4j_ready,
        message="Readiness check finished",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data={
            "database_neo4j": "connected" if neo4j_ready else "disconnected",
            "ready": neo4j_ready
        }
    )
