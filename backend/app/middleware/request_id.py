"""
Request ID and Correlation Middleware for FastAPI.
Extracts or generates an X-Request-ID, assigns it to request.state and contextvars,
logs request execution with structured metadata, and appends X-Request-ID to response headers.
"""

import time
import uuid
import logging
from contextvars import ContextVar
from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Context variable for thread/task correlation
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")
scan_id_ctx: ContextVar[str] = ContextVar("scan_id", default="")
snapshot_id_ctx: ContextVar[str] = ContextVar("snapshot_id", default="")

logger = logging.getLogger("cloudscope.access")


def get_current_request_id() -> str:
    return request_id_ctx.get()


class RequestCorrelationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Check if incoming request provided X-Request-ID, otherwise generate UUID4
        req_id = request.headers.get("X-Request-ID")
        if not req_id or not req_id.strip():
            req_id = str(uuid.uuid4())

        request.state.request_id = req_id
        token = request_id_ctx.set(req_id)

        start_time = time.perf_counter()

        try:
            response: Response = await call_next(request)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # Ensure X-Request-ID is present in the response
            response.headers["X-Request-ID"] = req_id

            # Extract user if available
            user = getattr(request.state, "user", None)
            user_id = user.subject if user else None

            # Extract client IP
            client_ip = request.client.host if request.client else "unknown"
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                client_ip = forwarded.split(",")[0].strip()

            # Skip logging health/metrics endpoints at high frequency to keep logs clean
            path = request.url.path
            if not (path == "/live" or path == "/ready" or path == "/metrics"):
                logger.info(
                    f"{request.method} {path} completed {response.status_code} in {duration_ms}ms",
                    extra={
                        "request_id": req_id,
                        "user_id": user_id,
                        "client_ip": client_ip,
                        "route": path,
                        "method": request.method,
                        "status_code": response.status_code,
                        "duration_ms": duration_ms,
                    }
                )
            return response
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.error(
                f"Unhandled exception processing {request.method} {request.url.path}: {exc}",
                extra={
                    "request_id": req_id,
                    "client_ip": client_ip if 'client_ip' in locals() else "unknown",
                    "route": request.url.path,
                    "method": request.method,
                    "duration_ms": duration_ms,
                    "error": str(exc),
                },
                exc_info=True
            )
            raise
        finally:
            request_id_ctx.reset(token)
