from app.config import settings
"""
Structured JSON / Key-Value Logger for CloudScope.
Sanitizes sensitive patterns (AWS keys, session tokens, passwords, Gemini keys).
Injects correlation IDs (request_id, scan_id, snapshot_id) into log records.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict
from app.utils.sanitizer import sanitize_data

class StructuredJsonFormatter(logging.Formatter):
    """
    Formats log records as JSON with sanitized metadata and contextual correlation IDs.
    """
    def format(self, record: logging.LogRecord) -> str:
        # Import lazily to avoid circular imports
        from app.middleware.request_id import request_id_ctx, scan_id_ctx, snapshot_id_ctx

        log_data: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": sanitize_data(record.getMessage()),
        }

        # Correlation fields
        req_id = getattr(record, "request_id", None) or request_id_ctx.get()
        if req_id:
            log_data["request_id"] = req_id

        s_id = getattr(record, "scan_id", None) or scan_id_ctx.get()
        if s_id:
            log_data["scan_id"] = s_id

        snap_id = getattr(record, "snapshot_id", None) or snapshot_id_ctx.get()
        if snap_id:
            log_data["snapshot_id"] = snap_id

        # Scan-specific structured fields if provided in extra
        for field in ("event", "phase", "collector", "region", "duration_ms", "status", "user_id", "route", "method", "status_code"):
            val = getattr(record, field, None)
            if val is not None:
                log_data[field] = sanitize_data(val)

        if record.exc_info:
            log_data["exception"] = sanitize_data(self.formatException(record.exc_info))

        return json.dumps(log_data)


def configure_logging():
    """
    Configure global logging with structured JSON formatting in production
    or readable structured logs in development.
    """
    log_format = settings.LOG_FORMAT.lower()
    log_level = settings.LOG_LEVEL.upper()

    handler = logging.StreamHandler(sys.stdout)
    if log_format == "json":
        handler.setFormatter(StructuredJsonFormatter())
    else:
        fmt = "%(asctime)s [%(levelname)s] %(name)s (req=%(request_id)s): %(message)s"
        handler.setFormatter(logging.Formatter(fmt))

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level, logging.INFO))
    # Replace existing handlers to avoid duplicates
    root_logger.handlers = [handler]

    # Silence overly verbose external loggers
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("apscheduler").setLevel(logging.INFO)
