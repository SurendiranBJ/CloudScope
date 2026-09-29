"""
CloudScope Central Audit Logging Service.

Provides durable, sanitized recording and querying of administrative, security,
and operational actions. Ensures sensitive secrets are never logged.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.persistence.repository import (
    record_audit_event,
    query_audit_events,
    cleanup_old_audit_events,
)
from app.utils.sanitizer import sanitize_data

logger = logging.getLogger("cloudscope.audit")


class AuditService:
    """Service for auditing sensitive operational and security events."""

    def log(
        self,
        actor_id: str,
        actor_role: str,
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        snapshot_id: Optional[str] = None,
        result: str = "SUCCESS",
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Sanitize and record an audit event durably."""
        event_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat() + "Z"

        clean_metadata = sanitize_data(metadata or {})

        record_audit_event(
            event_id=event_id,
            timestamp=now_iso,
            actor_id=actor_id,
            actor_role=actor_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            scan_id=scan_id,
            snapshot_id=snapshot_id,
            result=result,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=clean_metadata,
        )

        logger.info(
            f"[AUDIT] action={action} actor={actor_id} role={actor_role} "
            f"resource={resource_type}:{resource_id} result={result}"
        )
        return {
            "event_id": event_id,
            "timestamp": now_iso,
            "actor_id": actor_id,
            "actor_role": actor_role,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "scan_id": scan_id,
            "snapshot_id": snapshot_id,
            "result": result,
            "metadata": clean_metadata,
        }

    def get_events(
        self,
        limit: int = 50,
        offset: int = 0,
        actor: Optional[str] = None,
        actor_id: Optional[str] = None,
        action: Optional[str] = None,
        scan_id: Optional[str] = None,
        resource: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve audit log events with filtering."""
        clamped_limit = min(max(1, limit), 200)
        return query_audit_events(
            limit=clamped_limit,
            offset=max(0, offset),
            actor=actor,
            actor_id=actor_id,
            action=action,
            scan_id=scan_id,
            resource=resource,
            resource_type=resource_type,
            resource_id=resource_id,
        )

    def prune_old_events(self, retention_days: int = 90) -> int:
        """Prune audit records beyond the retention window."""
        return cleanup_old_audit_events(retention_days=retention_days)


audit_service = AuditService()
