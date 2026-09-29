"""
CloudScope Durable Relational Repository.

Handles transactions for ScanRuns, Snapshots, Finding lifecycle states, and Audit events.
"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from sqlalchemy import desc

from app.persistence.database import get_db_session, init_db
from app.persistence.models import (
    ScanRunModel,
    ScanSnapshotModel,
    FindingStateModel,
    AuditEventModel,
)

logger = logging.getLogger("cloudscope.persistence")

# Ensure tables are initialized on import
try:
    init_db()
except Exception as e:
    logger.error(f"Failed to auto-initialize relational database tables: {e}")

SNAPSHOT_RETENTION_COUNT = int(os.getenv("SNAPSHOT_RETENTION_COUNT", "10"))
AUDIT_RETENTION_DAYS = int(os.getenv("AUDIT_RETENTION_DAYS", "90"))


# ==============================================================================
# SCAN RUN REPOSITORY
# ==============================================================================

def record_scan_run_start(
    scan_id: str,
    started_at: str,
    scan_mode: str = "single",
    created_by: str = "system",
    trigger_type: str = "MANUAL",
) -> None:
    """Insert initial ScanRun record into durable store."""
    try:
        with get_db_session() as session:
            existing = session.query(ScanRunModel).filter_by(scan_id=scan_id).first()
            if not existing:
                run = ScanRunModel(
                    scan_id=scan_id,
                    status="SCANNING",
                    started_at=started_at,
                    scan_mode=scan_mode,
                    created_by=created_by,
                    trigger_type=trigger_type,
                    active_phase="INITIALIZING",
                )
                session.add(run)
    except Exception as e:
        logger.warning(f"Failed to record scan run start: {e}")


def record_scan_run_finish(
    scan_id: str,
    status: str,
    completed_at: str,
    duration_seconds: float,
    snapshot_id: Optional[str] = None,
    resolved_regions: Optional[List[str]] = None,
    successful_regions: Optional[List[str]] = None,
    failed_regions: Optional[List[str]] = None,
    error_summary: Optional[str] = None,
    completed_collectors: int = 12,
) -> None:
    """Update completed or failed ScanRun record in durable store."""
    try:
        with get_db_session() as session:
            run = session.query(ScanRunModel).filter_by(scan_id=scan_id).first()
            if not run:
                run = ScanRunModel(
                    scan_id=scan_id,
                    started_at=completed_at,
                    scan_mode="global",
                )
                session.add(run)

            run.status = status
            run.completed_at = completed_at
            run.duration_seconds = duration_seconds
            run.snapshot_id = snapshot_id
            run.active_phase = "COMPLETED" if status in ("SUCCESS", "PARTIAL") else "FAILED"
            run.resolved_regions = json.dumps(resolved_regions or [])
            run.successful_regions = json.dumps(successful_regions or [])
            run.failed_regions = json.dumps(failed_regions or [])
            run.error_summary = error_summary
            run.completed_collectors = completed_collectors
    except Exception as e:
        logger.warning(f"Failed to record scan run completion: {e}")


def get_recent_scan_runs(limit: int = 10) -> List[Dict[str, Any]]:
    """Retrieve recent scan executions ordered newest first."""
    try:
        with get_db_session() as session:
            runs = (
                session.query(ScanRunModel)
                .order_by(desc(ScanRunModel.started_at))
                .limit(limit)
                .all()
            )
            return [
                {
                    "scan_id": r.scan_id,
                    "snapshot_id": r.snapshot_id,
                    "status": r.status,
                    "started_at": r.started_at,
                    "completed_at": r.completed_at,
                    "duration_seconds": r.duration_seconds,
                    "scan_mode": r.scan_mode,
                    "resolved_regions": json.loads(r.resolved_regions or "[]"),
                    "successful_regions": json.loads(r.successful_regions or "[]"),
                    "failed_regions": json.loads(r.failed_regions or "[]"),
                    "active_phase": r.active_phase,
                    "error_summary": r.error_summary,
                    "created_by": r.created_by,
                    "trigger_type": r.trigger_type,
                }
                for r in runs
            ]
    except Exception as e:
        logger.warning(f"Failed to retrieve scan runs: {e}")
        return []


# ==============================================================================
# SNAPSHOT METADATA REPOSITORY
# ==============================================================================

def record_snapshot_metadata(
    snapshot_id: str,
    scan_id: str,
    published_at: str,
    status: str,
    duration_seconds: float,
    regions: Optional[Dict[str, Any]] = None,
    resource_counts: Optional[Dict[str, Any]] = None,
    finding_counts: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Store authoritative snapshot record and enforce retention policy."""
    try:
        with get_db_session() as session:
            existing = session.query(ScanSnapshotModel).filter_by(snapshot_id=snapshot_id).first()
            if not existing:
                snap = ScanSnapshotModel(
                    snapshot_id=snapshot_id,
                    scan_id=scan_id,
                    published_at=published_at,
                    status=status,
                    duration_seconds=duration_seconds,
                    regions_json=json.dumps(regions or {}),
                    resource_counts_json=json.dumps(resource_counts or {}),
                    finding_counts_json=json.dumps(finding_counts or {}),
                    metadata_json=json.dumps(metadata or {}),
                )
                session.add(snap)

        # Enforce snapshot retention count (preserves active snapshot)
        cleanup_old_snapshots(
            retention_count=SNAPSHOT_RETENTION_COUNT,
            preserve_snapshot_id=snapshot_id
        )
    except Exception as e:
        logger.warning(f"Failed to record snapshot metadata: {e}")


def get_latest_snapshot() -> Optional[Dict[str, Any]]:
    """Retrieve the most recently published snapshot metadata."""
    try:
        with get_db_session() as session:
            snap = (
                session.query(ScanSnapshotModel)
                .order_by(desc(ScanSnapshotModel.published_at))
                .first()
            )
            if not snap:
                return None
            return {
                "snapshot_id": snap.snapshot_id,
                "scan_id": snap.scan_id,
                "published_at": snap.published_at,
                "status": snap.status,
                "duration_seconds": snap.duration_seconds,
                "regions": json.loads(snap.regions_json or "{}"),
                "resource_counts": json.loads(snap.resource_counts_json or "{}"),
                "finding_counts": json.loads(snap.finding_counts_json or "{}"),
                "metadata": json.loads(snap.metadata_json or "{}"),
            }
    except Exception as e:
        logger.warning(f"Failed to fetch latest snapshot: {e}")
        return None


def cleanup_old_snapshots(retention_count: int = 10, preserve_snapshot_id: Optional[str] = None) -> int:
    """Prune historical snapshot records exceeding retention count."""
    try:
        with get_db_session() as session:
            all_snaps = (
                session.query(ScanSnapshotModel)
                .order_by(desc(ScanSnapshotModel.published_at))
                .all()
            )
            if len(all_snaps) <= retention_count:
                return 0

            to_delete = all_snaps[retention_count:]
            deleted_count = 0
            for s in to_delete:
                if preserve_snapshot_id and s.snapshot_id == preserve_snapshot_id:
                    continue
                session.delete(s)
                deleted_count += 1

            if deleted_count > 0:
                logger.info(f"[SNAPSHOT_CLEANUP] Pruned {deleted_count} historical snapshot records (retention={retention_count})")
            return deleted_count
    except Exception as e:
        logger.warning(f"Snapshot cleanup failed: {e}")
        return 0


# ==============================================================================
# FINDING LIFECYCLE REPOSITORY
# ==============================================================================

def record_finding_state(
    finding_id: str,
    status: str,
    snapshot_id: Optional[str] = None,
    first_seen: Optional[str] = None,
    last_seen: Optional[str] = None,
    resolved_at: Optional[str] = None,
    changed_by: Optional[str] = None,
    change_reason: Optional[str] = None,
) -> None:
    """Persist finding lifecycle state transition durably."""
    try:
        now_str = datetime.now(timezone.utc).isoformat() + "Z"
        first_seen_str = first_seen or now_str
        last_seen_str = last_seen or now_str
        snapshot_id_str = snapshot_id or "snap-initial"
        with get_db_session() as session:
            item = session.query(FindingStateModel).filter_by(finding_id=finding_id).first()
            if not item:
                item = FindingStateModel(
                    finding_id=finding_id,
                    status=status,
                    first_seen=first_seen_str,
                    last_seen=last_seen_str,
                    resolved_at=resolved_at,
                    updated_at=now_str,
                    snapshot_id=snapshot_id_str,
                    changed_by=changed_by,
                    change_reason=change_reason,
                )
                session.add(item)
            else:
                item.status = status
                item.last_seen = last_seen_str
                item.updated_at = now_str
                item.snapshot_id = snapshot_id_str
                if resolved_at is not None:
                    item.resolved_at = resolved_at
                if changed_by:
                    item.changed_by = changed_by
                if change_reason:
                    item.change_reason = change_reason
    except Exception as e:
        logger.warning(f"Failed to record finding state for {finding_id}: {e}")


def get_finding_state(finding_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve durable lifecycle state for a specific finding."""
    try:
        with get_db_session() as session:
            item = session.query(FindingStateModel).filter_by(finding_id=finding_id).first()
            if not item:
                return None
            return {
                "finding_id": item.finding_id,
                "status": item.status,
                "first_seen": item.first_seen,
                "last_seen": item.last_seen,
                "resolved_at": item.resolved_at,
                "updated_at": item.updated_at,
                "snapshot_id": item.snapshot_id,
                "changed_by": item.changed_by,
                "change_reason": item.change_reason,
            }
    except Exception as e:
        logger.warning(f"Failed to fetch finding state: {e}")
        return None


def get_all_finding_states() -> Dict[str, Dict[str, Any]]:
    """Retrieve all finding lifecycle states indexed by finding_id."""
    try:
        with get_db_session() as session:
            items = session.query(FindingStateModel).all()
            return {
                item.finding_id: {
                    "finding_id": item.finding_id,
                    "status": item.status,
                    "first_seen": item.first_seen,
                    "last_seen": item.last_seen,
                    "resolved_at": item.resolved_at,
                    "updated_at": item.updated_at,
                    "snapshot_id": item.snapshot_id,
                    "changed_by": item.changed_by,
                    "change_reason": item.change_reason,
                }
                for item in items
            }
    except Exception as e:
        logger.warning(f"Failed to fetch all finding states: {e}")
        return {}


# ==============================================================================
# AUDIT EVENT REPOSITORY
# ==============================================================================

def record_audit_event(
    event_id: str,
    timestamp: str,
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
) -> None:
    """Durable write of security-sensitive administrative and operational audit log event."""
    try:
        with get_db_session() as session:
            ev = AuditEventModel(
                event_id=event_id,
                timestamp=timestamp,
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
                metadata_json=json.dumps(metadata or {}),
            )
            session.add(ev)
    except Exception as e:
        logger.warning(f"Failed to record audit event: {e}")


def query_audit_events(
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
    """Query audit logs with server-side filtering."""
    eff_actor = actor_id or actor
    eff_resource = resource_id or resource
    try:
        with get_db_session() as session:
            q = session.query(AuditEventModel)
            if eff_actor:
                q = q.filter(AuditEventModel.actor_id == eff_actor)
            if action:
                q = q.filter(AuditEventModel.action == action)
            if scan_id:
                q = q.filter(AuditEventModel.scan_id == scan_id)
            if eff_resource:
                q = q.filter(AuditEventModel.resource_id == eff_resource)
            if resource_type:
                q = q.filter(AuditEventModel.resource_type == resource_type)

            events = (
                q.order_by(desc(AuditEventModel.timestamp))
                .offset(offset)
                .limit(limit)
                .all()
            )

            return [
                {
                    "event_id": ev.event_id,
                    "timestamp": ev.timestamp,
                    "actor_id": ev.actor_id,
                    "actor_role": ev.actor_role,
                    "action": ev.action,
                    "resource_type": ev.resource_type,
                    "resource_id": ev.resource_id,
                    "scan_id": ev.scan_id,
                    "snapshot_id": ev.snapshot_id,
                    "result": ev.result,
                    "ip_address": ev.ip_address,
                    "user_agent": ev.user_agent,
                    "metadata": json.loads(ev.metadata_json or "{}"),
                }
                for ev in events
            ]
    except Exception as e:
        logger.warning(f"Failed to query audit events: {e}")
        return []


def cleanup_old_audit_events(retention_days: int = 90) -> int:
    """Prune audit records older than the retention threshold."""
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat() + "Z"
        with get_db_session() as session:
            deleted = (
                session.query(AuditEventModel)
                .filter(AuditEventModel.timestamp < cutoff)
                .delete(synchronize_session=False)
            )
            if deleted > 0:
                logger.info(f"[AUDIT_CLEANUP] Pruned {deleted} audit log entries older than {retention_days} days")
            return deleted
    except Exception as e:
        logger.warning(f"Audit cleanup failed: {e}")
        return 0
