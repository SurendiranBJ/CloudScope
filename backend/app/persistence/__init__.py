"""CloudScope Relational Persistence Package."""

from app.persistence.database import init_db, get_db_session, engine, SessionLocal, Base
from app.persistence.repository import (
    record_scan_run_start,
    record_scan_run_finish,
    get_recent_scan_runs,
    record_snapshot_metadata,
    get_latest_snapshot,
    cleanup_old_snapshots,
    record_finding_state,
    get_finding_state,
    get_all_finding_states,
    record_audit_event,
    query_audit_events,
    cleanup_old_audit_events,
)

__all__ = [
    "init_db",
    "get_db_session",
    "engine",
    "SessionLocal",
    "Base",
    "record_scan_run_start",
    "record_scan_run_finish",
    "get_recent_scan_runs",
    "record_snapshot_metadata",
    "get_latest_snapshot",
    "cleanup_old_snapshots",
    "record_finding_state",
    "get_finding_state",
    "get_all_finding_states",
    "record_audit_event",
    "query_audit_events",
    "cleanup_old_audit_events",
]
