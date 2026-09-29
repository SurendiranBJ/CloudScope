"""
CloudScope Relational Persistence Models.

Stores ScanRuns, ScanSnapshots, FindingStates, and AuditEvents durably.
"""

from sqlalchemy import Column, String, Float, Integer, Text, DateTime
from app.persistence.database import Base


class ScanRunModel(Base):
    __tablename__ = "scan_runs"

    scan_id = Column(String(64), primary_key=True, index=True)
    snapshot_id = Column(String(64), index=True, nullable=True)
    status = Column(String(32), nullable=False, default="PENDING")
    started_at = Column(String(64), nullable=False)
    completed_at = Column(String(64), nullable=True)
    duration_seconds = Column(Float, nullable=True)
    scan_mode = Column(String(32), default="global")
    resolved_regions = Column(Text, default="[]")
    successful_regions = Column(Text, default="[]")
    failed_regions = Column(Text, default="[]")
    active_phase = Column(String(64), default="IDLE")
    total_collectors = Column(Integer, default=12)
    completed_collectors = Column(Integer, default=0)
    error_summary = Column(Text, nullable=True)
    created_by = Column(String(128), default="system")
    trigger_type = Column(String(32), default="MANUAL")  # MANUAL, SCHEDULED, REGION_CHANGE, STARTUP


class ScanSnapshotModel(Base):
    __tablename__ = "scan_snapshots"

    snapshot_id = Column(String(64), primary_key=True, index=True)
    scan_id = Column(String(64), index=True, nullable=False)
    published_at = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, default="SUCCESS")
    duration_seconds = Column(Float, nullable=True)
    regions_json = Column(Text, default="{}")
    resource_counts_json = Column(Text, default="{}")
    finding_counts_json = Column(Text, default="{}")
    metadata_json = Column(Text, default="{}")


class FindingStateModel(Base):
    __tablename__ = "finding_states"

    finding_id = Column(String(128), primary_key=True, index=True)
    status = Column(String(32), nullable=False, default="OPEN")  # OPEN, ACKNOWLEDGED, RESOLVED, SUPPRESSED
    first_seen = Column(String(64), nullable=False)
    last_seen = Column(String(64), nullable=False)
    resolved_at = Column(String(64), nullable=True)
    updated_at = Column(String(64), nullable=False)
    snapshot_id = Column(String(64), index=True, nullable=False)
    changed_by = Column(String(128), nullable=True)
    change_reason = Column(Text, nullable=True)


class AuditEventModel(Base):
    __tablename__ = "audit_events"

    event_id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(String(64), nullable=False, index=True)
    actor_id = Column(String(128), nullable=False, index=True)
    actor_role = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False, index=True)
    resource_type = Column(String(64), nullable=True)
    resource_id = Column(String(256), nullable=True, index=True)
    scan_id = Column(String(64), nullable=True, index=True)
    snapshot_id = Column(String(64), nullable=True, index=True)
    result = Column(String(32), nullable=False, default="SUCCESS")
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(256), nullable=True)
    metadata_json = Column(Text, default="{}")
