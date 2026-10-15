"""
CloudScope Relational Persistence Models.

Stores ScanRuns, ScanSnapshots, FindingStates, and AuditEvents durably.
"""

from sqlalchemy import Column, String, Float, Integer, Text, DateTime, UniqueConstraint, Index, text
from app.persistence.database import Base


class CloudProjectModel(Base):
    """A customer's registered AWS account; ownership is anchored to verified issuer + subject."""

    __tablename__ = "cloud_projects"
    __table_args__ = (
        UniqueConstraint("owner_issuer", "owner_subject", "project_id", name="uq_project_owner_id"),
        Index(
            "uq_active_project_owner_account", "owner_issuer", "owner_subject", "account_id",
            unique=True, sqlite_where=text("status = 'ACTIVE'"), postgresql_where=text("status = 'ACTIVE'"),
        ),
    )

    project_id = Column(String(36), primary_key=True, index=True)
    owner_issuer = Column(String(512), nullable=False, index=True)
    owner_subject = Column(String(256), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    description = Column(Text, nullable=False, default="")
    account_id = Column(String(12), nullable=True, index=True)
    role_arn = Column(String(2048), nullable=True)
    external_id = Column(String(64), nullable=True)
    verification_status = Column(String(16), nullable=False, default="NOT_CHECKED")
    verified_at = Column(String(64), nullable=True)
    verified_account_id = Column(String(12), nullable=True)
    verification_error = Column(String(256), nullable=True)
    status = Column(String(16), nullable=False, default="ACTIVE")
    created_at = Column(String(64), nullable=False)
    updated_at = Column(String(64), nullable=False)
    created_by = Column(String(256), nullable=False)


class ScanRunModel(Base):
    __tablename__ = "scan_runs"

    scan_id = Column(String(64), primary_key=True, index=True)
    project_id = Column(String(36), nullable=True, index=True)
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
    project_id = Column(String(36), nullable=True, index=True)
    scan_id = Column(String(64), index=True, nullable=False)
    published_at = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, default="SUCCESS")
    duration_seconds = Column(Float, nullable=True)
    regions_json = Column(Text, default="{}")
    collection_completeness_json = Column(Text, default="{}")
    resource_counts_json = Column(Text, default="{}")
    finding_counts_json = Column(Text, default="{}")
    metadata_json = Column(Text, default="{}")

    # Authoritative full snapshot collections
    users_json = Column(Text, default="[]")
    groups_json = Column(Text, default="[]")
    roles_json = Column(Text, default="[]")
    policies_json = Column(Text, default="[]")
    resources_json = Column(Text, default="[]")
    alerts_json = Column(Text, default="[]")
    correlated_risks_json = Column(Text, default="[]")
    findings_json = Column(Text, default="[]")
    risks_json = Column(Text, default="[]")
    attack_paths_json = Column(Text, default="[]")
    graph_json = Column(Text, default="[]")
    effective_access_json = Column(Text, default="[]")
    dashboard_json = Column(Text, default="{}")
    scan_metadata_json = Column(Text, default="{}")

    is_current = Column(Integer, default=0, index=True)


class CurrentSnapshotPointerModel(Base):
    __tablename__ = "current_snapshot_pointer"

    id = Column(Integer, primary_key=True)  # Singleton record (ID=1)
    scope_key = Column(String(64), nullable=False, default="global")
    snapshot_id = Column(String(64), nullable=False)
    published_at = Column(String(64), nullable=False)



class FindingStateModel(Base):
    __tablename__ = "finding_states"

    finding_id = Column(String(128), primary_key=True, index=True)
    source_finding_id = Column(String(256), nullable=True, index=True)
    project_id = Column(String(36), nullable=True, index=True)
    status = Column(String(32), nullable=False, default="OPEN")  # OPEN, ACKNOWLEDGED, RESOLVED, SUPPRESSED
    first_seen = Column(String(64), nullable=False)
    last_seen = Column(String(64), nullable=False)
    resolved_at = Column(String(64), nullable=True)
    updated_at = Column(String(64), nullable=False)
    snapshot_id = Column(String(64), index=True, nullable=False)
    changed_by = Column(String(128), nullable=True)
    change_reason = Column(Text, nullable=True)
    assigned_to = Column(String(128), nullable=True)
    due_date = Column(String(10), nullable=True)
    analyst_notes = Column(Text, nullable=True)


class FindingStateHistoryModel(Base):
    """Append-only record of finding lifecycle transitions."""

    __tablename__ = "finding_state_history"

    event_id = Column(String(64), primary_key=True, index=True)
    project_id = Column(String(36), nullable=True, index=True)
    finding_id = Column(String(128), nullable=False, index=True)
    source_finding_id = Column(String(256), nullable=True, index=True)
    from_status = Column(String(32), nullable=True)
    to_status = Column(String(32), nullable=False)
    occurred_at = Column(String(64), nullable=False, index=True)
    actor_id = Column(String(128), nullable=True)
    reason = Column(Text, nullable=True)
    snapshot_id = Column(String(64), nullable=True, index=True)


class AuditEventModel(Base):
    __tablename__ = "audit_events"

    event_id = Column(String(64), primary_key=True, index=True)
    project_id = Column(String(36), nullable=True, index=True)
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


class SimulationChangeModel(Base):
    """Durable analyst-owned simulation drafts, isolated by project."""

    __tablename__ = "simulation_changes"
    change_id = Column(String(36), primary_key=True)
    owner_id = Column(String(768), nullable=False, index=True)
    project_id = Column(String(36), nullable=True, index=True)
    action = Column(String(32), nullable=False)
    principal_type = Column(String(16), nullable=False)
    principal_id = Column(String(256), nullable=False)
    policy_arn = Column(String(2048), nullable=False)
    policy_name = Column(String(256), nullable=False)
    timestamp = Column(String(64), nullable=False)
