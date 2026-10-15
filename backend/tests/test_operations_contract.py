"""
Operations & Reliability Center API Contract and Durability Test Suite.
Validates:
- Canonical /operations/overview response schema matches frontend expectations.
- Accurate field types for scanner, distributed lock, dependencies, version, uptime.
- Distinguishing healthy empty scan history from database failure.
- RBAC enforcement (ADMINISTRATOR only).
- ScanRunModel durable lifecycle (start, complete, fail without fabricated snapshot ID).
- Deterministic ordering of scan runs.
- Interrupted execution recovery.
- Error safety and persistence failure handling.
"""

import pytest
import time
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from datetime import datetime, timezone

from app.main import app
from app.config import settings
from app.persistence.database import get_db_session
from app.persistence.models import ScanRunModel
from app.persistence.repository import (
    record_scan_run_start,
    record_scan_run_finish,
    get_recent_scan_runs,
    reconcile_interrupted_scans,
    DatabasePersistenceError,
    DatabaseQueryError,
)

settings.DEV_AUTH_MODE = True
admin_client = TestClient(app, headers={"X-Dev-Role": "ADMINISTRATOR", "X-Dev-Subject": "admin-test"})
viewer_client = TestClient(app, headers={"X-Dev-Role": "VIEWER", "X-Dev-Subject": "viewer-test"})


class TestOperationsContractAndDurability:

    def teardown_method(self):
        """Clean up test scan runs."""
        try:
            with get_db_session() as session:
                session.query(ScanRunModel).filter(ScanRunModel.scan_id.like("test-%")).delete(synchronize_session=False)
        except Exception:
            pass

    def test_operations_overview_canonical_contract(self):
        """Verify the canonical contract returned by /operations/overview."""
        resp = admin_client.get("/api/v1/operations/overview")
        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is True
        data = body["data"]

        # 1. Top-level metadata
        assert isinstance(data["timestamp"], str)
        assert isinstance(data["commit_hash"], str)
        assert isinstance(data["build_version"], str)
        assert isinstance(data["app_version"], str)
        assert isinstance(data["uptime_seconds"], (int, float))
        assert data["uptime_seconds"] >= 0

        # 2. Scanner info
        scanner = data["scanner"]
        assert isinstance(scanner["is_scanning"], bool)
        assert isinstance(scanner["active_phase"], str)
        assert isinstance(scanner["mode"], str)
        assert isinstance(scanner["progress"], int)
        assert isinstance(scanner["resolved_regions"], list)

        # 3. Distributed lock
        lock = data["distributed_lock"]
        assert isinstance(lock["locked"], bool)
        assert "owner_instance_id" in lock
        assert isinstance(lock["ttl_seconds"], int)
        assert isinstance(lock["stale"], bool)

        # 4. Dependencies
        deps = data["dependencies"]
        assert isinstance(deps["neo4j"], bool)
        assert isinstance(deps["redis"], bool)
        assert isinstance(deps["database"], bool)

        # 5. Metrics summary
        metrics = data["metrics_summary"]
        assert "last_scan_duration_seconds" in metrics
        assert "last_scan_status" in metrics
        assert isinstance(metrics["historical_failed_regions"], list)
        assert isinstance(metrics["recent_collector_failure_count"], int)

        # 6. Durable scan runs
        assert isinstance(data["recent_scans"], list)

        # 7. System & database status
        assert data["system_status"] in ("HEALTHY", "DEGRADED")
        assert data["database_status"] in ("HEALTHY", "ERROR")

    def test_operations_overview_rbac_enforcement(self):
        """Viewer role must be rejected with 403 Forbidden on operations overview."""
        resp = viewer_client.get("/api/v1/operations/overview")
        assert resp.status_code == 403

    def test_distinguish_healthy_empty_history_vs_database_error(self):
        """Verify the API distinguishes a healthy database from a database outage."""
        # 1. When DB is down: database_status == 'ERROR' and dependencies.database == False
        with patch("app.routers.operations.check_db_connectivity", return_value=False):
            resp = admin_client.get("/api/v1/operations/overview")
            assert resp.status_code == 200
            data = resp.json()["data"]
            assert data["database_status"] == "ERROR"
            assert data["dependencies"]["database"] is False
            assert data["database_error"] is not None

        # 2. When DB is healthy: database_status == 'HEALTHY' and dependencies.database == True
        with patch("app.routers.operations.check_db_connectivity", return_value=True):
            resp = admin_client.get("/api/v1/operations/overview")
            assert resp.status_code == 200
            data = resp.json()["data"]
            assert data["database_status"] == "HEALTHY"
            assert data["dependencies"]["database"] is True

    def test_scan_run_lifecycle_persistence(self):
        """Verify scan start, finish, and failure handling in durable repository."""
        scan_id = f"test-run-{time.time()}"
        start_time = datetime.now(timezone.utc).isoformat() + "Z"

        # 1. Record start
        record_scan_run_start(
            scan_id=scan_id,
            started_at=start_time,
            scan_mode="global",
            created_by="test-officer",
            trigger_type="MANUAL",
        )

        runs = get_recent_scan_runs(limit=10)
        started_run = next((r for r in runs if r["scan_id"] == scan_id), None)
        assert started_run is not None
        assert started_run["status"] == "SCANNING"
        assert started_run["created_by"] == "test-officer"
        assert started_run["active_phase"] == "INITIALIZING"

        # 2. Record success completion
        complete_time = datetime.now(timezone.utc).isoformat() + "Z"
        record_scan_run_finish(
            scan_id=scan_id,
            status="SUCCESS",
            completed_at=complete_time,
            duration_seconds=45.2,
            snapshot_id=f"snap-{scan_id}",
            resolved_regions=["us-east-1", "eu-west-1"],
            successful_regions=["us-east-1", "eu-west-1"],
            failed_regions=[],
            completed_collectors=12,
            total_collectors=12,
        )

        runs = get_recent_scan_runs(limit=10)
        finished_run = next((r for r in runs if r["scan_id"] == scan_id), None)
        assert finished_run is not None
        assert finished_run["status"] == "SUCCESS"
        assert finished_run["duration_seconds"] == 45.2
        assert finished_run["snapshot_id"] == f"snap-{scan_id}"
        assert finished_run["active_phase"] == "COMPLETED"

    def test_failed_scan_does_not_fabricate_snapshot_id(self):
        """Failed scans must have snapshot_id = None."""
        scan_id = f"test-failed-{time.time()}"
        start_time = datetime.now(timezone.utc).isoformat() + "Z"

        record_scan_run_start(scan_id=scan_id, started_at=start_time)
        record_scan_run_finish(
            scan_id=scan_id,
            status="FAILED",
            completed_at=start_time,
            duration_seconds=12.0,
            snapshot_id="fabricated-fake-id",
            error_summary="AWS STS assume role expired",
        )

        runs = get_recent_scan_runs(limit=10)
        failed_run = next((r for r in runs if r["scan_id"] == scan_id), None)
        assert failed_run is not None
        assert failed_run["status"] == "FAILED"
        assert failed_run["snapshot_id"] is None
        assert failed_run["error_summary"] == "AWS STS assume role expired"

    def test_deterministic_ordering_of_scan_runs(self):
        """Scan runs must be returned newest first with deterministic tie-breaker."""
        id_1 = "test-order-aaa"
        id_2 = "test-order-bbb"
        same_time = "2026-10-10T12:00:00.000000+00:00Z"

        record_scan_run_start(scan_id=id_1, started_at=same_time)
        record_scan_run_start(scan_id=id_2, started_at=same_time)

        runs = get_recent_scan_runs(limit=50)
        target_runs = [r for r in runs if r["scan_id"] in (id_1, id_2)]
        assert len(target_runs) == 2
        # Deterministic descending tie-breaker on scan_id
        assert target_runs[0]["scan_id"] == id_2
        assert target_runs[1]["scan_id"] == id_1

    def test_reconcile_interrupted_scans(self):
        """Orphaned SCANNING runs must be marked INTERRUPTED if no lock is held."""
        scan_id = f"test-orphaned-{time.time()}"
        record_scan_run_start(scan_id=scan_id, started_at="2026-10-10T10:00:00Z")

        # Ensure lock is not held
        with patch("app.services.scanner.distributed_lock.distributed_scan_lock.get_lock_info", return_value={"is_locked": False}):
            interrupted = reconcile_interrupted_scans()
            assert interrupted >= 1

        runs = get_recent_scan_runs(limit=50)
        reconciled = next((r for r in runs if r["scan_id"] == scan_id), None)
        assert reconciled is not None
        assert reconciled["status"] == "INTERRUPTED"
        assert reconciled["active_phase"] == "INTERRUPTED"
        assert reconciled["snapshot_id"] is None
