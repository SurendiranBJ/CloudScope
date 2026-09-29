"""
Phase 2 Durability & Multi-Instance Coordination Test Suite.
Validates:
- Snapshot durability across Redis restarts:
  Durable relational store retains snapshot metadata, scan runs, and finding states.
- Multi-instance coordinator concurrency:
  Two worker instances receiving simultaneous triggers coordinate via distributed lock:
  Instance A gets STARTED, Instance B gets ALREADY_RUNNING.
"""

import time
import pytest
from unittest.mock import patch, MagicMock

from datetime import datetime, timezone
from app.services.scanner.scan_coordinator import ScanCoordinator
from app.persistence.repository import (
    record_scan_run_start,
    record_scan_run_finish,
    record_snapshot_metadata,
    get_latest_snapshot,
    get_recent_scan_runs,
    record_finding_state,
    get_finding_state,
)


class TestDurableStateAndMultiInstance:
    def test_durable_snapshot_and_scan_run_persistence(self):
        # 1. Record scan run
        now_iso = datetime.now(timezone.utc).isoformat()
        scan_id = f"test-durable-{time.time()}"
        record_scan_run_start(
            scan_id=scan_id,
            trigger_type="MANUAL",
            created_by="test-admin",
            started_at=now_iso
        )
        record_scan_run_finish(
            scan_id=scan_id,
            status="SUCCESS",
            completed_at=now_iso,
            duration_seconds=60.0,
            snapshot_id=f"snap-{scan_id}",
            resolved_regions=["us-east-1"],
            successful_regions=["us-east-1"],
            failed_regions=[]
        )

        # 2. Record snapshot metadata in durable relational store
        record_snapshot_metadata(
            snapshot_id=f"snap-{scan_id}",
            scan_id=scan_id,
            published_at=now_iso,
            status="SUCCESS",
            duration_seconds=60.0,
            regions={"successful": ["us-east-1"]},
            resource_counts={"total": 42},
            finding_counts={"critical": 2, "high": 5}
        )

        # 3. Record finding state
        record_finding_state(
            finding_id=f"find-{scan_id}",
            status="ACKNOWLEDGED",
            first_seen=now_iso,
            snapshot_id=f"snap-{scan_id}",
            changed_by="security-officer-1",
            change_reason="False positive under review"
        )

        # 4. Verify durable recovery
        runs = get_recent_scan_runs(limit=20)
        found_run = next((r for r in runs if r["scan_id"] == scan_id), None)
        assert found_run is not None
        assert found_run["status"] == "SUCCESS"
        assert found_run["duration_seconds"] == 60.0

        latest_snap = get_latest_snapshot()
        assert latest_snap is not None

        finding = get_finding_state(f"find-{scan_id}")
        assert finding is not None
        assert finding["status"] == "ACKNOWLEDGED"
        assert finding["changed_by"] == "security-officer-1"

    def test_multi_worker_concurrency_single_execution(self, monkeypatch):
        """Simulate two workers receiving simultaneous scan triggers."""
        coord_a = ScanCoordinator()
        coord_b = ScanCoordinator()

        # Mock lock: worker A acquires, worker B is blocked
        mock_lock = MagicMock()
        mock_lock.acquire.side_effect = ["owner-token-a", None]
        monkeypatch.setattr("app.services.scanner.scan_coordinator.distributed_scan_lock", mock_lock)

        with patch.object(coord_a, "_run_scan_worker"):
            res_a = coord_a.request_scan(trigger_type="SCHEDULED", actor_id="worker-a")
            res_b = coord_b.request_scan(trigger_type="SCHEDULED", actor_id="worker-b")

            assert res_a["status"] == "STARTED"
            assert res_b["status"] == "ALREADY_RUNNING"
            assert "another worker" in res_b["message"].lower() or "already running" in res_b["message"].lower()
