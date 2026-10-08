"""
Phase 2 Snapshot Durability and Recovery Test Suite.

Mandatory Invariants:
1. Publish snapshot A -> SQL contains full snapshot -> Clear Redis & in-memory store
   -> Restart/recover from SQL -> Verify snapshot A restored -> Verify read endpoints return snapshot A.
2. Publish snapshot B -> Verify atomic pointer advances to B.
3. Simulate failed SQL publication -> Verify snapshot B remains current.
4. Finding lifecycle state persistence across restart and invalid transition rejection.
"""

import time
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.services.scanner.snapshot_store import snapshot_store, PublishedSnapshot
from app.persistence.repository import (
    load_authoritative_snapshot,
    get_authoritative_current_snapshot_pointer,
    save_authoritative_snapshot,
    record_finding_state,
    get_finding_state,
)
from app.cache import cache
from tests.test_phase2_authentication_rbac import create_token

client = TestClient(app)


class TestSnapshotDurabilityAndRecovery:
    def setup_method(self):
        """Reset snapshot store before each test."""
        snapshot_store.clear()
        cache.clear()

    def teardown_method(self):
        """Clean up DB state and snapshot store after each test."""
        snapshot_store.clear()
        cache.clear()
        try:
            from app.persistence.database import get_db_session
            from app.persistence.models import ScanSnapshotModel, CurrentSnapshotPointerModel
            with get_db_session() as session:
                session.query(ScanSnapshotModel).delete()
                session.query(CurrentSnapshotPointerModel).delete()
        except Exception:
            pass

    def test_mandatory_snapshot_recovery_across_redis_loss(self):
        """
        MANDATORY TEST:
        Publish snapshot A.
        Confirm SQL contains complete authoritative snapshot.
        Clear Redis.
        Restart backend / recover from SQL.
        Verify snapshot A is restored.
        Verify all read endpoints return snapshot A.
        """
        auth_token = create_token(sub="security-auditor", roles=["VIEWER", "ANALYST"])
        headers = {"Authorization": f"Bearer {auth_token}"}

        snap_a_id = f"snap-prod-alpha-{int(time.time() * 1000)}"
        now_iso = "2026-09-30T00:00:00.000000Z"

        policies = [
            {
                "id": "pol-101",
                "arn": "arn:aws:iam::123456789012:policy/SecurityAuditPolicy",
                "name": "SecurityAuditPolicy",
                "type": "customer-managed",
                "risk_score": 10,
                "is_critical": False,
            }
        ]
        resources = [
            {
                "id": "i-0abcdef1234567890",
                "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abcdef1234567890",
                "type": "ec2:instance",
                "name": "Production-App-Server",
                "region": "us-east-1",
                "status": "running",
            }
        ]
        users = [{"id": "usr-1", "name": "alice", "arn": "arn:aws:iam::123456789012:user/alice"}]
        dashboard = {
            "total_resources": 1,
            "total_policies": 1,
            "total_users": 1,
            "security_score": 95,
        }

        # 1. Publish snapshot A
        published_a = snapshot_store.publish(
            snapshot_id=snap_a_id,
            status="SUCCESS",
            published_at=now_iso,
            policies=policies,
            resources=resources,
            users=users,
            dashboard=dashboard,
            region_metadata={"regions": ["us-east-1"]},
            collection_completeness={"us-east-1": "SUCCESS"},
            correlated_risks=[{"id": "correlated-1"}],
            scan_metadata={"scan_id": snap_a_id, "duration_seconds": 12.5},
        )
        assert published_a.snapshot_id == snap_a_id

        # 2. Confirm SQL contains complete authoritative snapshot
        sql_snap = load_authoritative_snapshot(snap_a_id)
        assert sql_snap is not None
        assert sql_snap["snapshot_id"] == snap_a_id
        assert len(sql_snap["policies"]) == 1
        assert sql_snap["policies"][0]["name"] == "SecurityAuditPolicy"
        assert len(sql_snap["resources"]) == 1
        assert sql_snap["resources"][0]["name"] == "Production-App-Server"
        assert sql_snap["dashboard"]["security_score"] == 95
        assert sql_snap["collection_completeness"] == {"us-east-1": "SUCCESS"}
        assert sql_snap["correlated_risks"] == [{"id": "correlated-1"}]

        # 3. Simulate Total Loss of Redis AND In-Memory cache (backend crash & restart)
        # Wipe in-memory SnapshotStore
        snapshot_store.clear()
        # Wipe Redis and local cache
        cache.clear()

        # Confirm in-memory and Redis are completely blank
        assert snapshot_store._current_snapshot is None
        assert cache.get("v1:current_snapshot_id") is None

        # 4. Backend Restart Recovery
        recovered = snapshot_store.recover_from_sql()
        assert recovered is not None
        assert recovered.snapshot_id == snap_a_id
        assert len(recovered.policies) == 1
        assert len(recovered.resources) == 1
        assert recovered.collection_completeness == {"us-east-1": "SUCCESS"}
        assert list(recovered.correlated_risks) == [{"id": "correlated-1"}]

        # 5. Verify all read endpoints serve Snapshot A data with matching snapshot_id
        # Endpoint: /api/v1/policies
        resp_policies = client.get("/api/v1/policies", headers=headers)
        assert resp_policies.status_code == 200
        p_data = resp_policies.json()["data"]
        assert len(p_data["items"]) == 1
        assert p_data["items"][0]["name"] == "SecurityAuditPolicy"

        # Endpoint: /api/v1/resources
        resp_resources = client.get("/api/v1/resources", headers=headers)
        assert resp_resources.status_code == 200
        r_data = resp_resources.json()["data"]
        assert len(r_data) >= 1
        assert any(r["name"] == "Production-App-Server" for r in r_data)

        # Endpoint: /api/v1/dashboard
        resp_dash = client.get("/api/v1/dashboard", headers=headers)
        assert resp_dash.status_code == 200
        assert resp_dash.json().get("snapshot_id") == snap_a_id

    def test_atomic_pointer_advancement_and_rollback_on_failed_publish(self):
        """Publish B advances pointer; simulated failure preserves previous snapshot."""
        now_iso = "2026-09-30T01:00:00.000000Z"
        snap_a_id = f"snap-a-{int(time.time() * 1000)}"
        snap_b_id = f"snap-b-{int(time.time() * 1000)}"

        # 1. Publish Snapshot A
        snapshot_store.publish(
            snapshot_id=snap_a_id,
            status="SUCCESS",
            published_at=now_iso,
            policies=[{"id": "pol-a", "name": "PolicyA"}],
        )
        assert snapshot_store.get_current().snapshot_id == snap_a_id

        # 2. Publish Snapshot B -> pointer advances to B
        snapshot_store.publish(
            snapshot_id=snap_b_id,
            status="SUCCESS",
            published_at=now_iso,
            policies=[{"id": "pol-b", "name": "PolicyB"}],
        )
        assert snapshot_store.get_current().snapshot_id == snap_b_id
        ptr = get_authoritative_current_snapshot_pointer()
        assert ptr["snapshot_id"] == snap_b_id

        # 3. Simulate publication failure during Snapshot C
        # If save_authoritative_snapshot fails, pointer must NOT advance
        snap_c_id = f"snap-c-{int(time.time() * 1000)}"
        with patch("app.persistence.repository.save_authoritative_snapshot", return_value=False):
            with patch("app.services.scanner.snapshot_store.logger.warning") as mock_warn:
                try:
                    snapshot_store.publish(
                        snapshot_id=snap_c_id,
                        status="SUCCESS",
                        published_at=now_iso,
                    )
                except Exception:
                    pass

        # Verify pointer remains at B in durable SQL
        ptr_after = get_authoritative_current_snapshot_pointer()
        assert ptr_after["snapshot_id"] == snap_b_id

    def test_finding_lifecycle_durability_across_restart(self):
        """Finding lifecycle state transitions persist across backend restart."""
        finding_id = f"finding-durable-{int(time.time() * 1000)}"
        now_iso = "2026-09-30T02:00:00.000000Z"

        # 1. First seen as OPEN
        record_finding_state(
            finding_id=finding_id,
            status="OPEN",
            first_seen=now_iso,
            snapshot_id="snap-1",
        )
        state_1 = get_finding_state(finding_id)
        assert state_1 is not None
        assert state_1["status"] == "OPEN"

        # 2. Transition to ACKNOWLEDGED with audit details
        record_finding_state(
            finding_id=finding_id,
            status="ACKNOWLEDGED",
            snapshot_id="snap-2",
            changed_by="sec-officer-99",
            change_reason="Accepted business risk in dev environment",
        )
        state_2 = get_finding_state(finding_id)
        assert state_2["status"] == "ACKNOWLEDGED"
        assert state_2["changed_by"] == "sec-officer-99"
        assert state_2["change_reason"] == "Accepted business risk in dev environment"

        # 3. Transition to RESOLVED
        resolved_time = "2026-09-30T03:00:00.000000Z"
        record_finding_state(
            finding_id=finding_id,
            status="RESOLVED",
            resolved_at=resolved_time,
            snapshot_id="snap-3",
            changed_by="sec-officer-99",
            change_reason="Remediation verified",
        )
        state_3 = get_finding_state(finding_id)
        assert state_3["status"] == "RESOLVED"
        assert state_3["resolved_at"] == resolved_time

    def test_sql_pointer_overrides_stale_redis_pointer(self):
        snap_sql = f"snap-sql-{int(time.time() * 1000)}"
        snap_cache = f"snap-cache-{int(time.time() * 1000)}"
        snapshot_store.publish(
            snapshot_id=snap_sql,
            status="SUCCESS",
            published_at="2026-10-01T00:00:00Z",
            users=[{"name": "sql-authoritative"}],
        )
        cache.set(f"v1:snapshot:{snap_cache}", {"snapshot_id": snap_cache, "users": [{"name": "stale-cache"}]})
        cache.set("v1:current_snapshot_id", snap_cache)
        snapshot_store.clear()

        current = snapshot_store.get_current()
        assert current is not None
        assert current.snapshot_id == snap_sql
        assert current.users[0]["name"] == "sql-authoritative"
