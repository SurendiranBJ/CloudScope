import pytest
import time
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from app.main import app
from app.cache import cache
from app.services.scanner.scan_manager import ScanManager, scan_manager
from app.services.scanner.inventory import AWSInventory
from app.services.scanner.current_snapshot import (
    get_current_snapshot_id,
    get_current_policies,
    get_current_relationship_inputs,
    get_current_risks,
    get_current_alerts,
    get_current_resources,
)

client = TestClient(app)


def _reset_scan_manager():
    for target in (ScanManager, scan_manager):
        target._is_running = False
        target._status = "IDLE"
        target._active_phase = "IDLE"
        target._last_error = None
        target._last_published_scan_id = None
        target._last_published_at = None
        target._published_snapshot = None
        target._current_scan_id = None


@pytest.fixture(autouse=True)
def clean_state():
    cache.clear()
    _reset_scan_manager()
    yield
    cache.clear()
    _reset_scan_manager()


def seed_published_snapshot(snapshot_id="scan-snap-100", published_at="2026-09-26T12:00:00Z"):
    """Seeds a consistent published snapshot in cache and ScanManager."""
    policies = [
        {
            "arn": "arn:aws:iam::123456789012:policy/SecurityAuditPolicy",
            "name": "SecurityAuditPolicy",
            "policy_type": "customer-managed",
            "risk_score": 25,
            "attachment_count": 2,
            "document": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
            "created_at": "2026-01-01T00:00:00Z"
        }
    ]
    users = [
        {
            "user_id": "AIDASNAP100USER",
            "name": "audit-user",
            "arn": "arn:aws:iam::123456789012:user/audit-user",
            "user_name": "audit-user",
            "attached_policies": ["arn:aws:iam::123456789012:policy/SecurityAuditPolicy"],
            "inline_policies": {},
            "groups": ["SecurityGroup"]
        }
    ]
    roles = [
        {
            "role_id": "AROASNAP100ROLE",
            "name": "AuditRole",
            "arn": "arn:aws:iam::123456789012:role/AuditRole",
            "role_name": "AuditRole",
            "attached_policies": [],
            "inline_policies": {},
            "assume_role_policy": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:user/audit-user"}, "Action": "sts:AssumeRole"}]}
        }
    ]
    groups = [
        {
            "group_id": "AGPASNAP100GRP",
            "name": "SecurityGroup",
            "arn": "arn:aws:iam::123456789012:group/SecurityGroup",
            "group_name": "SecurityGroup",
            "attached_policies": ["arn:aws:iam::123456789012:policy/SecurityAuditPolicy"]
        }
    ]
    resources = [
        {
            "id": "arn:aws:s3:::audit-bucket-100",
            "name": "audit-bucket-100",
            "type": "S3",
            "arn": "arn:aws:s3:::audit-bucket-100",
            "region": "us-east-1",
            "account_id": "123456789012",
            "owner": "123456789012",
            "riskScore": 15,
            "status": "active"
        }
    ]
    risks = [
        {
            "id": "risk-snap-100-1",
            "identity": "arn:aws:iam::123456789012:user/audit-user",
            "identityType": "User",
            "issue": "Unrestricted Administrative Access",
            "title": "Unrestricted Administrative Access",
            "severity": "critical",
            "riskScore": 95,
            "recommendation": "Attach least-privilege scoped policy",
            "status": "OPEN",
        }
    ]
    alerts = [
        {
            "id": "alert-snap-100-1",
            "timestamp": "2026-09-26T11:58:00Z",
            "resource": "arn:aws:iam::123456789012:user/audit-user",
            "description": "Unauthorized Access Attempt Observed in CloudTrail",
            "severity": "high",
            "status": "open",
            "details": "{}"
        }
    ]

    cache.set("v1:last_published_scan_id", snapshot_id)
    cache.set("v1:last_published_at", published_at)
    cache.set("v1:policies", policies)
    cache.set("v1:users", users)
    cache.set("v1:roles", roles)
    cache.set("v1:groups", groups)
    cache.set("v1:resources", resources)
    cache.set("v1:risks", risks)
    cache.set("v1:findings", risks)
    cache.set("v1:alerts", alerts)

    # Sync to ScanManager
    for target in (ScanManager, scan_manager):
        target._last_published_scan_id = snapshot_id
        target._last_published_at = published_at
        target._published_snapshot = {
            "snapshot_id": snapshot_id,
            "published_at": published_at,
            "users": users,
            "roles": roles,
            "groups": groups,
            "policies": policies,
            "resources": resources,
            "risks": risks,
            "findings": risks,
            "alerts": alerts,
        }


def test_consistent_snapshot_across_all_endpoints():
    """All security read endpoints return the same snapshot_id and data."""
    snap_id = "scan-snap-alpha"
    published_at = "2026-09-26T14:30:00Z"
    seed_published_snapshot(snap_id, published_at)

    # 1. Policies
    res_p = client.get("/api/v1/policies")
    assert res_p.status_code == 200
    p_data = res_p.json()["data"]
    assert p_data["snapshot_id"] == snap_id
    assert p_data["snapshot_published_at"] == published_at
    assert len(p_data["items"]) == 1
    assert p_data["items"][0]["name"] == "SecurityAuditPolicy"

    # 2. Relationships
    res_r = client.get("/api/v1/relationships")
    assert res_r.status_code == 200
    r_data = res_r.json()["data"]
    assert r_data["snapshot_id"] == snap_id
    assert r_data["snapshot_published_at"] == published_at
    assert r_data["total"] > 0

    # 3. Risks
    res_k = client.get("/api/v1/risk-assessment")
    assert res_k.status_code == 200
    k_json = res_k.json()
    assert k_json["snapshot_id"] == snap_id
    assert k_json["snapshot_published_at"] == published_at
    assert len(k_json["data"]) == 1

    # 4. Alerts
    res_a = client.get("/api/v1/alerts")
    assert res_a.status_code == 200
    a_json = res_a.json()
    assert a_json["snapshot_id"] == snap_id
    assert a_json["snapshot_published_at"] == published_at
    assert len(a_json["data"]) == 1

    # 5. Resources
    res_res = client.get("/api/v1/resources")
    assert res_res.status_code == 200
    res_json = res_res.json()
    assert res_json["snapshot_id"] == snap_id
    assert res_json["snapshot_published_at"] == published_at
    assert len(res_json["data"]) == 1


def test_snapshot_preserved_during_active_scan():
    """While a new scan is running, read endpoints must keep returning previous snapshot A."""
    seed_published_snapshot("scan-snap-100", "2026-09-26T12:00:00Z")

    # Simulate an active scan in progress
    for target in (ScanManager, scan_manager):
        target._is_running = True
        target._active_phase = "DISCOVERY"
        target._current_scan_id = "scan-snap-101-working"

    # Verify all endpoints continue returning snapshot-100, not empty lists
    res_p = client.get("/api/v1/policies")
    assert res_p.status_code == 200
    p_data = res_p.json()["data"]
    assert p_data["snapshot_id"] == "scan-snap-100"
    assert len(p_data["items"]) == 1

    res_r = client.get("/api/v1/relationships")
    assert res_r.status_code == 200
    r_data = res_r.json()["data"]
    assert r_data["snapshot_id"] == "scan-snap-100"
    assert r_data["total"] > 0

    res_k = client.get("/api/v1/risk-assessment")
    assert res_k.status_code == 200
    assert res_k.json()["snapshot_id"] == "scan-snap-100"
    assert len(res_k.json()["data"]) == 1

    res_a = client.get("/api/v1/alerts")
    assert res_a.status_code == 200
    assert res_a.json()["snapshot_id"] == "scan-snap-100"
    assert len(res_a.json()["data"]) == 1

    res_res = client.get("/api/v1/resources")
    assert res_res.status_code == 200
    assert res_res.json()["snapshot_id"] == "scan-snap-100"
    assert len(res_res.json()["data"]) == 1


def test_failed_scan_retains_previous_snapshot():
    """If scan B fails, snapshot A remains published and active."""
    seed_published_snapshot("scan-snap-100", "2026-09-26T12:00:00Z")

    # Simulate scan failure
    for target in (ScanManager, scan_manager):
        target._is_running = False
        target._status = "FAILED"
        target._last_error = "AWS STS credentials expired"

    # Endpoints still serve snapshot A
    res_p = client.get("/api/v1/policies")
    assert res_p.status_code == 200
    assert res_p.json()["data"]["snapshot_id"] == "scan-snap-100"
    assert len(res_p.json()["data"]["items"]) == 1

    res_r = client.get("/api/v1/relationships")
    assert res_r.status_code == 200
    assert res_r.json()["data"]["snapshot_id"] == "scan-snap-100"


def test_atomic_publication_updates_all_endpoints():
    """Once snapshot B is published, all endpoints atomically switch to snapshot B."""
    seed_published_snapshot("scan-snap-100", "2026-09-26T12:00:00Z")

    # Verify initial is snap-100
    assert client.get("/api/v1/policies").json()["data"]["snapshot_id"] == "scan-snap-100"

    # Publish snapshot B
    seed_published_snapshot("scan-snap-101", "2026-09-26T12:05:00Z")

    # All endpoints now serve snap-101
    assert client.get("/api/v1/policies").json()["data"]["snapshot_id"] == "scan-snap-101"
    assert client.get("/api/v1/relationships").json()["data"]["snapshot_id"] == "scan-snap-101"
    assert client.get("/api/v1/risk-assessment").json()["snapshot_id"] == "scan-snap-101"
    assert client.get("/api/v1/alerts").json()["snapshot_id"] == "scan-snap-101"
    assert client.get("/api/v1/resources").json()["snapshot_id"] == "scan-snap-101"


def test_no_duplicate_scan_triggered_by_reads_when_snapshot_exists():
    """Read endpoints must not trigger ScanManager.trigger_async_scan when a snapshot exists."""
    seed_published_snapshot("scan-snap-100", "2026-09-26T12:00:00Z")

    with patch.object(ScanManager, "trigger_async_scan") as mock_trigger:
        client.get("/api/v1/policies")
        client.get("/api/v1/relationships")
        client.get("/api/v1/risk-assessment")
        client.get("/api/v1/alerts")
        client.get("/api/v1/resources")

        mock_trigger.assert_not_called()
