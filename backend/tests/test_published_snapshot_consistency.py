import pytest
import time
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from app.main import app
from app.cache import cache
from app.services.scanner.scan_manager import ScanManager, scan_manager
from app.services.scanner.snapshot_store import snapshot_store
from app.services.scanner.inventory import AWSInventory
from app.services.scanner.current_snapshot import (
    pin_request_snapshot,
    reset_request_snapshot,
    get_current_snapshot_id,
    get_current_snapshot_published_at,
    get_current_policies,
    get_current_relationship_inputs,
    get_current_risks,
    get_current_alerts,
    get_current_resources,
    get_current_attack_paths,
    get_current_graph,
    get_current_users,
    get_current_roles,
    get_current_findings,
    get_current_dashboard,
)

client = TestClient(app)


def _reset_scan_manager():
    snapshot_store.clear()
    try:
        from app.persistence.database import get_db_session
        from app.persistence.models import ScanSnapshotModel, CurrentSnapshotPointerModel
        with get_db_session() as session:
            session.query(ScanSnapshotModel).delete()
            session.query(CurrentSnapshotPointerModel).delete()
    except Exception:
        pass
    for target in (ScanManager, scan_manager):
        target._is_running = False
        target._scan_status = "IDLE"
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


def seed_published_snapshot(
    snapshot_id="scan-snap-100",
    published_at="2026-09-26T12:00:00Z",
    alerts_list=None,
    policies_list=None,
    resources_list=None,
):
    """Seeds a consistent published snapshot in SnapshotStore, cache, and ScanManager."""
    policies = policies_list if policies_list is not None else [
        {
            "arn": "arn:aws:iam::123456789012:policy/SecurityAuditPolicy",
            "name": "SecurityAuditPolicy",
            "type": "customer-managed",
            "policy_type": "customer-managed",
            "riskScore": 25,
            "attachmentCount": 2,
            "document": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
            "created_at": "2026-01-01T00:00:00Z"
        }
    ]
    users = [
        {
            "id": "AIDASNAP100USER",
            "name": "audit-user",
            "arn": "arn:aws:iam::123456789012:user/audit-user",
            "user_name": "audit-user",
            "attached_policies": ["arn:aws:iam::123456789012:policy/SecurityAuditPolicy"],
            "policies": ["SecurityAuditPolicy"],
            "groups": ["SecurityGroup"],
            "status": "active",
            "mfaEnabled": True,
            "riskScore": 25,
        }
    ]
    roles = [
        {
            "id": "AROASNAP100ROLE",
            "name": "AuditRole",
            "arn": "arn:aws:iam::123456789012:role/AuditRole",
            "role_name": "AuditRole",
            "attached_policies": [],
            "policies": [],
            "trustPolicy": '{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:user/audit-user"}, "Action": "sts:AssumeRole"}]}',
            "riskScore": 20,
        }
    ]
    groups = [
        {
            "id": "AGPASNAP100GRP",
            "name": "SecurityGroup",
            "arn": "arn:aws:iam::123456789012:group/SecurityGroup",
            "group_name": "SecurityGroup",
            "attached_policies": ["arn:aws:iam::123456789012:policy/SecurityAuditPolicy"]
        }
    ]
    resources = resources_list if resources_list is not None else [
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
    findings = [
        {
            "id": "finding-snap-100-1",
            "title": "Unrestricted Administrative Access",
            "description": "User has full admin access",
            "severity": "critical",
            "category": "iam",
            "status": "open",
            "source": "static_iam",
            "principal": "arn:aws:iam::123456789012:user/audit-user",
            "principalType": "User",
            "resource": "arn:aws:iam::123456789012:user/audit-user",
            "resourceType": "User",
            "riskScore": 95,
        }
    ]
    alerts = alerts_list if alerts_list is not None else [
        {
            "id": "alert-snap-100-1",
            "timestamp": "2026-09-26T11:58:00Z",
            "resource": "arn:aws:iam::123456789012:user/audit-user",
            "description": "Unauthorized Access Attempt Observed in CloudTrail",
            "severity": "high",
            "status": "open",
            "details": "{}",
        }
    ]
    attack_paths = [
        {
            "id": "path-snap-100-1",
            "name": "audit-user to audit-bucket-100",
            "source": "arn:aws:iam::123456789012:user/audit-user",
            "destination": "arn:aws:s3:::audit-bucket-100",
            "target": "arn:aws:s3:::audit-bucket-100",
            "pathType": "privilege_escalation",
            "riskScore": 90,
            "severity": "critical",
            "hopCount": 2,
            "blastRadius": "High",
            "mitreTechniques": ["T1078 - Valid Accounts"],
            "recommendation": "Enforce least privilege",
            "description": "audit-user can reach audit-bucket-100",
            "nodes": [
                {"id": "arn:aws:iam::123456789012:user/audit-user", "name": "audit-user", "type": "User"},
                {"id": "arn:aws:s3:::audit-bucket-100", "name": "audit-bucket-100", "type": "S3"}
            ],
            "orderedRelationships": ["ALLOWS"],
        }
    ]
    graph = [
        {
            "data": {
                "id": "aws:user:audit-user",
                "label": "audit-user",
                "type": "User",
                "arn": "arn:aws:iam::123456789012:user/audit-user",
                "riskScore": 25,
            }
        },
        {
            "data": {
                "id": "aws:s3:audit-bucket-100",
                "label": "audit-bucket-100",
                "type": "S3",
                "arn": "arn:aws:s3:::audit-bucket-100",
                "riskScore": 15,
            }
        },
    ]
    dashboard = {
        "securityScore": "82",
        "stats": {
            "users": len(users),
            "roles": len(roles),
            "policies": len(policies),
            "risks": len(risks),
            "paths": len(attack_paths),
            "resources": len(resources),
        },
        "riskDistribution": [
            {"name": "Critical", "value": 1, "color": "#EF4444"},
            {"name": "High", "value": 0, "color": "#F59E0B"},
            {"name": "Medium", "value": 0, "color": "#3B82F6"},
            {"name": "Low", "value": 0, "color": "#10B981"},
        ],
        "activityMetrics": {
            "staticAttackPaths": 1,
            "observedSecurityEvents": 1,
            "correlatedFindings": 0,
            "observedAttackActivity": 0,
        },
        "recentAlerts": alerts,
        "criticalPaths": attack_paths,
        "recommendations": [],
        "lastScan": {
            "timestamp": published_at,
            "duration_seconds": 1.5,
            "resources_found": len(resources),
            "risks_found": len(risks),
            "graph_nodes_count": len(graph),
            "graph_edges_count": 0,
        },
        "topRiskyIdentities": [],
        "resourceBreakdown": [],
        "scanId": snapshot_id,
        "scanStatus": "SUCCESS",
    }

    # Publish through immutable SnapshotStore (which sets versioned and active keys without TTL)
    snapshot_store.publish(
        snapshot_id=snapshot_id,
        published_at=published_at,
        status="SUCCESS",
        region_metadata={"scan_mode": "global", "successful_regions": ["us-east-1"], "failed_regions": []},
        collection_completeness={"is_complete": True, "total_regions": 1, "failed_count": 0, "success_count": 1},
        users=users,
        roles=roles,
        groups=groups,
        policies=policies,
        resources=resources,
        alerts=alerts,
        findings=findings,
        risks=risks,
        attack_paths=attack_paths,
        graph=graph,
        effective_access=[],
        dashboard=dashboard,
        scan_metadata={"snapshot_id": snapshot_id, "snapshot_published_at": published_at},
    )

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
            "findings": findings,
            "alerts": alerts,
            "v1:attack-paths": attack_paths,
            "v1:graph": graph,
            "v1:dashboard": dashboard,
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

    # 6. Attack Paths
    res_ap = client.get("/api/v1/attack-paths")
    assert res_ap.status_code == 200
    ap_json = res_ap.json()
    assert ap_json["snapshot_id"] == snap_id
    assert ap_json["snapshot_published_at"] == published_at
    assert len(ap_json["data"]) == 1

    # 7. Graph
    res_g = client.get("/api/v1/graph")
    assert res_g.status_code == 200
    g_json = res_g.json()
    assert g_json["snapshot_id"] == snap_id
    assert g_json["snapshot_published_at"] == published_at
    assert len(g_json["data"]) == 2

    # 8. Users
    res_u = client.get("/api/v1/users")
    assert res_u.status_code == 200
    u_json = res_u.json()
    assert u_json["snapshot_id"] == snap_id
    assert len(u_json["data"]) == 1

    # 9. Roles
    res_ro = client.get("/api/v1/roles")
    assert res_ro.status_code == 200
    ro_json = res_ro.json()
    assert ro_json["snapshot_id"] == snap_id
    assert len(ro_json["data"]) == 1

    # 10. Dashboard
    res_dash = client.get("/api/v1/dashboard")
    assert res_dash.status_code == 200
    dash_json = res_dash.json()
    assert dash_json["snapshot_id"] == snap_id
    assert dash_json["snapshot_published_at"] == published_at


def test_old_snapshot_survives_active_scan():
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
    assert res_p.json()["data"]["snapshot_id"] == "scan-snap-100"

    res_r = client.get("/api/v1/relationships")
    assert res_r.status_code == 200
    assert res_r.json()["data"]["snapshot_id"] == "scan-snap-100"

    res_k = client.get("/api/v1/risk-assessment")
    assert res_k.status_code == 200
    assert res_k.json()["snapshot_id"] == "scan-snap-100"

    res_a = client.get("/api/v1/alerts")
    assert res_a.status_code == 200
    assert res_a.json()["snapshot_id"] == "scan-snap-100"

    res_res = client.get("/api/v1/resources")
    assert res_res.status_code == 200
    assert res_res.json()["snapshot_id"] == "scan-snap-100"

    res_ap = client.get("/api/v1/attack-paths")
    assert res_ap.status_code == 200
    assert res_ap.json()["snapshot_id"] == "scan-snap-100"

    res_g = client.get("/api/v1/graph")
    assert res_g.status_code == 200
    assert res_g.json()["snapshot_id"] == "scan-snap-100"


def test_failed_scan_preserves_old_snapshot():
    """If scan B fails, snapshot A remains published and active."""
    seed_published_snapshot("scan-snap-100", "2026-09-26T12:00:00Z")

    # Simulate scan failure
    for target in (ScanManager, scan_manager):
        target._is_running = False
        target._scan_status = "FAILED"
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

    res_k = client.get("/api/v1/risk-assessment")
    assert res_k.status_code == 200
    assert res_k.json()["snapshot_id"] == "scan-snap-100"


def test_all_pages_switch_from_snapshot_a_to_b_together():
    """Once snapshot B is published, all endpoints atomically switch to snapshot B."""
    seed_published_snapshot("scan-snap-100", "2026-09-26T12:00:00Z")

    # Verify initial is snap-100 across pages
    assert client.get("/api/v1/policies").json()["data"]["snapshot_id"] == "scan-snap-100"
    assert client.get("/api/v1/relationships").json()["data"]["snapshot_id"] == "scan-snap-100"
    assert client.get("/api/v1/risk-assessment").json()["snapshot_id"] == "scan-snap-100"
    assert client.get("/api/v1/alerts").json()["snapshot_id"] == "scan-snap-100"
    assert client.get("/api/v1/resources").json()["snapshot_id"] == "scan-snap-100"
    assert client.get("/api/v1/attack-paths").json()["snapshot_id"] == "scan-snap-100"
    assert client.get("/api/v1/graph").json()["snapshot_id"] == "scan-snap-100"

    # Publish snapshot B
    seed_published_snapshot("scan-snap-101", "2026-09-26T12:05:00Z")

    # All endpoints now serve snap-101 together
    assert client.get("/api/v1/policies").json()["data"]["snapshot_id"] == "scan-snap-101"
    assert client.get("/api/v1/relationships").json()["data"]["snapshot_id"] == "scan-snap-101"
    assert client.get("/api/v1/risk-assessment").json()["snapshot_id"] == "scan-snap-101"
    assert client.get("/api/v1/alerts").json()["snapshot_id"] == "scan-snap-101"
    assert client.get("/api/v1/resources").json()["snapshot_id"] == "scan-snap-101"
    assert client.get("/api/v1/attack-paths").json()["snapshot_id"] == "scan-snap-101"
    assert client.get("/api/v1/graph").json()["snapshot_id"] == "scan-snap-101"


def test_empty_collections_are_not_replaced_by_stale_data():
    """A valid scan with zero alerts/policies publishes [] and does NOT fall back to older stale items."""
    # First publish snapshot with data
    seed_published_snapshot("scan-snap-100", "2026-09-26T12:00:00Z")
    res_a = client.get("/api/v1/alerts")
    assert len(res_a.json()["data"]) == 1

    # Second scan discovers ZERO alerts (clean security posture)
    seed_published_snapshot(
        "scan-snap-102",
        "2026-09-26T12:10:00Z",
        alerts_list=[],
    )

    # Must return empty list, NOT the old alert from snap-100
    res_a2 = client.get("/api/v1/alerts")
    assert res_a2.status_code == 200
    assert res_a2.json()["snapshot_id"] == "scan-snap-102"
    assert res_a2.json()["data"] == []


def test_partial_scan_publishes_reconciled_snapshot():
    """Partial scan publishes reconciled snapshot recording failed and successful regions."""
    snapshot_store.publish(
        snapshot_id="scan-snap-partial",
        published_at="2026-09-26T12:15:00Z",
        status="PARTIAL",
        region_metadata={
            "scan_mode": "multi",
            "successful_regions": ["us-east-1"],
            "failed_regions": ["eu-west-1"],
        },
        collection_completeness={
            "is_complete": False,
            "total_regions": 2,
            "failed_count": 1,
            "success_count": 1,
        },
        resources=[{"id": "res-1", "name": "res-1", "type": "S3", "region": "us-east-1", "arn": "arn:aws:s3:::res-1", "status": "active", "riskScore": 0}],
        scan_metadata={"snapshot_id": "scan-snap-partial", "status": "PARTIAL"}
    )

    snap = snapshot_store.get_current()
    assert snap is not None
    assert snap.status == "PARTIAL"
    assert snap.region_metadata["failed_regions"] == ["eu-west-1"]
    assert snap.region_metadata["successful_regions"] == ["us-east-1"]
    assert snap.collection_completeness["is_complete"] is False

    res_res = client.get("/api/v1/resources")
    assert res_res.status_code == 200
    assert res_res.json()["snapshot_id"] == "scan-snap-partial"
    assert len(res_res.json()["data"]) == 1


def test_request_reads_remain_pinned_when_publication_changes_mid_request():
    seed_published_snapshot("snapshot-request-a", "2026-10-01T00:00:00Z")
    from app.services.scanner.current_snapshot import get_current_resources
    import app.services.scanner.current_snapshot as current_snapshot
    original_pin = current_snapshot.pin_request_snapshot
    published = False

    def pin_a_then_publish_b():
        nonlocal published
        token = original_pin()
        if not published:
            published = True
            snapshot_store.publish(
                snapshot_id="snapshot-request-b",
                published_at="2026-10-02T00:00:00Z",
                status="SUCCESS",
                policies=[{"name": "PolicyB", "arn": "arn:aws:iam::123456789012:policy/PolicyB"}],
                resources=[{"id": "resource-b", "name": "resource-b", "type": "S3", "region": "us-east-1"}],
            )
        return token

    with patch.object(current_snapshot, "pin_request_snapshot", side_effect=pin_a_then_publish_b):
        response = client.get("/api/v1/policies")

    assert response.status_code == 200
    assert response.json()["data"]["snapshot_id"] == "snapshot-request-a"
    assert response.json()["data"]["items"][0]["name"] == "SecurityAuditPolicy"
    assert get_current_resources()[0]["name"] == "resource-b"


def test_snapshot_persistence_failure_does_not_publish_or_replace_current():
    seed_published_snapshot("snapshot-durable-a", "2026-10-01T00:00:00Z")
    with patch("app.persistence.repository.save_authoritative_snapshot", return_value=False):
        with pytest.raises(RuntimeError, match="Could not durably publish"):
            snapshot_store.publish(
                snapshot_id="snapshot-durable-b",
                published_at="2026-10-02T00:00:00Z",
                status="SUCCESS",
                resources=[{"id": "partial-b"}],
            )

    assert snapshot_store.get_current().snapshot_id == "snapshot-durable-a"
    assert cache.get("v1:current_snapshot_id") == "snapshot-durable-a"
    assert cache.get("v1:snapshot:snapshot-durable-b") is None


def test_request_snapshot_pin_keeps_all_collection_reads_on_same_version():
    seed_published_snapshot("snapshot-pin-a", "2026-10-01T00:00:00Z")
    token = pin_request_snapshot()
    try:
        snapshot_store.publish(
            snapshot_id="snapshot-pin-b",
            published_at="2026-10-02T00:00:00Z",
            status="SUCCESS",
            users=[{"name": "new-user"}],
            resources=[{"id": "new-resource"}],
        )
        from app.services.scanner.current_snapshot import get_current_users
        assert get_current_snapshot_id() == "snapshot-pin-a"
        assert get_current_users()[0]["name"] == "audit-user"
        assert get_current_resources()[0]["name"] == "audit-bucket-100"
    finally:
        reset_request_snapshot(token)


def test_scan_status_exposes_publication_and_regional_progress_fields():
    target = scan_manager
    target._is_running = True
    target._scan_id = "progress-scan-1"
    target._active_phase = "DISCOVERY"
    target._publication_state = "NOT_PUBLISHED"
    target._regional_status = {"EC2:us-east-1": "SUCCESS_EMPTY", "Lambda:eu-west-1": "FAILED: timeout"}

    status = target.get_status()
    assert status["scan_id"] == "progress-scan-1"
    assert status["active_phase"] == "DISCOVERY"
    assert status["elapsed_seconds"] >= 0
    assert status["collector_status"]
    assert status["regional_status"]["EC2:us-east-1"] == "SUCCESS_EMPTY"
    assert status["publication_state"] == "NOT_PUBLISHED"

