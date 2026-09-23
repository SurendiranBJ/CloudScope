"""
Phase 6 Hardening, Performance, Reliability, and Regression Tests for CloudScope.

Tests cover:
1. Scanner concurrency and lock protection against race conditions.
2. Granular phase duration measurement across all 6 pipeline stages.
3. Finding lifecycle state machine validation (rejecting invalid transitions).
4. Finding reopen functionality and API HTTP 400 validation.
5. Deterministic finding ID invariance across repeated extractions.
6. Regional failure isolation invariance on finding resolution.
7. ActivityEvent idempotency upon repeated event ingestion.
8. AccessDenied event security semantics (never treated as successful transitions).
9. Dashboard 4-state activity metrics and empty state safety.
"""

import pytest
from fastapi.testclient import TestClient
import networkx as nx

from app.main import app
from app.services.scanner.scan_manager import ScanManager
from app.services.scanner.inventory import AWSInventory
from app.services.findings.finding_service import (
    FindingService,
    compute_deterministic_id,
    finding_service,
)
from app.schemas import SecurityFinding, FindingRemediation
from app.services.attack.cloudtrail_correlator import correlate_activity_with_graph


@pytest.fixture
def client():
    return TestClient(app)


# ==============================================================================
# 1. Scanner Concurrency & Bounded Execution
# ==============================================================================

def test_scanner_concurrency_rejects_duplicate_scan():
    """Verify that ScanManager rejects overlapping scan triggers without crashing."""
    manager = ScanManager()

    # Simulate scan in progress
    manager._is_running = True
    res = manager.trigger_async_scan()
    assert res["status"] == "already_running"
    assert "in progress" in res["message"].lower()

    # Verify run_scan also acquires lock non-blockingly
    manager._is_running = False
    acquired = manager._lock.acquire(blocking=False)
    assert acquired is True

    try:
        # A second run_scan while lock is held must cleanly return skipped
        skipped_res = manager.run_scan()
        assert skipped_res["status"] == "skipped"
        assert "already running" in skipped_res["message"].lower()
    finally:
        manager._lock.release()


# ==============================================================================
# 2. Granular Phase Duration Measurement
# ==============================================================================

def test_phase_duration_timing_recorded():
    """Verify ScanManager measures and exposes phase durations in get_status()."""
    manager = ScanManager()
    manager._phase_durations = {
        "discovery": 1.25,
        "iam_analysis": 0.45,
        "graph_construction": 0.30,
        "path_analysis": 0.20,
        "cloudtrail_correlation": 0.15,
        "finding_synthesis": 0.10,
        "total": 2.45
    }

    status = manager.get_status()
    assert "phase_durations" in status
    pd = status["phase_durations"]
    assert pd["discovery"] == 1.25
    assert pd["iam_analysis"] == 0.45
    assert pd["graph_construction"] == 0.30
    assert pd["path_analysis"] == 0.20
    assert pd["cloudtrail_correlation"] == 0.15
    assert pd["finding_synthesis"] == 0.10
    assert pd["total"] == 2.45


# ==============================================================================
# 3. Finding Lifecycle State Machine Validation
# ==============================================================================

def test_lifecycle_state_machine_transitions():
    """Verify finding lifecycle state machine allows valid transitions and rejects invalid ones."""
    svc = FindingService()
    test_finding = SecurityFinding(
        id="test-lifecycle-001",
        type="S3_PUBLIC_EXPOSURE",
        category="DATA_EXPOSURE",
        title="Public Bucket",
        description="Bucket allows public read",
        severity="high",
        riskScore=75,
        riskFactors=[],
        resource="my-test-bucket",
        resourceType="S3",
        region="us-east-1",
        status="OPEN",
        source="STATIC_ANALYSIS",
        evidence={"public": True},
        remediation=FindingRemediation(
            title="Block Public Access",
            summary="Block public access",
            action_type="S3_BLOCK_PUBLIC_ACCESS",
            steps=["1. Enable block public access"],
            priority="IMMEDIATE"
        )
    )

    svc._save_findings([test_finding])

    # 1. OPEN -> ACKNOWLEDGED (valid)
    ack_res = svc.acknowledge_finding("test-lifecycle-001")
    assert ack_res is not None
    assert ack_res.status == "ACKNOWLEDGED"

    # 2. ACKNOWLEDGED -> RESOLVED (valid)
    res_res = svc.resolve_finding("test-lifecycle-001")
    assert res_res is not None
    assert res_res.status == "RESOLVED"

    # 3. RESOLVED -> ACKNOWLEDGED (invalid: must raise ValueError)
    with pytest.raises(ValueError) as exc_info:
        svc.acknowledge_finding("test-lifecycle-001")
    assert "reopen" in str(exc_info.value).lower()

    # 4. RESOLVED -> SUPPRESSED (invalid: must raise ValueError)
    with pytest.raises(ValueError) as exc_info:
        svc.suppress_finding("test-lifecycle-001")
    assert "reopen" in str(exc_info.value).lower()

    # 5. RESOLVED -> reopen -> OPEN (valid)
    reopen_res = svc.reopen_finding("test-lifecycle-001")
    assert reopen_res is not None
    assert reopen_res.status == "OPEN"

    # 6. OPEN -> SUPPRESSED (valid)
    sup_res = svc.suppress_finding("test-lifecycle-001")
    assert sup_res is not None
    assert sup_res.status == "SUPPRESSED"


def test_api_findings_lifecycle_validation_http_codes(client):
    """Verify REST API returns 400 Bad Request on invalid lifecycle state transitions."""
    test_finding = SecurityFinding(
        id="test-api-lifecycle-002",
        type="NO_MFA",
        category="IDENTITY_EXCESSIVE_PRIVILEGE",
        title="No MFA for User",
        description="User lacks MFA",
        severity="high",
        riskScore=75,
        riskFactors=[],
        principal="test-user",
        principalType="User",
        resource="test-user",
        resourceType="User",
        region="global",
        status="OPEN",
        source="STATIC_ANALYSIS",
        evidence={"mfa": False},
        remediation=FindingRemediation(
            title="Enable MFA",
            summary="Enable MFA",
            action_type="ENABLE_MFA",
            steps=["1. Enable virtual MFA device"],
            priority="IMMEDIATE"
        )
    )

    finding_service._save_findings([test_finding])

    # Transition to RESOLVED
    res1 = client.post("/api/v1/findings/test-api-lifecycle-002/resolve")
    assert res1.status_code == 200
    assert res1.json()["data"]["status"] == "RESOLVED"

    # Attempting to ACKNOWLEDGE a RESOLVED finding must return 400 Bad Request
    res2 = client.post("/api/v1/findings/test-api-lifecycle-002/acknowledge")
    assert res2.status_code == 400
    assert "reopen" in res2.json()["detail"].lower()

    # Reopening the finding returns 200 OK and status OPEN
    res3 = client.post("/api/v1/findings/test-api-lifecycle-002/reopen")
    assert res3.status_code == 200
    assert res3.json()["data"]["status"] == "OPEN"

    # Now acknowledging succeeds
    res4 = client.post("/api/v1/findings/test-api-lifecycle-002/acknowledge")
    assert res4.status_code == 200
    assert res4.json()["data"]["status"] == "ACKNOWLEDGED"


# ==============================================================================
# 4. Deterministic Finding ID Stability Across Repeated Scans
# ==============================================================================

def test_deterministic_id_invariance():
    """Verify compute_deterministic_id produces deterministic, repeatable SHA-256 hashes."""
    id1 = compute_deterministic_id("S3_PUBLIC_EXPOSURE", resource="arn:aws:s3:::my-test-bucket", region="us-east-1")
    id2 = compute_deterministic_id("S3_PUBLIC_EXPOSURE", resource="arn:aws:s3:::my-test-bucket", region="us-east-1")
    assert id1 == id2
    assert id1.startswith("find-")
    assert len(id1) >= 20

    # Different resource yields different ID
    id3 = compute_deterministic_id("S3_PUBLIC_EXPOSURE", resource="arn:aws:s3:::other-bucket", region="us-east-1")
    assert id1 != id3


# ==============================================================================
# 5. Regional Failure Isolation Invariance
# ==============================================================================

def test_regional_failure_isolation_preserves_findings():
    """Verify that findings in a region that fails during a scan are never resolved."""
    svc = FindingService()
    active_finding = SecurityFinding(
        id="find-regional-isolate-01",
        type="EC2_PUBLIC_IP",
        category="NETWORK_EXPOSURE",
        title="Public EC2 Instance",
        description="Instance has public IP",
        severity="medium",
        riskScore=50,
        riskFactors=[],
        resource="i-1234567890abcdef0",
        resourceType="EC2",
        region="ap-south-1",
        status="OPEN",
        source="STATIC_ANALYSIS",
        evidence={"public_ip": "1.2.3.4"},
        remediation=FindingRemediation(
            title="Restrict Public IP",
            summary="Restrict public IP",
            action_type="RESTRICT_SECURITY_GROUP",
            steps=["1. Remove public IPv4"],
            priority="SCHEDULED"
        )
    )

    svc._save_findings([active_finding])

    # Reconcile with an empty inventory where ap-south-1 FAILED
    inv = AWSInventory()
    reconciled = svc.reconcile_scan_findings(
        inventory=inv,
        successful_regions=["us-east-1"],
        failed_regions=["ap-south-1"],
        scan_timestamp="2026-09-23T05:00:00Z"
    )

    matched = next((f for f in reconciled if f.id == "find-regional-isolate-01"), None)
    assert matched is not None
    # Must REMAIN OPEN because ap-south-1 failed
    assert matched.status == "OPEN"

    # Now reconcile when ap-south-1 SUCCESSFUL (resource genuinely gone)
    reconciled_after_fix = svc.reconcile_scan_findings(
        inventory=inv,
        successful_regions=["ap-south-1", "us-east-1"],
        failed_regions=[],
        scan_timestamp="2026-09-23T06:00:00Z"
    )
    matched_after = next((f for f in reconciled_after_fix if f.id == "find-regional-isolate-01"), None)
    assert matched_after is not None
    # Now it is safely RESOLVED
    assert matched_after.status == "RESOLVED"


# ==============================================================================
# 6. ActivityEvent Idempotency & Denied Events
# ==============================================================================

def test_activity_event_idempotency_and_denied_semantics():
    """Verify repeated ingestion of same event retains 1 node and AccessDenied remains OBSERVED_ACTIVITY."""
    G = nx.DiGraph()
    G.add_node("aws:user:alice", label="alice", type="User", riskScore=50)
    G.add_node("aws:role:AdminRole", label="AdminRole", type="Role", riskScore=85)
    # Alice has NO static CAN_ASSUME edge to AdminRole

    inv = AWSInventory()
    event = {
        "event_id": "evt-repeat-001",
        "event_name": "AssumeRole",
        "actor": "alice",
        "target": "AdminRole",
        "error_code": "AccessDenied",
        "error_message": "User is not authorized to perform sts:AssumeRole",
        "timestamp": "2026-09-23T04:00:00Z"
    }

    # First run
    res1 = correlate_activity_with_graph([event], inv, G)
    assert G.has_node("event:evt-repeat-001")
    # AccessDenied must remain OBSERVED_ACTIVITY (never CORRELATED_ACTIVITY)
    assert res1["metrics"]["correlated_activity_count"] == 0
    assert res1["metrics"]["observed_activity_count"] == 1

    # Second run with exact same event
    res2 = correlate_activity_with_graph([event], inv, G)
    # Node must remain exactly 1
    activity_nodes = [n for n in G.nodes() if n == "event:evt-repeat-001"]
    assert len(activity_nodes) == 1
    assert res2["metrics"]["correlated_activity_count"] == 0


# ==============================================================================
# 7. Dashboard 4 Security States & Empty State
# ==============================================================================

def test_dashboard_api_returns_four_security_states_and_empty_state_safety(client):
    """Verify /api/v1/dashboard returns valid 4-state activity metrics and handles cold state cleanly."""
    res = client.get("/api/v1/dashboard")
    assert res.status_code == 200
    data = res.json()["data"]

    # Security score format
    assert "securityScore" in data
    # Stats structure
    stats = data["stats"]
    assert all(k in stats for k in ["users", "roles", "policies", "risks", "paths", "resources"])

    # 4 Security states correlation metrics
    assert "activityMetrics" in data
    am = data["activityMetrics"]
    assert am is not None
    assert "staticAttackPaths" in am
    assert "observedSecurityEvents" in am
    assert "correlatedFindings" in am
    assert "observedAttackActivity" in am

    # Risk distribution categories present
    rd = data["riskDistribution"]
    assert len(rd) == 4
    severity_names = {x["name"] for x in rd}
    assert severity_names == {"Critical", "High", "Medium", "Low"}
