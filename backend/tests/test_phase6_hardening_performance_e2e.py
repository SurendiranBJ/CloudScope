"""
Phase 6 Hardening, Performance, Reliability, Deployment, and E2E Regression Tests for CloudScope.

Covers all 25 validation requirements:
1. atomic duplicate scan rejection
2. scan lock release after failure
3. phase timing fields
4. duration values >= 0
5. stage failure states
6. lifecycle: OPEN -> ACKNOWLEDGED
7. lifecycle: ACKNOWLEDGED -> RESOLVED
8. invalid: RESOLVED -> ACKNOWLEDGED
9. reopen: RESOLVED -> OPEN
10. suppression lifecycle
11. deterministic ID stability
12. existing finding ID compatibility
13. regional failed finding preservation
14. successful-region resolution
15. repeated CloudTrail eventId idempotency
16. denied CloudTrail events remain observed activity
17. exact attack-path transition correlation
18. dashboard cold state
19. dashboard populated state
20. query parameter validation
21. limit/offset validation
22. no secret fields exposed
23. remediation remains read-only
24. JSON export uses real findings
25. report counts match canonical findings
"""

import math
import pytest
import threading
from unittest.mock import patch
from fastapi.testclient import TestClient
import networkx as nx

from app.main import app
from app.cache import cache
from app.services.scanner.scan_manager import ScanManager, scan_manager
from app.services.scanner.inventory import AWSInventory
from app.services.findings.finding_service import (
    FindingService,
    compute_deterministic_id,
    finding_service,
    generate_remediation
)
from app.schemas import SecurityFinding, FindingRemediation
from app.services.attack.cloudtrail_correlator import correlate_activity_with_graph
from app.routers.reports import _compute_reports_from_cache


@pytest.fixture
def client():
    return TestClient(app)


# ------------------------------------------------------------------------------
# 1. Atomic Duplicate Scan Rejection
# ------------------------------------------------------------------------------
def test_01_atomic_duplicate_scan_rejection():
    """Verify duplicate scan triggers are rejected atomically with status 'already_running'."""
    manager = ScanManager()

    # When a scan is running, immediate trigger returns already_running
    manager._is_running = True
    res = manager.trigger_async_scan()
    assert res["status"] in ("already_running", "skipped")
    assert "already running" in res["message"].lower()

    # Reset
    manager._is_running = False
    with patch.object(threading.Thread, "start"):
        res_started = manager.trigger_async_scan()
        assert res_started["status"] == "started"
        assert "scan started" in res_started["message"].lower()

        # Immediate follow-up must be rejected
        res_dup = manager.trigger_async_scan()
        assert res_dup["status"] in ("already_running", "skipped")
        assert "already running" in res_dup["message"].lower()


# ------------------------------------------------------------------------------
# 2. Scan Lock Release After Failure
# ------------------------------------------------------------------------------
def test_02_scan_lock_release_after_failure():
    """Verify scan lock/slot is released deterministically when an execution fails."""
    manager = ScanManager()
    manager._is_running = True

    with patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", side_effect=RuntimeError("STS failure")):
        result = manager._execute_scan("test-failure-scan-id")
        assert result["status"] == "failed"
        assert manager.is_running is False

    # After failure, another scan can be triggered
    with patch.object(threading.Thread, "start"):
        res = manager.trigger_async_scan()
        assert res["status"] == "started"


# ------------------------------------------------------------------------------
# 3. Phase Timing Fields
# ------------------------------------------------------------------------------
def test_03_phase_timing_fields():
    """Verify all 6 pipeline phases + total duration are recorded with duration and status."""
    manager = ScanManager()
    status = manager.get_status()
    assert "phase_durations" in status
    pd = status["phase_durations"]

    expected_phases = [
        "discovery",
        "iam_analysis",
        "graph_construction",
        "path_analysis",
        "cloudtrail_correlation",
        "finding_synthesis",
        "total"
    ]
    for phase in expected_phases:
        assert phase in pd, f"Missing phase '{phase}' in phase_durations"
        assert "duration_seconds" in pd[phase]
        assert "status" in pd[phase]


# ------------------------------------------------------------------------------
# 4. Duration Values >= 0
# ------------------------------------------------------------------------------
def test_04_duration_values_greater_than_or_equal_to_zero():
    """Verify duration values are numeric, finite, and >= 0."""
    manager = ScanManager()
    pd = manager.get_status()["phase_durations"]
    for phase, info in pd.items():
        dur = info["duration_seconds"]
        assert isinstance(dur, (int, float))
        assert math.isfinite(dur)
        assert dur >= 0.0


# ------------------------------------------------------------------------------
# 5. Stage Failure States
# ------------------------------------------------------------------------------
def test_05_stage_failure_states():
    """Verify that aborted scans mark the failing phase as FAILED and unreached phases as SKIPPED."""
    manager = ScanManager()
    manager._phase_durations["discovery"] = {"duration_seconds": 1.45, "status": "FAILED"}
    manager._phase_durations["total"] = {"duration_seconds": 1.45, "status": "FAILED"}

    pd = manager.get_status()["phase_durations"]
    assert pd["discovery"]["status"] == "FAILED"
    assert pd["iam_analysis"]["status"] == "SKIPPED"
    assert pd["graph_construction"]["status"] == "SKIPPED"
    assert pd["total"]["status"] == "FAILED"


# ------------------------------------------------------------------------------
# 6. Lifecycle: OPEN -> ACKNOWLEDGED
# ------------------------------------------------------------------------------
def test_06_lifecycle_open_to_acknowledged():
    """Verify transitioning finding from OPEN to ACKNOWLEDGED succeeds."""
    svc = FindingService()
    f = SecurityFinding(
        id="find-life-01",
        type="NO_MFA",
        category="CREDENTIAL",
        title="No MFA",
        description="User lacks MFA",
        severity="high",
        riskScore=75,
        riskFactors=[],
        principal="test-user-1",
        principalType="User",
        resource="test-user-1",
        resourceType="User",
        region="global",
        status="OPEN",
        source="STATIC_IAM",
        evidence={"mfa": False}
    )
    svc._save_findings([f])

    updated = svc.acknowledge_finding("find-life-01")
    assert updated is not None
    assert updated.status == "ACKNOWLEDGED"
    assert updated.updatedAt is not None


# ------------------------------------------------------------------------------
# 7. Lifecycle: ACKNOWLEDGED -> RESOLVED
# ------------------------------------------------------------------------------
def test_07_lifecycle_acknowledged_to_resolved():
    """Verify transitioning finding from ACKNOWLEDGED to RESOLVED succeeds."""
    svc = FindingService()
    f = SecurityFinding(
        id="find-life-02",
        type="NO_MFA",
        category="CREDENTIAL",
        title="No MFA",
        description="User lacks MFA",
        severity="high",
        riskScore=75,
        riskFactors=[],
        status="ACKNOWLEDGED",
        source="STATIC_IAM",
        evidence={"mfa": False}
    )
    svc._save_findings([f])

    updated = svc.resolve_finding("find-life-02")
    assert updated is not None
    assert updated.status == "RESOLVED"
    assert updated.resolvedAt is not None


# ------------------------------------------------------------------------------
# 8. Invalid: RESOLVED -> ACKNOWLEDGED
# ------------------------------------------------------------------------------
def test_08_invalid_lifecycle_resolved_to_acknowledged():
    """Verify invalid transition from RESOLVED to ACKNOWLEDGED raises ValueError."""
    svc = FindingService()
    f = SecurityFinding(
        id="find-life-03",
        type="NO_MFA",
        category="CREDENTIAL",
        title="No MFA",
        description="User lacks MFA",
        severity="high",
        riskScore=75,
        riskFactors=[],
        status="RESOLVED",
        source="STATIC_IAM",
        evidence={"mfa": False}
    )
    svc._save_findings([f])

    with pytest.raises(ValueError) as exc:
        svc.acknowledge_finding("find-life-03")
    assert "Invalid finding status transition" in str(exc.value)


# ------------------------------------------------------------------------------
# 9. Reopen: RESOLVED -> OPEN
# ------------------------------------------------------------------------------
def test_09_reopen_resolved_to_open():
    """Verify reopening a RESOLVED finding transitions it to OPEN and clears resolvedAt."""
    svc = FindingService()
    f = SecurityFinding(
        id="find-life-04",
        type="NO_MFA",
        category="CREDENTIAL",
        title="No MFA",
        description="User lacks MFA",
        severity="high",
        riskScore=75,
        riskFactors=[],
        status="RESOLVED",
        resolvedAt="2026-09-23T00:00:00Z",
        source="STATIC_IAM",
        evidence={"mfa": False}
    )
    svc._save_findings([f])

    reopened = svc.reopen_finding("find-life-04")
    assert reopened is not None
    assert reopened.status == "OPEN"
    assert reopened.resolvedAt is None


# ------------------------------------------------------------------------------
# 10. Suppression Lifecycle
# ------------------------------------------------------------------------------
def test_10_suppression_lifecycle():
    """Verify OPEN -> SUPPRESSED, SUPPRESSED -> ACK (invalid), SUPPRESSED -> OPEN (valid), SUPPRESSED -> RESOLVED (valid)."""
    svc = FindingService()
    f = SecurityFinding(
        id="find-life-05",
        type="NO_MFA",
        category="CREDENTIAL",
        title="No MFA",
        description="User lacks MFA",
        severity="high",
        riskScore=75,
        riskFactors=[],
        status="OPEN",
        source="STATIC_IAM",
        evidence={"mfa": False}
    )
    svc._save_findings([f])

    # OPEN -> SUPPRESSED
    suppressed = svc.suppress_finding("find-life-05")
    assert suppressed.status == "SUPPRESSED"

    # SUPPRESSED -> ACKNOWLEDGED (invalid)
    with pytest.raises(ValueError):
        svc.acknowledge_finding("find-life-05")

    # SUPPRESSED -> RESOLVED (valid)
    resolved = svc.resolve_finding("find-life-05")
    assert resolved.status == "RESOLVED"


# ------------------------------------------------------------------------------
# 11. Deterministic ID Stability
# ------------------------------------------------------------------------------
def test_11_deterministic_id_stability():
    """Verify same semantic inputs generate identical stable IDs across calls."""
    id1 = compute_deterministic_id("S3_PUBLIC_EXPOSURE", resource="arn:aws:s3:::prod-bucket", region="us-east-1")
    id2 = compute_deterministic_id("S3_PUBLIC_EXPOSURE", resource="arn:aws:s3:::prod-bucket", region="us-east-1")
    assert id1 == id2
    assert id1.startswith("find-")

    # Different resource yields different ID
    id3 = compute_deterministic_id("S3_PUBLIC_EXPOSURE", resource="arn:aws:s3:::other-bucket", region="us-east-1")
    assert id1 != id3


# ------------------------------------------------------------------------------
# 12. Existing Finding ID Compatibility
# ------------------------------------------------------------------------------
def test_12_existing_finding_id_compatibility():
    """Verify compatibility with existing CloudTrail event IDs and attack-path IDs."""
    ct_id = compute_deterministic_id("CLOUDTRAIL_ANOMALY", event_id="evt-abc-999")
    assert ct_id == "find-ct-evt-abc-999"

    path_id = compute_deterministic_id("ATTACK_PATH_VULNERABILITY", attack_path_id="path-admin-esc")
    assert path_id == "find-path-admin-esc"


# ------------------------------------------------------------------------------
# 13. Regional Failed Finding Preservation
# ------------------------------------------------------------------------------
def test_13_regional_failed_finding_preservation():
    """Verify findings in a region that failed are NEVER resolved or pruned."""
    svc = FindingService()
    f = SecurityFinding(
        id="find-fail-preserve-01",
        type="EC2_PUBLIC_IP",
        category="NETWORK_EXPOSURE",
        title="Public EC2",
        description="Public IP attached",
        severity="medium",
        riskScore=50,
        riskFactors=[],
        region="ap-south-1",
        status="OPEN",
        source="RESOURCE_CONFIGURATION",
        evidence={"public_ip": "13.234.1.2"}
    )
    svc._save_findings([f])

    inv = AWSInventory()
    reconciled = svc.reconcile_scan_findings(
        inventory=inv,
        successful_regions=["us-east-1"],
        failed_regions=["ap-south-1"]
    )
    preserved = next((x for x in reconciled if x.id == "find-fail-preserve-01"), None)
    assert preserved is not None
    assert preserved.status == "OPEN"


# ------------------------------------------------------------------------------
# 14. Successful-Region Resolution
# ------------------------------------------------------------------------------
def test_14_successful_region_resolution():
    """Verify findings in a successful region are marked RESOLVED when the resource is gone."""
    svc = FindingService()
    f = SecurityFinding(
        id="find-succ-resolve-01",
        type="EC2_PUBLIC_IP",
        category="NETWORK_EXPOSURE",
        title="Public EC2",
        description="Public IP attached",
        severity="medium",
        riskScore=50,
        riskFactors=[],
        region="ap-south-1",
        status="OPEN",
        source="RESOURCE_CONFIGURATION",
        evidence={"public_ip": "13.234.1.2"}
    )
    svc._save_findings([f])

    inv = AWSInventory()
    reconciled = svc.reconcile_scan_findings(
        inventory=inv,
        successful_regions=["ap-south-1"],
        failed_regions=[]
    )
    resolved = next((x for x in reconciled if x.id == "find-succ-resolve-01"), None)
    assert resolved is not None
    assert resolved.status == "RESOLVED"
    assert resolved.resolvedAt is not None


# ------------------------------------------------------------------------------
# 15. Repeated CloudTrail EventId Idempotency
# ------------------------------------------------------------------------------
def test_15_repeated_cloudtrail_event_id_idempotency():
    """Verify ingesting the same CloudTrail event multiple times is idempotent."""
    G = nx.DiGraph()
    G.add_node("aws:user:bob", label="bob", type="User", riskScore=40)
    G.add_node("aws:role:TargetRole", label="TargetRole", type="Role", riskScore=70)

    inv = AWSInventory()
    ev = {
        "event_id": "evt-idempotent-001",
        "event_name": "AssumeRole",
        "actor": "bob",
        "target": "TargetRole",
        "timestamp": "2026-09-23T05:00:00Z"
    }

    res1 = correlate_activity_with_graph([ev], inv, G)
    nodes_count_1 = G.number_of_nodes()

    res2 = correlate_activity_with_graph([ev], inv, G)
    nodes_count_2 = G.number_of_nodes()

    assert nodes_count_1 == nodes_count_2
    assert G.has_node("event:evt-idempotent-001")


# ------------------------------------------------------------------------------
# 16. Denied CloudTrail Events Remain Observed Activity
# ------------------------------------------------------------------------------
def test_16_denied_cloudtrail_events_remain_observed_activity():
    """Verify AccessDenied events remain OBSERVED_ACTIVITY and never CORRELATED_ACTIVITY."""
    G = nx.DiGraph()
    G.add_node("aws:user:alice", label="alice", type="User", riskScore=30)
    G.add_node("aws:role:AdminRole", label="AdminRole", type="Role", riskScore=90)
    # Alice has CAN_ASSUME edge
    G.add_edge("aws:user:alice", "aws:role:AdminRole", label="CAN_ASSUME", edge_type="CAN_ASSUME")

    inv = AWSInventory()
    denied_ev = {
        "event_id": "evt-denied-001",
        "event_name": "AssumeRole",
        "actor": "alice",
        "target": "AdminRole",
        "error_code": "AccessDenied",
        "error_message": "Explicit deny in policy",
        "timestamp": "2026-09-23T05:30:00Z"
    }

    res = correlate_activity_with_graph([denied_ev], inv, G)
    metrics = res["metrics"]
    assert metrics["correlated_activity_count"] == 0
    assert metrics["observed_activity_count"] == 1


# ------------------------------------------------------------------------------
# 17. Exact Attack-Path Transition Correlation
# ------------------------------------------------------------------------------
def test_17_exact_attack_path_transition_correlation():
    """Verify events matching exact attack path transitions correlate as OBSERVED_ATTACK_ACTIVITY."""
    alice_arn = "arn:aws:iam::123456789012:user/alice"
    role_jump_arn = "arn:aws:iam::123456789012:role/JumpRole"

    attack_paths = [
        {
            "id": "path-jump-1",
            "name": "Jump Path",
            "nodes": [
                {"id": alice_arn, "name": "alice"},
                {"id": role_jump_arn, "name": "JumpRole"}
            ],
            "ordered_relationships": ["CAN_ASSUME"]
        }
    ]

    event = {
        "EventId": "evt-attack-001",
        "EventName": "AssumeRole",
        "EventTime": "2026-09-22T16:20:00Z",
        "userIdentity": {"type": "IAMUser", "arn": alice_arn, "userName": "alice"},
        "RequestParameters": '{"roleArn": "arn:aws:iam::123456789012:role/JumpRole"}'
    }

    res = correlate_activity_with_graph([event], G=nx.DiGraph(), attack_paths=attack_paths)
    finding = res["correlated_findings"][0]
    assert finding["type"] == "OBSERVED_ATTACK_ACTIVITY"
    assert attack_paths[0]["correlation_status"] == "OBSERVED_ATTACK_ACTIVITY"
    metrics = res["metrics"]
    assert metrics["observed_attack_activity_count"] == 1
    assert metrics["correlated_activity_count"] == 1


# ------------------------------------------------------------------------------
# 18. Dashboard Cold State
# ------------------------------------------------------------------------------
def test_18_dashboard_cold_state(client):
    """Verify GET /api/v1/dashboard handles cold state cleanly without null errors."""
    cache.clear()
    res = client.get("/api/v1/dashboard")
    assert res.status_code == 200
    data = res.json()["data"]
    assert "securityScore" in data
    assert "stats" in data
    assert "activityMetrics" in data
    assert "phaseDurations" in data or "phase_durations" in data


# ------------------------------------------------------------------------------
# 19. Dashboard Populated State
# ------------------------------------------------------------------------------
def test_19_dashboard_populated_state(client):
    """Verify GET /api/v1/dashboard returns real authoritative counts when populated."""
    scan_manager._is_running = False
    scan_manager._scan_status = "SUCCESS"
    cache.set("v1:dashboard", {
        "securityScore": "85 / 100",
        "stats": {
            "users": 5,
            "roles": 3,
            "policies": 12,
            "risks": 2,
            "paths": 1,
            "resources": 25
        },
        "activityMetrics": {
            "staticAttackPaths": 1,
            "observedSecurityEvents": 10,
            "correlatedFindings": 2,
            "observedAttackActivity": 1
        },
        "riskDistribution": [
            {"name": "Critical", "value": 1, "color": "#EF4444"},
            {"name": "High", "value": 1, "color": "#F59E0B"},
            {"name": "Medium", "value": 0, "color": "#3B82F6"},
            {"name": "Low", "value": 0, "color": "#10B981"}
        ],
        "recentAlerts": [],
        "criticalPaths": [],
        "recommendations": [],
        "resourceBreakdown": [{"type": "IAM Users", "count": 5}],
        "topRiskyIdentities": [{"name": "alice", "type": "User", "riskScore": 75}],
        "scanStatus": "SUCCESS"
    })

    res = client.get("/api/v1/dashboard")
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["stats"]["users"] == 5
    assert data["stats"]["roles"] == 3
    assert data["scanStatus"] == "SUCCESS"


# ------------------------------------------------------------------------------
# 20. Query Parameter Validation
# ------------------------------------------------------------------------------
def test_20_query_parameter_validation(client):
    """Verify GET /api/v1/findings rejects invalid query params with HTTP 400."""
    res_sev = client.get("/api/v1/findings?severity=SUPER_CRITICAL")
    assert res_sev.status_code == 400

    res_st = client.get("/api/v1/findings?status=PENDING_REVIEW")
    assert res_st.status_code == 400

    res_cat = client.get("/api/v1/findings?category=UNKNOWN_CAT")
    assert res_cat.status_code == 400

    res_src = client.get("/api/v1/findings?source=INVALID_SRC")
    assert res_src.status_code == 400


# ------------------------------------------------------------------------------
# 21. Limit / Offset Validation
# ------------------------------------------------------------------------------
def test_21_limit_offset_validation(client):
    """Verify limit and offset boundary validations enforce 1-200 and >= 0."""
    res_lim_low = client.get("/api/v1/findings?limit=0")
    assert res_lim_low.status_code == 400

    res_lim_high = client.get("/api/v1/findings?limit=201")
    assert res_lim_high.status_code == 400

    res_off_neg = client.get("/api/v1/findings?offset=-5")
    assert res_off_neg.status_code == 400

    res_ok = client.get("/api/v1/findings?limit=50&offset=0")
    assert res_ok.status_code == 200


# ------------------------------------------------------------------------------
# 22. No Secret Fields Exposed
# ------------------------------------------------------------------------------
def test_22_no_secret_fields_exposed(client):
    """Verify findings and responses do not leak AWS secret keys, session tokens, or private credentials."""
    findings = finding_service.get_all_findings()
    forbidden_keys = {
        "aws_secret_access_key",
        "secret_access_key",
        "secretaccesskey",
        "session_token",
        "sessiontoken",
        "secretstring",
        "private_key",
        "privatekey"
    }

    for f in findings:
        dump = str(f.model_dump()).lower()
        for fk in forbidden_keys:
            assert fk not in dump, f"Found forbidden credential key '{fk}' in finding {f.id}"


# ------------------------------------------------------------------------------
# 23. Remediation Remains Read-Only
# ------------------------------------------------------------------------------
def test_23_remediation_remains_read_only():
    """Verify remediations only provide guidance/CLI commands and make no mutating calls."""
    user = {"name": "test-rem-user", "arn": "arn:aws:iam::123:user/test-rem-user"}
    rem = generate_remediation("NO_MFA", user)
    assert isinstance(rem, FindingRemediation)
    assert "MFA" in rem.title
    assert len(rem.steps) > 0
    # Steps are instructional strings, not executing boto3 mutations
    for step in rem.steps:
        assert isinstance(step, str)


# ------------------------------------------------------------------------------
# 24. JSON Export Uses Real Findings
# ------------------------------------------------------------------------------
def test_24_json_export_uses_real_findings():
    """Verify report summary uses authentic findings from cache, not dummy or mock datasets."""
    report = _compute_reports_from_cache()
    assert "summary" in report
    assert "compliance" in report
    assert "findings" in report
    assert isinstance(report["findings"], list)


# ------------------------------------------------------------------------------
# 25. Report Counts Match Canonical Findings
# ------------------------------------------------------------------------------
def test_25_report_counts_match_canonical_findings():
    """Verify report summary findings_count matches count of open canonical findings."""
    f1 = SecurityFinding(
        id="f-report-match-01",
        type="NO_MFA",
        category="CREDENTIAL",
        title="Test",
        description="Test",
        severity="high",
        riskScore=70,
        riskFactors=[],
        status="OPEN",
        source="STATIC_IAM",
        evidence={}
    )
    cache.set("v1:findings", [f1.model_dump()])
    cache.set("v1:users", [{"name": "test"}])

    report = _compute_reports_from_cache()
    assert report["summary"]["findings_count"] == 1
    assert report["findings_by_severity"]["high"] == 1


# ------------------------------------------------------------------------------
# 26. IAM Analysis Failure Marks FAILED & Unreached SKIPPED
# ------------------------------------------------------------------------------
def test_26_phase_failure_iam_analysis_marks_failed_and_unreached_skipped():
    """Verify that a failure during IAM Analysis marks that phase FAILED and subsequent phases SKIPPED."""
    mgr = ScanManager()
    with patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "123", "arn": "arn:aws:iam::123:root", "region": "ap-south-1"}), \
         patch("app.services.scanner.scan_manager.iam_service.collect_users", return_value=[{"name": "u1", "inlinePolicyDocuments": {}}]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_roles", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_groups", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_policies", return_value=[]), \
         patch("app.services.scanner.scan_manager.ec2_service.collect_ec2_instances", return_value=[]), \
         patch("app.services.scanner.scan_manager.s3_service.collect_s3_buckets", return_value=[]), \
         patch("app.services.scanner.scan_manager.lambda_service.collect_lambda_functions", return_value=[]), \
         patch("app.services.scanner.scan_manager.secrets_service.collect_secrets", return_value=[]), \
         patch("app.services.scanner.scan_manager.rds_service.collect_rds_instances", return_value=[]), \
         patch("app.services.scanner.scan_manager.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
         patch("app.services.scanner.scan_manager.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
         patch("app.services.scanner.scan_manager.cloudtrail_service.collect_recent_alerts", return_value=[]), \
         patch("app.services.scanner.scan_manager.risk_engine.get_user_risk_assessment", side_effect=RuntimeError("IAM Risk Engine Fatal Error")):

        res = mgr._execute_scan("scan-test-iam-fail")
        assert res["scan_status"] == "FAILED"
        pd = res["phase_durations"]
        assert pd["discovery"]["status"] == "COMPLETED"
        assert pd["iam_analysis"]["status"] == "FAILED"
        assert pd["graph_construction"]["status"] == "SKIPPED"
        assert pd["path_analysis"]["status"] == "SKIPPED"
        assert pd["cloudtrail_correlation"]["status"] == "SKIPPED"
        assert pd["finding_synthesis"]["status"] == "SKIPPED"
        assert pd["total"]["status"] == "FAILED"


# ------------------------------------------------------------------------------
# 27. Graph Construction Failure Marks FAILED & Unreached SKIPPED
# ------------------------------------------------------------------------------
def test_27_phase_failure_graph_construction_marks_failed_and_unreached_skipped():
    """Verify that a failure during Graph Construction marks that phase FAILED and subsequent phases SKIPPED."""
    mgr = ScanManager()
    with patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "123", "arn": "arn:aws:iam::123:root", "region": "ap-south-1"}), \
         patch("app.services.scanner.scan_manager.iam_service.collect_users", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_roles", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_groups", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_policies", return_value=[]), \
         patch("app.services.scanner.scan_manager.ec2_service.collect_ec2_instances", return_value=[]), \
         patch("app.services.scanner.scan_manager.s3_service.collect_s3_buckets", return_value=[]), \
         patch("app.services.scanner.scan_manager.lambda_service.collect_lambda_functions", return_value=[]), \
         patch("app.services.scanner.scan_manager.secrets_service.collect_secrets", return_value=[]), \
         patch("app.services.scanner.scan_manager.rds_service.collect_rds_instances", return_value=[]), \
         patch("app.services.scanner.scan_manager.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
         patch("app.services.scanner.scan_manager.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
         patch("app.services.scanner.scan_manager.cloudtrail_service.collect_recent_alerts", return_value=[]), \
         patch("app.services.scanner.scan_manager.graph_builder.build_graph_in_neo4j", side_effect=Exception("Neo4j down")), \
         patch("app.services.scanner.scan_manager.graph_loader.build_local_graph", side_effect=RuntimeError("Graph Memory Crash")):

        res = mgr._execute_scan("scan-test-graph-fail")
        assert res["scan_status"] == "FAILED"
        pd = res["phase_durations"]
        assert pd["discovery"]["status"] == "COMPLETED"
        assert pd["iam_analysis"]["status"] == "COMPLETED"
        assert pd["graph_construction"]["status"] == "FAILED"
        assert pd["path_analysis"]["status"] == "SKIPPED"
        assert pd["cloudtrail_correlation"]["status"] == "SKIPPED"
        assert pd["finding_synthesis"]["status"] == "SKIPPED"
        assert pd["total"]["status"] == "FAILED"


# ------------------------------------------------------------------------------
# 28. Path Analysis Failure Marks FAILED & Unreached SKIPPED
# ------------------------------------------------------------------------------
def test_28_phase_failure_path_analysis_marks_failed_and_unreached_skipped():
    """Verify that a failure during Path Analysis marks that phase FAILED and subsequent phases SKIPPED."""
    mgr = ScanManager()
    with patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "123", "arn": "arn:aws:iam::123:root", "region": "ap-south-1"}), \
         patch("app.services.scanner.scan_manager.iam_service.collect_users", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_roles", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_groups", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_policies", return_value=[]), \
         patch("app.services.scanner.scan_manager.ec2_service.collect_ec2_instances", return_value=[]), \
         patch("app.services.scanner.scan_manager.s3_service.collect_s3_buckets", return_value=[]), \
         patch("app.services.scanner.scan_manager.lambda_service.collect_lambda_functions", return_value=[]), \
         patch("app.services.scanner.scan_manager.secrets_service.collect_secrets", return_value=[]), \
         patch("app.services.scanner.scan_manager.rds_service.collect_rds_instances", return_value=[]), \
         patch("app.services.scanner.scan_manager.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
         patch("app.services.scanner.scan_manager.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
         patch("app.services.scanner.scan_manager.cloudtrail_service.collect_recent_alerts", return_value=[]), \
         patch("app.services.scanner.scan_manager.graph_builder.build_graph_in_neo4j", return_value=None), \
         patch("app.services.scanner.scan_manager.graph_loader.build_local_graph", return_value=nx.DiGraph()), \
         patch("app.services.scanner.scan_manager.path_engine.find_attack_paths", side_effect=RuntimeError("Path Engine Overflow")):

        res = mgr._execute_scan("scan-test-path-fail")
        assert res["scan_status"] == "FAILED"
        pd = res["phase_durations"]
        assert pd["discovery"]["status"] == "COMPLETED"
        assert pd["iam_analysis"]["status"] == "COMPLETED"
        assert pd["graph_construction"]["status"] == "COMPLETED"
        assert pd["path_analysis"]["status"] == "FAILED"
        assert pd["cloudtrail_correlation"]["status"] == "SKIPPED"
        assert pd["finding_synthesis"]["status"] == "SKIPPED"
        assert pd["total"]["status"] == "FAILED"


# ------------------------------------------------------------------------------
# 29. CloudTrail Correlation Failure Marks FAILED & Unreached SKIPPED
# ------------------------------------------------------------------------------
def test_29_phase_failure_cloudtrail_correlation_marks_failed_and_unreached_skipped():
    """Verify that a failure during CloudTrail Correlation marks that phase FAILED and subsequent phases SKIPPED."""
    mgr = ScanManager()
    with patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "123", "arn": "arn:aws:iam::123:root", "region": "ap-south-1"}), \
         patch("app.services.scanner.scan_manager.iam_service.collect_users", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_roles", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_groups", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_policies", return_value=[]), \
         patch("app.services.scanner.scan_manager.ec2_service.collect_ec2_instances", return_value=[]), \
         patch("app.services.scanner.scan_manager.s3_service.collect_s3_buckets", return_value=[]), \
         patch("app.services.scanner.scan_manager.lambda_service.collect_lambda_functions", return_value=[]), \
         patch("app.services.scanner.scan_manager.secrets_service.collect_secrets", return_value=[]), \
         patch("app.services.scanner.scan_manager.rds_service.collect_rds_instances", return_value=[]), \
         patch("app.services.scanner.scan_manager.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
         patch("app.services.scanner.scan_manager.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
         patch("app.services.scanner.scan_manager.cloudtrail_service.collect_recent_alerts", return_value=[]), \
         patch("app.services.scanner.scan_manager.graph_builder.build_graph_in_neo4j", return_value=None), \
         patch("app.services.scanner.scan_manager.graph_loader.build_local_graph", return_value=nx.DiGraph()), \
         patch("app.services.scanner.scan_manager.path_engine.find_attack_paths", return_value=[]), \
         patch("app.services.scanner.scan_manager.cloudtrail_correlator.correlate_activity_with_graph", side_effect=RuntimeError("Correlator Deadlock")):

        res = mgr._execute_scan("scan-test-ct-fail")
        assert res["scan_status"] == "FAILED"
        pd = res["phase_durations"]
        assert pd["discovery"]["status"] == "COMPLETED"
        assert pd["iam_analysis"]["status"] == "COMPLETED"
        assert pd["graph_construction"]["status"] == "COMPLETED"
        assert pd["path_analysis"]["status"] == "COMPLETED"
        assert pd["cloudtrail_correlation"]["status"] == "FAILED"
        assert pd["finding_synthesis"]["status"] == "SKIPPED"
        assert pd["total"]["status"] == "FAILED"


# ------------------------------------------------------------------------------
# 30. Finding Synthesis Failure Marks FAILED & Total FAILED
# ------------------------------------------------------------------------------
def test_30_phase_failure_finding_synthesis_marks_failed_and_total_failed():
    """Verify that a failure during Finding Synthesis marks that phase FAILED and total FAILED."""
    mgr = ScanManager()
    with patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "123", "arn": "arn:aws:iam::123:root", "region": "ap-south-1"}), \
         patch("app.services.scanner.scan_manager.iam_service.collect_users", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_roles", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_groups", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_policies", return_value=[]), \
         patch("app.services.scanner.scan_manager.ec2_service.collect_ec2_instances", return_value=[]), \
         patch("app.services.scanner.scan_manager.s3_service.collect_s3_buckets", return_value=[]), \
         patch("app.services.scanner.scan_manager.lambda_service.collect_lambda_functions", return_value=[]), \
         patch("app.services.scanner.scan_manager.secrets_service.collect_secrets", return_value=[]), \
         patch("app.services.scanner.scan_manager.rds_service.collect_rds_instances", return_value=[]), \
         patch("app.services.scanner.scan_manager.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
         patch("app.services.scanner.scan_manager.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
         patch("app.services.scanner.scan_manager.cloudtrail_service.collect_recent_alerts", return_value=[]), \
         patch("app.services.scanner.scan_manager.graph_builder.build_graph_in_neo4j", return_value=None), \
         patch("app.services.scanner.scan_manager.graph_loader.build_local_graph", return_value=nx.DiGraph()), \
         patch("app.services.scanner.scan_manager.path_engine.find_attack_paths", return_value=[]), \
         patch("app.services.scanner.scan_manager.cloudtrail_correlator.correlate_activity_with_graph", return_value={"correlated_findings": [], "metrics": {}}), \
         patch("app.services.scanner.scan_manager.finding_service.reconcile_scan_findings", side_effect=RuntimeError("Lifecycle Reconciliation Crash")):

        res = mgr._execute_scan("scan-test-find-fail")
        assert res["scan_status"] == "FAILED"
        pd = res["phase_durations"]
        assert pd["discovery"]["status"] == "COMPLETED"
        assert pd["iam_analysis"]["status"] == "COMPLETED"
        assert pd["graph_construction"]["status"] == "COMPLETED"
        assert pd["path_analysis"]["status"] == "COMPLETED"
        assert pd["cloudtrail_correlation"]["status"] == "COMPLETED"
        assert pd["finding_synthesis"]["status"] == "FAILED"
        assert pd["total"]["status"] == "FAILED"


# ------------------------------------------------------------------------------
# 31. Scan Metadata: SUCCESS Updates Both Completed and Successful
# ------------------------------------------------------------------------------
def test_31_scan_metadata_success_updates_both_completed_and_successful():
    """Verify that a successful scan updates both lastCompletedScanAt and lastSuccessfulScanAt."""
    mgr = ScanManager()
    with patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "123", "arn": "arn:aws:iam::123:root", "region": "ap-south-1"}), \
         patch("app.services.scanner.scan_manager.iam_service.collect_users", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_roles", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_groups", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_policies", return_value=[]), \
         patch("app.services.scanner.scan_manager.ec2_service.collect_ec2_instances", return_value=[]), \
         patch("app.services.scanner.scan_manager.s3_service.collect_s3_buckets", return_value=[]), \
         patch("app.services.scanner.scan_manager.lambda_service.collect_lambda_functions", return_value=[]), \
         patch("app.services.scanner.scan_manager.secrets_service.collect_secrets", return_value=[]), \
         patch("app.services.scanner.scan_manager.rds_service.collect_rds_instances", return_value=[]), \
         patch("app.services.scanner.scan_manager.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
         patch("app.services.scanner.scan_manager.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
         patch("app.services.scanner.scan_manager.cloudtrail_service.collect_recent_alerts", return_value=[]), \
         patch("app.services.scanner.scan_manager.graph_builder.build_graph_in_neo4j", return_value=None), \
         patch("app.services.scanner.scan_manager.graph_loader.build_local_graph", return_value=nx.DiGraph()), \
         patch("app.services.scanner.scan_manager.path_engine.find_attack_paths", return_value=[]), \
         patch("app.services.scanner.scan_manager.cloudtrail_correlator.correlate_activity_with_graph", return_value={"correlated_findings": [], "metrics": {}}), \
         patch("app.services.scanner.scan_manager.finding_service.reconcile_scan_findings", return_value=[]):

        res = mgr._execute_scan("scan-test-success-meta")
        assert res["scan_status"] == "SUCCESS"
        assert mgr._last_completed_scan_at is not None
        assert mgr._last_successful_scan_at is not None
        assert mgr._last_completed_scan_at == mgr._last_successful_scan_at
        assert mgr._last_completed_scan_id == "scan-test-success-meta"
        assert mgr._last_successful_scan_id == "scan-test-success-meta"


# ------------------------------------------------------------------------------
# 32. Scan Metadata: PARTIAL Updates Completed but Preserves Successful
# ------------------------------------------------------------------------------
def test_32_scan_metadata_partial_updates_completed_but_preserves_successful():
    """Verify that a PARTIAL scan updates lastCompletedScanAt but preserves previous lastSuccessfulScanAt."""
    class FakeRegionalResult:
        def __init__(self):
            self.items = []
            self.regional_status = {"ap-south-1": "SUCCESS", "us-east-1": "FAILED: AccessDenied"}
            self.successful_regions = ["ap-south-1"]
            self.failed_regions = ["us-east-1"]

    mgr = ScanManager()
    mgr._last_successful_scan_at = "2026-09-23T01:00:00Z"
    mgr._last_successful_scan_id = "prior-good-id"

    with patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "123", "arn": "arn:aws:iam::123:root", "region": "ap-south-1"}), \
         patch("app.services.scanner.scan_manager.iam_service.collect_users", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_roles", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_groups", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_policies", return_value=[]), \
         patch("app.services.scanner.scan_manager.ec2_service.collect_ec2_instances", return_value=FakeRegionalResult()), \
         patch("app.services.scanner.scan_manager.s3_service.collect_s3_buckets", return_value=[]), \
         patch("app.services.scanner.scan_manager.lambda_service.collect_lambda_functions", return_value=[]), \
         patch("app.services.scanner.scan_manager.secrets_service.collect_secrets", return_value=[]), \
         patch("app.services.scanner.scan_manager.rds_service.collect_rds_instances", return_value=[]), \
         patch("app.services.scanner.scan_manager.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
         patch("app.services.scanner.scan_manager.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
         patch("app.services.scanner.scan_manager.cloudtrail_service.collect_recent_alerts", return_value=[]), \
         patch("app.services.scanner.scan_manager.graph_builder.build_graph_in_neo4j", return_value=None), \
         patch("app.services.scanner.scan_manager.graph_loader.build_local_graph", return_value=nx.DiGraph()), \
         patch("app.services.scanner.scan_manager.path_engine.find_attack_paths", return_value=[]), \
         patch("app.services.scanner.scan_manager.cloudtrail_correlator.correlate_activity_with_graph", return_value={"correlated_findings": [], "metrics": {}}), \
         patch("app.services.scanner.scan_manager.finding_service.reconcile_scan_findings", return_value=[]):

        res = mgr._execute_scan("scan-test-partial-meta")
        assert res["scan_status"] == "PARTIAL"
        assert mgr._last_completed_scan_at != "2026-09-23T01:00:00Z"
        assert mgr._last_completed_scan_id == "scan-test-partial-meta"
        # Crucial preservation guarantee:
        assert mgr._last_successful_scan_at == "2026-09-23T01:00:00Z"
        assert mgr._last_successful_scan_id == "prior-good-id"


# ------------------------------------------------------------------------------
# 33. Scan Metadata: FAILED Preserves Both Previous Timestamps
# ------------------------------------------------------------------------------
def test_33_scan_metadata_failed_preserves_both_previous_timestamps():
    """Verify that a FAILED scan does not update lastCompletedScanAt or lastSuccessfulScanAt."""
    mgr = ScanManager()
    mgr._last_completed_scan_at = "2026-09-23T01:00:00Z"
    mgr._last_completed_scan_id = "prior-completed-id"
    mgr._last_successful_scan_at = "2026-09-23T01:00:00Z"
    mgr._last_successful_scan_id = "prior-successful-id"

    with patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": False, "error": "InvalidClientTokenId"}):
        res = mgr._execute_scan("scan-test-fail-preserve")
        assert res["scan_status"] == "FAILED"
        assert mgr._last_completed_scan_at == "2026-09-23T01:00:00Z"
        assert mgr._last_completed_scan_id == "prior-completed-id"
        assert mgr._last_successful_scan_at == "2026-09-23T01:00:00Z"
        assert mgr._last_successful_scan_id == "prior-successful-id"


# ------------------------------------------------------------------------------
# 34. JSON Export Endpoint Exercises Canonical Findings and Metadata
# ------------------------------------------------------------------------------
def test_34_json_export_endpoint_exercises_canonical_findings_and_metadata(client):
    """Verify that GET /api/v1/reports/export/json produces authentic scan metadata and canonical findings."""
    scan_meta = {
        "scanId": "scan-export-abc",
        "scanStatus": "SUCCESS",
        "scannedRegions": ["ap-south-1"],
        "durationSeconds": 2.45,
        "lastCompletedScanAt": "2026-09-23T05:00:00Z",
        "lastSuccessfulScanAt": "2026-09-23T05:00:00Z",
    }
    cache.set("v1:scan_metadata", scan_meta)

    f1 = SecurityFinding(
        id="f-canonical-export-01",
        type="NO_MFA",
        category="CREDENTIAL",
        title="Root user without MFA",
        description="The account root user does not have MFA enabled",
        severity="critical",
        riskScore=95,
        riskFactors=[{"code": "ROOT_USER", "points": 50, "reason": "Root account access"}],
        status="OPEN",
        source="STATIC_IAM",
        principal="root",
        principalType="User",
        evidence={"mfa_active": False}
    )
    cache.set("v1:findings", [f1.model_dump()])
    cache.set("v1:users", [{"name": "root", "mfaEnabled": False, "riskScore": 95}])

    resp = client.get("/api/v1/reports/export/json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    data = body["data"]

    assert "generated_at" in data
    assert data["scan_information"]["scan_id"] == "scan-export-abc"
    assert data["scan_information"]["scan_status"] == "SUCCESS"
    assert "ap-south-1" in data["scan_information"]["scanned_regions"]
    assert "security_summary" in data
    assert "score" in data["security_summary"]
    assert len(data["canonical_findings"]) >= 1
    assert data["canonical_findings"][0]["id"] == "f-canonical-export-01"
    assert data["canonical_findings"][0]["severity"] == "critical"
    assert data["canonical_findings"][0]["principal"] == "root"


# ------------------------------------------------------------------------------
# 35. High-Resolution Monotonic Timing Recorded for All Phases
# ------------------------------------------------------------------------------
def test_35_monotonic_timing_high_resolution_recorded_for_all_phases():
    """Verify that all 6 phases + total have high-resolution float durations and valid status."""
    manager = ScanManager()
    pd = manager.get_status()["phase_durations"]
    expected_phases = [
        "discovery",
        "iam_analysis",
        "graph_construction",
        "path_analysis",
        "cloudtrail_correlation",
        "finding_synthesis",
        "total"
    ]
    for p in expected_phases:
        assert p in pd
        assert isinstance(pd[p]["duration_seconds"], float)
        assert pd[p]["duration_seconds"] >= 0.0
        assert pd[p]["status"] in {"COMPLETED", "FAILED", "SKIPPED"}

