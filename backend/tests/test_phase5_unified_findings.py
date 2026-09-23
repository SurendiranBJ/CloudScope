"""
Phase 5 Comprehensive Test Suite: Unified Security Findings, Explainable Risk,
Remediation Guidance, Finding Lifecycle, Deduplication, and Real-Data-Only Reporting.

Tests all 30 scenarios specified in Section 34 of Phase 5 requirements.
"""

import json
import pytest
from datetime import datetime
from fastapi.testclient import TestClient

from app.main import app
from app.cache import cache
from app.schemas import SecurityFinding, FindingRemediation
from app.services.scanner.inventory import AWSInventory
from app.services.findings.finding_service import (
    FindingService,
    compute_deterministic_id,
    finding_service
)
from app.services.findings.remediation_engine import (
    generate_remediation,
    REMEDIATION_TEMPLATES
)
from app.routers.reports import _compute_reports_from_cache

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_test_cache():
    """Ensure clean cache before and after each test."""
    cache.clear()
    finding_service._memory_store.clear()
    yield
    cache.clear()
    finding_service._memory_store.clear()


# ==============================================================================
# 1. FINDING MODEL TESTS (Scenarios 1-3)
# ==============================================================================

def test_1_canonical_finding_serialization():
    """1. Canonical SecurityFinding serializes cleanly to dict and JSON."""
    remediation = FindingRemediation(
        title="Enable MFA for IAM User",
        summary="User credentials lack MFA.",
        steps=["Step 1", "Step 2"],
        priority="HIGH",
        references=["https://docs.aws.amazon.com/mfa"]
    )
    finding = SecurityFinding(
        id="find-mfa-123456",
        type="NO_MFA",
        category="CREDENTIAL",
        title="MFA Not Enabled for User 'alice'",
        description="IAM user alice lacks MFA.",
        severity="high",
        riskScore=75,
        riskFactors=[{"code": "NO_MFA", "points": 25, "reason": "No MFA"}],
        principal="alice",
        principalType="User",
        resource="alice",
        resourceType="User",
        region="global",
        evidence={"mfa_enabled": False},
        impact="Direct credential compromise allows access.",
        remediation=remediation,
        status="OPEN",
        firstSeen="2026-09-23T00:00:00Z",
        lastSeen="2026-09-23T00:00:00Z",
        source="STATIC_IAM",
        tags=["iam", "mfa"]
    )
    dumped = finding.model_dump()
    assert dumped["id"] == "find-mfa-123456"
    assert dumped["remediation"]["title"] == "Enable MFA for IAM User"
    assert json.loads(finding.model_dump_json())["riskScore"] == 75


def test_2_required_fields_enforcement():
    """2. Required fields must be provided; missing required fields raise error."""
    with pytest.raises(Exception):
        SecurityFinding(
            id="missing-fields",
            type="NO_MFA"
            # Missing category, title, description, severity, riskScore, source
        )


def test_3_optional_evidence_handling():
    """3. Optional evidence fields handle None/empty gracefully without crash."""
    finding = SecurityFinding(
        id="find-no-evidence-1",
        type="BROAD_IAM_PERMISSION",
        category="IAM",
        title="Elevated User",
        description="Broad permissions",
        severity="medium",
        riskScore=50,
        source="STATIC_IAM",
        evidence=None,
        impact=None,
        remediation=None,
        firstSeen=None,
        lastSeen=None
    )
    assert finding.evidence is None
    assert finding.remediation is None
    assert finding.status == "OPEN"


# ==============================================================================
# 2. FINDING DEDUPLICATION TESTS (Scenarios 4-5)
# ==============================================================================

def test_4_same_static_finding_across_scans_remains_one_finding():
    """4. The same static vulnerability across repeated scans produces identical ID."""
    id_scan_1 = compute_deterministic_id(
        finding_type="S3_PUBLIC_EXPOSURE",
        resource="arn:aws:s3:::prod-data",
        region="us-east-1"
    )
    id_scan_2 = compute_deterministic_id(
        finding_type="S3_PUBLIC_EXPOSURE",
        resource="arn:aws:s3:::prod-data",
        region="us-east-1"
    )
    assert id_scan_1 == id_scan_2
    assert "2026" not in id_scan_1  # No timestamps in static IDs


def test_5_runtime_event_deduplicates_using_event_id():
    """5. Runtime CloudTrail findings deduplicate strictly on eventId."""
    id1 = compute_deterministic_id("OBSERVED_SECURITY_ACTIVITY", event_id="evt-unique-999")
    id2 = compute_deterministic_id("OBSERVED_SECURITY_ACTIVITY", event_id="evt-unique-999")
    assert id1 == id2
    assert id1 == "find-ct-evt-unique-999"


# ==============================================================================
# 3. EXPLAINABLE RISK TESTS (Scenarios 6-9)
# ==============================================================================

def test_6_risk_score_remains_clamped_0_to_100():
    """6. Risk scores are strictly integers between 0 and 100."""
    inv = AWSInventory()
    inv.users = [{"name": "alice", "arn": "arn:aws:iam::123:user/alice", "mfaEnabled": False, "riskScore": 95}]
    service = FindingService()
    findings = service.extract_findings_from_scan(inv)
    for f in findings:
        assert 0 <= f.riskScore <= 100


def test_7_severity_matches_score_thresholds():
    """7. Severity adheres strictly to 80+ critical, 60+ high, 40+ medium, <40 low."""
    from app.services.risk.risk_constants import get_severity_label
    assert get_severity_label(85) == "critical"
    assert get_severity_label(80) == "critical"
    assert get_severity_label(79) == "high"
    assert get_severity_label(60) == "high"
    assert get_severity_label(59) == "medium"
    assert get_severity_label(40) == "medium"
    assert get_severity_label(39) == "low"
    assert get_severity_label(0) == "low"


def test_8_factor_evidence_is_preserved():
    """8. Each finding risk score preserves concrete risk factors with points and reason."""
    inv = AWSInventory()
    inv.users = [{
        "name": "alice",
        "arn": "arn:aws:iam::123:user/alice",
        "mfaEnabled": False,
        "riskScore": 75,
        "riskAssessment": {
            "factors": [
                {"code": "NO_MFA", "points": 15, "reason": "No MFA device registered"},
                {"code": "INACTIVE_CREDENTIALS", "points": 10, "reason": "Stale credentials"}
            ]
        }
    }]
    service = FindingService()
    findings = service.extract_findings_from_scan(inv)
    mfa_finding = next(f for f in findings if f.type == "NO_MFA")
    assert mfa_finding.riskFactors is not None
    assert len(mfa_finding.riskFactors) > 0
    assert mfa_finding.riskFactors[0]["points"] > 0


def test_9_no_fake_likelihood_or_probability():
    """9. Finding models do not contain fabricated likelihood or probability fields."""
    finding = SecurityFinding(
        id="test-f",
        type="NO_MFA",
        category="CREDENTIAL",
        title="No MFA",
        description="No MFA",
        severity="medium",
        riskScore=50,
        source="STATIC_IAM"
    )
    dumped = finding.model_dump()
    assert "likelihood" not in dumped
    assert "probability" not in dumped


# ==============================================================================
# 4. REMEDIATION GUIDANCE TESTS (Scenarios 10-13)
# ==============================================================================

def test_10_passrole_finding_gets_passrole_remediation():
    """10. PassRole escalation finding gets PassRole-specific remediation."""
    rem = generate_remediation("PASSROLE_ESCALATION", {"name": "DevRole"})
    assert "PassRole" in rem.title
    assert rem.priority == "CRITICAL"
    assert any("iam:PassedToService" in step or "Resource" in step for step in rem.steps)


def test_11_s3_exposure_gets_s3_remediation():
    """11. S3 public exposure finding gets S3 Block Public Access remediation."""
    rem = generate_remediation("S3_PUBLIC_EXPOSURE", {"name": "public-bucket"})
    assert "Block Public Access" in rem.title
    assert rem.priority == "CRITICAL"
    assert any("Block all public access" in s for s in rem.steps)


def test_12_mfa_finding_gets_mfa_remediation():
    """12. MFA finding gets MFA enforcement remediation."""
    rem = generate_remediation("NO_MFA", {"name": "alice"})
    assert "Enable MFA" in rem.title
    assert rem.priority == "HIGH"
    assert any("TOTP" in s or "MFA device" in s for s in rem.steps)


def test_13_no_remediation_mutates_aws():
    """13. Remediation engine provides guidance strings only; never executes AWS API calls."""
    import inspect
    import app.services.findings.remediation_engine as rem_mod
    source = inspect.getsource(rem_mod)
    assert "boto3" not in source
    assert "client.put_" not in source
    assert "client.modify_" not in source
    assert "client.delete_" not in source


# ==============================================================================
# 5. FINDING LIFECYCLE TESTS (Scenarios 14-18)
# ==============================================================================

def test_14_new_finding_is_open():
    """14. A newly discovered finding always starts with status OPEN."""
    inv = AWSInventory()
    inv.users = [{"name": "alice", "arn": "arn:aws:iam::123:user/alice", "mfaEnabled": False, "riskScore": 75}]
    service = FindingService()
    reconciled = service.reconcile_scan_findings(inv, scan_timestamp="2026-09-23T01:00:00Z")
    assert len(reconciled) > 0
    assert reconciled[0].status == "OPEN"


def test_15_acknowledgement_changes_status():
    """15. User acknowledgement changes status to ACKNOWLEDGED."""
    inv = AWSInventory()
    inv.users = [{"name": "alice", "arn": "arn:aws:iam::123:user/alice", "mfaEnabled": False, "riskScore": 75}]
    reconciled = finding_service.reconcile_scan_findings(inv, scan_timestamp="2026-09-23T01:00:00Z")
    fid = reconciled[0].id

    updated = finding_service.acknowledge_finding(fid)
    assert updated is not None
    assert updated.status == "ACKNOWLEDGED"

    # Persists in store
    retrieved = finding_service.get_finding_by_id(fid)
    assert retrieved.status == "ACKNOWLEDGED"


def test_16_resolve_works():
    """16. Explicit or scan-driven resolution transitions status to RESOLVED."""
    inv = AWSInventory()
    inv.users = [{"name": "alice", "arn": "arn:aws:iam::123:user/alice", "mfaEnabled": False, "riskScore": 75}]
    reconciled = finding_service.reconcile_scan_findings(inv, scan_timestamp="2026-09-23T01:00:00Z")
    fid = reconciled[0].id

    updated = finding_service.resolve_finding(fid)
    assert updated.status == "RESOLVED"


def test_17_suppression_works():
    """17. User suppression transitions status to SUPPRESSED."""
    inv = AWSInventory()
    inv.users = [{"name": "alice", "arn": "arn:aws:iam::123:user/alice", "mfaEnabled": False, "riskScore": 75}]
    reconciled = finding_service.reconcile_scan_findings(inv, scan_timestamp="2026-09-23T01:00:00Z")
    fid = reconciled[0].id

    updated = finding_service.suppress_finding(fid)
    assert updated.status == "SUPPRESSED"


def test_18_resolved_finding_is_not_deleted_from_history():
    """18. When a condition disappears, finding transitions to RESOLVED and retains history."""
    inv1 = AWSInventory()
    inv1.users = [{"name": "alice", "arn": "arn:aws:iam::123:user/alice", "mfaEnabled": False, "riskScore": 75}]
    service = FindingService()
    service.reconcile_scan_findings(inv1, successful_regions=["us-east-1"], scan_timestamp="2026-09-23T01:00:00Z")

    # In scan 2, Alice enabled MFA -> condition resolved
    inv2 = AWSInventory()
    inv2.users = [{"name": "alice", "arn": "arn:aws:iam::123:user/alice", "mfaEnabled": True, "riskScore": 0}]
    scan2_findings = service.reconcile_scan_findings(inv2, successful_regions=["us-east-1"], scan_timestamp="2026-09-23T02:00:00Z")

    # Finding must NOT be deleted
    assert len(scan2_findings) > 0
    mfa_finding = next(f for f in scan2_findings if f.type == "NO_MFA")
    assert mfa_finding.status == "RESOLVED"
    assert mfa_finding.firstSeen == "2026-09-23T01:00:00Z"
    assert mfa_finding.lastSeen == "2026-09-23T02:00:00Z"


# ==============================================================================
# 6. REGIONAL FAILURE ISOLATION (Scenarios 19-20)
# ==============================================================================

def test_19_failed_region_does_not_resolve_finding():
    """19. If a region fails in the scan, its findings must NOT be resolved."""
    inv1 = AWSInventory()
    inv1.s3 = [{"name": "prod-bucket", "arn": "arn:aws:s3:::prod-bucket", "region": "eu-north-1", "details": {"public_blocked": False}, "riskScore": 85}]
    service = FindingService()
    service.reconcile_scan_findings(inv1, successful_regions=["eu-north-1"], scan_timestamp="2026-09-23T01:00:00Z")

    # In scan 2, eu-north-1 failed! Inventory is empty for that region
    inv2 = AWSInventory()
    inv2.s3 = []
    scan2_findings = service.reconcile_scan_findings(
        inv2,
        successful_regions=["us-east-1"],
        failed_regions=["eu-north-1"],
        scan_timestamp="2026-09-23T02:00:00Z"
    )

    s3_finding = next((f for f in scan2_findings if f.type == "S3_PUBLIC_EXPOSURE"), None)
    assert s3_finding is not None
    # Must remain OPEN because region failed, not resolved!
    assert s3_finding.status == "OPEN"


def test_20_successful_region_reconciliation_resolves_finding():
    """20. When a region successfully scans and condition is gone, finding is resolved."""
    inv1 = AWSInventory()
    inv1.s3 = [{"name": "prod-bucket", "arn": "arn:aws:s3:::prod-bucket", "region": "eu-north-1", "details": {"public_blocked": False}, "riskScore": 85}]
    service = FindingService()
    service.reconcile_scan_findings(inv1, successful_regions=["eu-north-1"], scan_timestamp="2026-09-23T01:00:00Z")

    # In scan 2, eu-north-1 succeeds and bucket is now secure
    inv2 = AWSInventory()
    inv2.s3 = [{"name": "prod-bucket", "arn": "arn:aws:s3:::prod-bucket", "region": "eu-north-1", "details": {"public_blocked": True, "encrypted": True}, "riskScore": 0}]
    scan2_findings = service.reconcile_scan_findings(
        inv2,
        successful_regions=["eu-north-1"],
        failed_regions=[],
        scan_timestamp="2026-09-23T02:00:00Z"
    )

    s3_finding = next(f for f in scan2_findings if f.type == "S3_PUBLIC_EXPOSURE")
    assert s3_finding.status == "RESOLVED"


# ==============================================================================
# 7. CLOUDTRAIL INTEGRATION TESTS (Scenarios 21-25)
# ==============================================================================

def test_21_static_only_finding_remains_static():
    """21. Static IAM misconfigurations without CloudTrail activity have source STATIC_IAM."""
    inv = AWSInventory()
    inv.users = [{"name": "alice", "arn": "arn:aws:iam::123:user/alice", "mfaEnabled": False, "riskScore": 75}]
    service = FindingService()
    findings = service.extract_findings_from_scan(inv)
    assert findings[0].source == "STATIC_IAM"
    assert findings[0].eventId is None


def test_22_observed_only_event_remains_observed():
    """22. Standalone CloudTrail events without matching static path are marked CLOUDTRAIL."""
    inv = AWSInventory()
    raw_corr = [{
        "eventId": "evt-lone-1",
        "eventName": "DescribeInstances",
        "actor": "bob",
        "target": "EC2",
        "severity": "low",
        "riskScore": 20,
        "matched_static_relationship": "NONE",
        "reason": "Observed lone management event"
    }]
    service = FindingService()
    findings = service.extract_findings_from_scan(inv, correlated_findings=raw_corr)
    ct_finding = next(f for f in findings if f.eventId == "evt-lone-1")
    assert ct_finding.source == "CLOUDTRAIL"


def test_23_correlated_event_links_to_static_finding():
    """23. Correlated finding preserves source CORRELATION and matched static relationship."""
    inv = AWSInventory()
    raw_corr = [{
        "eventId": "evt-corr-1",
        "eventName": "AssumeRole",
        "actor": "alice",
        "target": "AdminRole",
        "severity": "critical",
        "riskScore": 90,
        "matched_static_relationship": "CAN_ASSUME",
        "reason": "Observed activity matches verified CAN_ASSUME edge"
    }]
    service = FindingService()
    findings = service.extract_findings_from_scan(inv, correlated_findings=raw_corr)
    cf = next(f for f in findings if f.eventId == "evt-corr-1")
    assert cf.source == "CORRELATION"
    assert cf.evidence["matched_static_relationship"] == "CAN_ASSUME"


def test_24_wrong_actor_target_does_not_correlate():
    """24. Correlated finding is NOT created when actor or target does not match static edge."""
    raw_corr = [{
        "eventId": "evt-nomatch",
        "eventName": "AssumeRole",
        "actor": "stranger",
        "target": "UnknownRole",
        "matched_static_relationship": "NONE"
    }]
    service = FindingService()
    findings = service.extract_findings_from_scan(AWSInventory(), correlated_findings=raw_corr)
    f = next(f for f in findings if f.eventId == "evt-nomatch")
    assert f.source == "CLOUDTRAIL"  # Not CORRELATION


def test_25_exact_attack_path_activity_links_correctly():
    """25. Attack path findings expose attackPathId, ordered transitions, and blast radius."""
    attack_paths = [{
        "id": "path-005",
        "name": "PassRole to Lambda Execution Role",
        "source": "JuniorDev",
        "target": "LambdaRole",
        "severity": "critical",
        "riskScore": 88,
        "is_privilege_escalation": True,
        "orderedRelationships": ["CAN_ASSUME", "EXECUTES_WITH", "ALLOWS"],
        "blastRadius": "3 resources in us-east-1"
    }]
    service = FindingService()
    findings = service.extract_findings_from_scan(AWSInventory(), attack_paths=attack_paths)
    path_find = next(f for f in findings if f.attackPathId == "path-005")
    assert path_find.type == "PASSROLE_ESCALATION"
    assert path_find.category == "PRIVILEGE_ESCALATION"
    assert path_find.source == "ATTACK_PATH"
    assert path_find.evidence["blast_radius"] == "3 resources in us-east-1"


# ==============================================================================
# 8. REPORTING & REAL-DATA-ONLY TESTS (Scenarios 26-30)
# ==============================================================================

def test_26_no_hardcoded_fallback_risk_values():
    """26. When no scan data is in cache, reports return explicit empty state, never 84%/85."""
    rep = _compute_reports_from_cache()
    assert rep["has_data"] is False
    assert rep["summary"]["score"] is None
    assert rep["summary"]["grade"] == "No scan data available"
    assert rep["summary"]["findings_count"] == 0


def test_27_dashboard_counts_match_finding_data():
    """27. Dashboard stats match live canonical findings."""
    inv = AWSInventory()
    inv.users = [{"name": "alice", "arn": "arn:aws:iam::123:user/alice", "mfaEnabled": False, "riskScore": 85}]
    finding_service.reconcile_scan_findings(inv, scan_timestamp="2026-09-23T01:00:00Z")
    all_f = finding_service.get_all_findings()
    open_f = [f for f in all_f if f.status == "OPEN"]
    crit_f = [f for f in open_f if f.severity == "critical"]
    assert len(open_f) == len(all_f)
    assert len(crit_f) >= 1


def test_28_report_summary_matches_finding_data():
    """28. Reports summary findings_count strictly reflects active canonical findings."""
    inv = AWSInventory()
    inv.users = [{"name": "alice", "arn": "arn:aws:iam::123:user/alice", "mfaEnabled": False, "riskScore": 85}]
    findings = finding_service.reconcile_scan_findings(inv, scan_timestamp="2026-09-23T01:00:00Z")
    cache.set("v1:users", inv.users)
    cache.set("v1:findings", [f.model_dump() for f in findings])

    rep = _compute_reports_from_cache()
    assert rep["has_data"] is True
    assert rep["summary"]["findings_count"] == len(findings)
    assert rep["summary"]["score"] is not None


def test_29_json_export_contains_canonical_findings():
    """29. Findings API endpoint GET /api/v1/findings returns full canonical schemas."""
    inv = AWSInventory()
    inv.users = [{"name": "alice", "arn": "arn:aws:iam::123:user/alice", "mfaEnabled": False, "riskScore": 85}]
    finding_service.reconcile_scan_findings(inv, scan_timestamp="2026-09-23T01:00:00Z")

    resp = client.get("/api/v1/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert len(data["data"]) >= 1
    first = data["data"][0]
    assert "remediation" in first
    assert "riskFactors" in first
    assert "status" in first


def test_30_filtering_endpoints_work():
    """30. GET /api/v1/findings filters correctly by severity and status."""
    inv = AWSInventory()
    inv.users = [
        {"name": "alice", "arn": "arn:aws:iam::123:user/alice", "mfaEnabled": False, "riskScore": 85},
        {"name": "bob", "arn": "arn:aws:iam::123:user/bob", "lastActive": "Never", "riskScore": 25}
    ]
    finding_service.reconcile_scan_findings(inv, scan_timestamp="2026-09-23T01:00:00Z")

    # Filter critical
    resp = client.get("/api/v1/findings?severity=critical")
    assert resp.status_code == 200
    items = resp.json()["data"]
    for it in items:
        assert it["severity"] == "critical"

    # Filter status OPEN
    resp_open = client.get("/api/v1/findings?status=OPEN")
    assert resp_open.status_code == 200
    assert len(resp_open.json()["data"]) >= 1
