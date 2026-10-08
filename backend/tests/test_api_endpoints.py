import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from app.main import app
from app.cache import cache

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["success"] is True
    assert res_json["data"]["status"] == "healthy"


def test_ready_endpoint():
    response = client.get("/ready")
    assert response.status_code == 200
    res_json = response.json()
    assert "data" in res_json
    assert res_json["data"]["backend"] == "ok"
    assert "ready" in res_json["data"]


def test_health_aws_endpoint():
    with patch("app.main.get_aws_diagnostic_info") as mock_diag:
        mock_diag.return_value = {
            "authenticated": True,
            "account_id": "123456789012",
            "arn": "arn:aws:iam::123456789012:user/scanner",
            "user_id": "AIDA123",
            "profile": "identityscope-scanner",
            "region": "ap-south-1",
            "error": None
        }
        response = client.get("/health/aws")
        assert response.status_code == 200
        res_json = response.json()
        assert res_json["success"] is True
        assert res_json["data"]["authenticated"] is True
        assert res_json["data"]["account_id"] == "123456789012"


def test_dashboard_endpoint():
    cache.set("v1:dashboard", {
        "securityScore": "85 / 100",
        "stats": {"users": 2, "roles": 3, "policies": 5, "risks": 1, "paths": 1, "resources": 10},
        "riskDistribution": [{"name": "Critical", "value": 1, "color": "#EF4444"}],
        "recentAlerts": [],
        "criticalPaths": [],
        "recommendations": [],
        "topRiskyIdentities": [{"name": "alice", "type": "User", "riskScore": 75}],
        "resourceBreakdown": [{"type": "S3", "count": 2}],
        "scannedRegions": ["ap-south-1"],
        "correlatedRisks": []
    })
    response = client.get("/api/v1/dashboard")
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["success"] is True
    assert res_json["data"]["securityScore"] == "85 / 100"


def test_users_endpoint():
    cache.set("v1:users", [{
        "id": "u1",
        "name": "alice",
        "arn": "arn:aws:iam::123:user/alice",
        "status": "active",
        "policies": ["DevPolicy"],
        "groups": ["Devs"],
        "riskScore": 25,
        "mfaEnabled": True,
        "lastActive": "2026-08-29T12:00:00Z"
    }])
    response = client.get("/api/v1/users")
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["success"] is True
    assert len(res_json["data"]) == 1


def test_roles_endpoint():
    cache.set("v1:roles", [{
        "name": "AdminRole",
        "arn": "arn:aws:iam::123:role/AdminRole",
        "trustPolicy": "{}",
        "description": "Administrator Role",
        "activeSessions": 1,
        "riskScore": 85
    }])
    response = client.get("/api/v1/roles")
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["success"] is True
    assert len(res_json["data"]) == 1


def test_resources_endpoint():
    cache.set("v1:resources", [{
        "name": "my-bucket",
        "type": "S3",
        "region": "ap-south-1",
        "status": "configured",
        "owner": "123456789012",
        "arn": "arn:aws:s3:::my-bucket",
        "riskScore": 20
    }])
    response = client.get("/api/v1/resources")
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["success"] is True
    assert len(res_json["data"]) == 1


def test_graph_endpoint():
    cache.set("v1:graph", [{"data": {"id": "aws:user:alice", "label": "alice", "type": "User"}}])
    response = client.get("/api/v1/graph")
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["success"] is True
    assert len(res_json["data"]) == 1


def test_graph_effective_access_endpoint():
    cache.set("v1:effective_access", [{
        "identity_id": "aws:user:alice",
        "identity_name": "alice",
        "identity_type": "User",
        "target_resource_id": "my-bucket",
        "target_resource_name": "my-bucket",
        "target_resource_type": "S3",
        "access_path": ["alice", "AdminPolicy", "my-bucket"],
        "through_relationship": ["HAS_POLICY", "ALLOWS"],
        "policy_names": ["AdminPolicy"],
        "policy_arns": []
    }])
    response = client.get("/api/v1/graph/effective-access")
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["success"] is True
    assert len(res_json["data"]) == 1
    assert res_json["data"][0]["identity_name"] == "alice"


def test_attack_paths_endpoint():
    cache.set("v1:attack-paths", [{
        "id": "path-1",
        "name": "User to Admin Role",
        "nodes": [{"id": "u1", "name": "alice", "type": "User"}],
        "severity": "critical",
        "riskScore": 90,
        "blastRadius": "High",
        "mitreTechniques": ["T1078"],
        "recommendation": "Enforce MFA",
        "description": "Direct assume role path"
    }])
    response = client.get("/api/v1/attack-paths")
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["success"] is True
    assert len(res_json["data"]) == 1


def test_risk_assessment_endpoint():
    cache.set("v1:risks", [{
        "id": "risk-1",
        "identity": "alice",
        "identityType": "User",
        "issue": "Missing MFA",
        "severity": "high",
        "riskScore": 75,
        "recommendation": "Enable MFA immediately"
    }])
    response = client.get("/api/v1/risk-assessment")
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["success"] is True
    assert len(res_json["data"]) == 1


def test_alerts_and_correlated_risks_endpoints():
    cache.set("v1:alerts", [{
        "id": "alert-1",
        "timestamp": "2026-08-29T12:00:00Z",
        "severity": "critical",
        "resource": "AdminRole",
        "description": "AssumeRole executed by alice",
        "status": "open",
        "details": "{}"
    }])
    cache.set("v1:correlated_risks", [{
        "id": "corr-1",
        "type": "OBSERVED_ATTACK_ACTIVITY",
        "title": "Alice assumed AdminRole",
        "actor": "alice",
        "target": "AdminRole",
        "event_name": "sts:AssumeRole",
        "event_time": "2026-08-29T12:00:00Z",
        "source_ip": "203.0.113.1",
        "severity": "critical",
        "risk_score": 90,
        "matched_static_relationship": "CAN_ASSUME",
        "reason": "Observed activity matches privileged attack path",
        "recommendation": "Enforce MFA in trust policy",
        "is_correlated": True
    }])

    res_alerts = client.get("/api/v1/alerts")
    assert res_alerts.status_code == 200
    assert len(res_alerts.json()["data"]) == 1

    res_corr = client.get("/api/v1/correlated-risks")
    assert res_corr.status_code == 200
    assert len(res_corr.json()["data"]) == 1
    assert res_corr.json()["data"][0]["type"] == "OBSERVED_ATTACK_ACTIVITY"


def test_scan_status_endpoint():
    response = client.get("/api/v1/scan/status")
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["success"] is True
    assert "is_scanning" in res_json["data"]


def test_finding_evidence_endpoint():
    from app.services.findings.finding_service import finding_service
    from app.schemas import SecurityFinding

    fid = "find-test-evidence-001"
    finding_service._memory_store[fid] = SecurityFinding(
        id=fid,
        type="NO_MFA",
        category="CREDENTIAL",
        title="MFA Missing on Root",
        description="Root lacks MFA",
        severity="critical",
        riskScore=90,
        principal="root",
        source="STATIC_IAM",
        evidence={"mfa_enabled": False}
    )
    # Findings APIs intentionally read only published snapshot data; seed that
    # authoritative view instead of relying on the lifecycle service's staging store.
    from app.services.scanner.snapshot_store import snapshot_store
    snapshot_store.publish(
        snapshot_id="api-test-finding-snapshot",
        status="SUCCESS",
        findings=[finding_service._memory_store[fid].model_dump(mode="json")],
    )

    response = client.get(f"/api/v1/findings/{fid}/evidence")
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["success"] is True
    assert res_json["data"]["finding_id"] == fid
    assert res_json["data"]["risk_model_version"] == "phase4-v2"
    assert res_json["data"]["evidence"]["mfa_enabled"] is False


def test_attack_path_evidence_and_filtering_endpoints():
    cache.set("v1:attack-paths", [
        {
            "id": "path-001",
            "canonical_id": "ap-crit-001",
            "name": "Path 1",
            "source": "alice",
            "target": "s3-vault",
            "target_type": "S3",
            "severity": "critical",
            "riskScore": 95,
            "blastRadius": "High",
            "mitreTechniques": ["T1078"],
            "recommendation": "Restrict policy",
            "description": "Critical path to S3",
            "ordered_relationships": ["HAS_POLICY", "ALLOWS"],
            "nodes": [{"id": "alice", "name": "alice", "type": "User"}],
            "evidence": [{"from_name": "alice", "to_name": "s3-vault", "why": "Policy allows GetObject"}]
        },
        {
            "id": "path-002",
            "canonical_id": "ap-med-002",
            "name": "Path 2",
            "source": "bob",
            "target": "ec2-worker",
            "target_type": "EC2",
            "severity": "medium",
            "riskScore": 50,
            "blastRadius": "Low",
            "mitreTechniques": ["T1078"],
            "recommendation": "Review permissions",
            "description": "Medium path",
            "ordered_relationships": ["HAS_POLICY"],
            "nodes": [{"id": "bob", "name": "bob", "type": "User"}],
            "evidence": []
        }
    ])

    # 1. Evidence endpoint
    ev_resp = client.get("/api/v1/attack-paths/path-001/evidence")
    assert ev_resp.status_code == 200
    ev_json = ev_resp.json()
    assert ev_json["success"] is True
    assert ev_json["data"]["canonical_id"] == "ap-crit-001"
    assert ev_json["data"]["risk_model_version"] == "phase4-v2"
    assert len(ev_json["data"]["transition_evidence"]) == 1

    # 2. Filtering by severity
    filt_resp = client.get("/api/v1/attack-paths?severity=critical")
    assert filt_resp.status_code == 200
    assert len(filt_resp.json()["data"]) == 1
    assert filt_resp.json()["data"][0]["id"] == "path-001"

    # 3. Pagination
    page_resp = client.get("/api/v1/attack-paths?limit=1&offset=1")
    assert page_resp.status_code == 200
    assert len(page_resp.json()["data"]) == 1
    assert page_resp.json()["data"][0]["id"] == "path-002"


def test_risk_explanation_endpoint():
    cache.set("v1:users", [{
        "name": "superadmin",
        "arn": "arn:aws:iam::123:user/superadmin",
        "riskScore": 85,
        "riskAssessment": {
            "score": 85,
            "severity": "critical",
            "factors": [{"code": "ADMIN_POLICY", "points": 50, "reason": "Full admin access"}]
        }
    }])

    response = client.get("/api/v1/risk-explanation/superadmin")
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["success"] is True
    assert res_json["data"]["risk_score"] == 85
    assert res_json["data"]["risk_model_version"] == "phase4-v2"
    assert len(res_json["data"]["factors"]) == 1
