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


def test_attack_paths_endpoint():
    cache.set("v1:attack-paths", [{
        "id": "path-1",
        "name": "User to Admin Role",
        "nodes": [{"id": "u1", "name": "alice", "type": "User"}],
        "severity": "critical",
        "likelihood": 90,
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
