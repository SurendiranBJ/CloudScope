"""
Phase 2 Authentication and RBAC Test Suite.
Validates:
- Valid JWT decode and principal creation
- Expired JWT rejection (HTTP 401)
- Wrong issuer rejection (HTTP 401)
- Wrong audience rejection (HTTP 401)
- Invalid signature rejection (HTTP 401)
- Missing token handling (HTTP 401 when AUTH_REQUIRED=True)
- Role hierarchy enforcement:
  - Viewer attempting admin operation (HTTP 403)
  - Analyst attempting admin operation (HTTP 403)
  - Security officer lifecycle action (HTTP 200)
  - Admin scan trigger (HTTP 200)
"""

import time
import pytest
import jwt
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from app.security.models import Role, AuthenticatedUser
from app.security.auth import decode_and_verify_token

client = TestClient(app)
import os
TEST_SECRET = os.getenv("JWT_SECRET", "phase2-test-secret-key-32-chars-long!")


@pytest.fixture(autouse=True)
def configure_auth_env(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.cloudscope.test")
    monkeypatch.setenv("OIDC_AUDIENCE", "cloudscope-api")
    monkeypatch.setattr("app.security.auth.JWT_SECRET", TEST_SECRET)
    monkeypatch.setattr("app.security.auth.JWT_ALGORITHM", "HS256")
    monkeypatch.setattr("app.security.auth.OIDC_ISSUER_URL", "https://auth.cloudscope.test")
    monkeypatch.setattr("app.security.auth.OIDC_AUDIENCE", "cloudscope-api")


def create_token(sub="user-123", roles=None, issuer="https://auth.cloudscope.test", audience="cloudscope-api", exp_offset=3600, secret=None):
    active_secret = secret or os.getenv("JWT_SECRET") or TEST_SECRET
    payload = {
        "sub": sub,
        "email": f"{sub}@example.com",
        "name": "Test User",
        "roles": roles or ["VIEWER"],
        "iss": issuer,
        "aud": audience,
        "iat": int(time.time()),
        "exp": int(time.time()) + exp_offset,
    }
    return jwt.encode(payload, active_secret, algorithm="HS256")


class TestAuthenticationJWT:
    def test_valid_jwt(self):
        token = create_token(sub="analyst-1", roles=["ANALYST"])
        claims = decode_and_verify_token(token)
        assert claims["sub"] == "analyst-1"
        assert claims["roles"] == ["ANALYST"]

    def test_expired_jwt(self):
        token = create_token(exp_offset=-10)
        with pytest.raises(Exception) as exc_info:
            decode_and_verify_token(token)
        assert "expired" in str(exc_info.value).lower()

    def test_wrong_issuer(self):
        token = create_token(issuer="https://malicious-issuer.com")
        with pytest.raises(Exception) as exc_info:
            decode_and_verify_token(token)
        assert "issuer" in str(exc_info.value).lower()

    def test_wrong_audience(self):
        token = create_token(audience="wrong-client-app")
        with pytest.raises(Exception) as exc_info:
            decode_and_verify_token(token)
        assert "audience" in str(exc_info.value).lower()

    def test_invalid_signature(self):
        token = create_token(secret="completely-different-wrong-secret")
        with pytest.raises(Exception) as exc_info:
            decode_and_verify_token(token)
        assert "signature" in str(exc_info.value).lower() or "decode" in str(exc_info.value).lower()

    def test_missing_token_when_auth_required(self, monkeypatch):
        monkeypatch.setattr("app.security.dependencies.AUTH_REQUIRED", True)
        monkeypatch.setattr("app.security.dependencies.DEV_AUTH_MODE", False)

        resp = client.post("/api/v1/scan")
        assert resp.status_code == 401
        assert "authentication required" in resp.json()["detail"].lower() or "bearer" in resp.headers.get("www-authenticate", "").lower()


class TestRBACAuthorization:
    def test_viewer_blocked_on_admin_operation(self):
        token = create_token(sub="viewer-bob", roles=["VIEWER"])
        headers = {"Authorization": f"Bearer {token}"}

        # Viewer attempting admin scan trigger
        resp = client.post("/api/v1/scan", headers=headers)
        assert resp.status_code == 403
        assert "insufficient privileges" in resp.json()["detail"].lower()

        # Viewer attempting admin settings change
        resp_settings = client.post("/api/v1/settings/scan-interval", json={"minutes": 30}, headers=headers)
        assert resp_settings.status_code == 403

    def test_analyst_blocked_on_admin_and_finding_mutation(self):
        token = create_token(sub="analyst-carol", roles=["ANALYST"])
        headers = {"Authorization": f"Bearer {token}"}

        # Analyst attempting admin scan trigger
        resp = client.post("/api/v1/scan", headers=headers)
        assert resp.status_code == 403

        # Analyst attempting security officer lifecycle mutation
        resp_finding = client.post("/api/v1/findings/find-test-123/acknowledge", headers=headers)
        assert resp_finding.status_code == 403

    def test_security_officer_allowed_on_finding_mutation(self):
        token = create_token(sub="officer-dave", roles=["SECURITY_OFFICER"])
        headers = {"Authorization": f"Bearer {token}"}

        with patch("app.routers.findings.finding_service.acknowledge_finding") as mock_ack:
            from app.schemas import SecurityFinding
            mock_ack.return_value = SecurityFinding(
                id="find-ack-1",
                type="NO_MFA",
                category="CREDENTIAL",
                title="No MFA",
                description="Test",
                severity="high",
                riskScore=75,
                status="ACKNOWLEDGED",
                source="STATIC_IAM"
            )
            resp = client.post("/api/v1/findings/find-ack-1/acknowledge", headers=headers)
            assert resp.status_code == 200
            assert resp.json()["success"] is True

    def test_admin_allowed_on_scan_trigger(self):
        token = create_token(sub="admin-eve", roles=["ADMINISTRATOR"])
        headers = {"Authorization": f"Bearer {token}"}

        with patch("app.routers.scan.scan_coordinator.request_scan") as mock_scan:
            mock_scan.return_value = {
                "status": "STARTED",
                "scan_id": "test-admin-scan-123",
                "message": "Scan started successfully"
            }
            resp = client.post("/api/v1/scan", headers=headers)
            assert resp.status_code == 200
            assert resp.json()["data"]["status"] == "STARTED"
