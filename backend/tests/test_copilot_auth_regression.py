"""
Regression and verification test suite for CloudScope Copilot Authentication and RBAC.

Validates:
- Stale / invalid tokens are rejected with 401 (never silently bypassed).
- Expired tokens produce 401.
- In explicit local development mode (DEV_AUTH_MODE=True), X-Dev-Role is honored:
  - Role ANALYST or higher is allowed on Copilot endpoints.
  - Role VIEWER is rejected with 403 Forbidden.
- Production environment fails closed:
  - Unauthenticated requests produce 401.
  - X-Dev-Role headers NEVER bypass production authentication.
  - No unauthenticated administrator fallback exists in production.
- AI provider errors are properly distinguished from user authentication errors.
- Request IDs are retained in responses.
- Secrets and tokens are never leaked in error messages.
"""

import time
import pytest
import jwt
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.security.models import Role
from app.services.ai.base import (
    CopilotAIResponse,
    AIUnavailableError,
    AIRateLimitError,
)

client = TestClient(app)
TEST_SECRET = "super_secret_test_key_which_is_at_least_32_chars"


def make_jwt(
    sub: str = "test-user-1",
    roles: list = None,
    issuer: str = "https://test.com",
    audience: str = "test-audience",
    exp_offset: int = 3600,
    secret: str = TEST_SECRET,
) -> str:
    payload = {
        "sub": sub,
        "email": f"{sub}@cloudscope.dev",
        "name": "Test User",
        "roles": roles or ["ANALYST"],
        "iss": issuer,
        "aud": audience,
        "iat": int(time.time()),
        "exp": int(time.time()) + exp_offset,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


@pytest.fixture(autouse=True)
def reset_settings(monkeypatch):
    monkeypatch.setattr(settings, "JWT_SECRET", TEST_SECRET)
    monkeypatch.setattr(settings, "JWT_ALGORITHM", "HS256")
    monkeypatch.setattr(settings, "OIDC_ISSUER_URL", "https://test.com")
    monkeypatch.setattr(settings, "OIDC_AUDIENCE", "test-audience")


class TestCopilotAuthenticationAndRBAC:

    def test_copilot_authorized_request_reaches_ai_service(self, monkeypatch):
        """A valid JWT with ANALYST role reaches the AI service and returns 200."""
        monkeypatch.setattr(settings, "ENVIRONMENT", "development")
        token = make_jwt(sub="analyst-1", roles=["ANALYST"])
        headers = {"Authorization": f"Bearer {token}"}

        mock_ai_resp = CopilotAIResponse(
            summary="Attack Path Analysis",
            analysis="Verified IAM privilege escalation path.",
            severity="HIGH",
            risk_score=75,
            affected_entities=["arn:aws:iam::123:role/AdminRole"],
            evidence=["AssumeRole allowed unconditionally"],
            recommendations=["Add MFA condition to trust policy"],
            suggested_questions=[]
        )

        with patch("app.routers.copilot.context_builder.has_completed_scan", return_value=True), \
             patch("app.routers.copilot.get_ai_provider") as mock_provider_getter:
            mock_provider = MagicMock()
            mock_provider.generate_security_response = AsyncMock(return_value=mock_ai_resp)
            mock_provider_getter.return_value = mock_provider

            resp = client.post("/api/v1/copilot", json={"prompt": "Analyze blast radius"}, headers=headers)
            assert resp.status_code == 200
            data = resp.json()["data"]
            assert data["summary"] == "Attack Path Analysis"
            assert "X-Request-ID" in resp.headers

    def test_copilot_dev_mode_role_analyst_authorized(self, monkeypatch):
        """In explicit dev mode, X-Dev-Role: ANALYST is honored and authorized."""
        monkeypatch.setattr(settings, "ENVIRONMENT", "development")
        monkeypatch.setattr(settings, "DEV_AUTH_MODE", True)
        headers = {"X-Dev-Role": "ANALYST", "X-Dev-Subject": "local-dev"}

        mock_ai_resp = CopilotAIResponse(
            summary="Dev Copilot Analysis",
            analysis="Analysis performed under local dev session.",
            severity="MEDIUM",
            risk_score=50,
            affected_entities=[],
            evidence=[],
            recommendations=["Review IAM permissions"]
        )

        with patch("app.routers.copilot.context_builder.has_completed_scan", return_value=True), \
             patch("app.routers.copilot.get_ai_provider") as mock_provider_getter:
            mock_provider = MagicMock()
            mock_provider.generate_security_response = AsyncMock(return_value=mock_ai_resp)
            mock_provider_getter.return_value = mock_provider

            resp = client.post("/api/v1/copilot", json={"prompt": "Explain IAM risk"}, headers=headers)
            assert resp.status_code == 200
            assert resp.json()["success"] is True

    def test_copilot_viewer_role_rejected_with_403(self, monkeypatch):
        """Users with VIEWER role are rejected with 403 Forbidden on all copilot endpoints."""
        monkeypatch.setattr(settings, "ENVIRONMENT", "development")
        token = make_jwt(sub="viewer-user", roles=["VIEWER"])
        headers = {"Authorization": f"Bearer {token}"}

        resp = client.post("/api/v1/copilot", json={"prompt": "Explain finding"}, headers=headers)
        assert resp.status_code == 403
        assert "insufficient privileges" in resp.json()["detail"].lower()

        resp_finding = client.post(
            "/api/v1/copilot/explain-finding",
            json={"finding_id": "f-123"},
            headers=headers
        )
        assert resp_finding.status_code == 403

        resp_path = client.post(
            "/api/v1/copilot/explain-attack-path",
            json={"attack_path_id": "p-123"},
            headers=headers
        )
        assert resp_path.status_code == 403

    def test_copilot_dev_mode_viewer_rejected_with_403(self, monkeypatch):
        """In dev mode, if X-Dev-Role is VIEWER, copilot returns 403 Forbidden."""
        monkeypatch.setattr(settings, "ENVIRONMENT", "development")
        monkeypatch.setattr(settings, "DEV_AUTH_MODE", True)
        headers = {"X-Dev-Role": "VIEWER"}

        resp = client.post("/api/v1/copilot", json={"prompt": "Explain path"}, headers=headers)
        assert resp.status_code == 403
        assert "insufficient privileges" in resp.json()["detail"].lower()

    def test_stale_invalid_token_rejected_with_401(self, monkeypatch):
        """Stale or forged token must produce 401, not silent bypass."""
        monkeypatch.setattr(settings, "ENVIRONMENT", "development")
        bad_token = make_jwt(secret="wrong-secret-signature-tampered!")
        headers = {"Authorization": f"Bearer {bad_token}"}

        resp = client.post("/api/v1/copilot", json={"prompt": "Explain"}, headers=headers)
        assert resp.status_code == 401
        assert "invalid authentication token" in resp.json()["detail"].lower()

    def test_expired_token_rejected_with_401(self, monkeypatch):
        """Expired JWT produces 401."""
        monkeypatch.setattr(settings, "ENVIRONMENT", "development")
        expired_token = make_jwt(exp_offset=-100)
        headers = {"Authorization": f"Bearer {expired_token}"}

        resp = client.post("/api/v1/copilot", json={"prompt": "Explain"}, headers=headers)
        assert resp.status_code == 401
        assert "invalid authentication token" in resp.json()["detail"].lower()

    def test_production_fails_closed_without_token(self, monkeypatch):
        """In production, missing credentials always produce 401."""
        monkeypatch.setattr(settings, "ENVIRONMENT", "production")
        monkeypatch.setattr(settings, "DEV_AUTH_MODE", False)

        resp = client.post("/api/v1/copilot", json={"prompt": "Explain"})
        assert resp.status_code == 401
        assert "authentication required" in resp.json()["detail"].lower()

    def test_production_dev_role_headers_never_bypass_authentication(self, monkeypatch):
        """In production, X-Dev-Role headers are ignored and request fails closed with 401."""
        monkeypatch.setattr(settings, "ENVIRONMENT", "production")
        monkeypatch.setattr(settings, "DEV_AUTH_MODE", False)
        headers = {"X-Dev-Role": "ADMINISTRATOR", "X-Dev-Subject": "attacker"}

        resp = client.post("/api/v1/copilot", json={"prompt": "Explain"}, headers=headers)
        assert resp.status_code == 401
        assert "authentication required" in resp.json()["detail"].lower()

    def test_production_unauthenticated_request_no_admin_fallback(self, monkeypatch):
        """In production, no unauthenticated administrator fallback is allowed."""
        monkeypatch.setattr(settings, "ENVIRONMENT", "production")
        monkeypatch.setattr(settings, "DEV_AUTH_MODE", False)
        monkeypatch.setattr(settings, "AUTH_REQUIRED", False)

        resp = client.get("/api/v1/policies")
        assert resp.status_code == 401

    def test_ai_provider_error_distinguished_from_auth_error(self, monkeypatch):
        """AI provider error (e.g. 503) is distinguished from a 401 authentication error."""
        monkeypatch.setattr(settings, "ENVIRONMENT", "development")
        monkeypatch.setattr(settings, "DEV_AUTH_MODE", True)
        headers = {"X-Dev-Role": "ANALYST"}

        with patch("app.routers.copilot.context_builder.has_completed_scan", return_value=True), \
             patch("app.routers.copilot.get_ai_provider") as mock_provider_getter:
            mock_provider = MagicMock()
            mock_provider.generate_security_response = AsyncMock(
                side_effect=AIUnavailableError("Gemini service unavailable", user_friendly_message="AI Service temporarily unavailable.")
            )
            mock_provider_getter.return_value = mock_provider

            resp = client.post("/api/v1/copilot", json={"prompt": "Explain path"}, headers=headers)
            # Must return 503 Service Unavailable, NOT 401
            assert resp.status_code == 503
            assert resp.status_code != 401
            assert "unavailable" in resp.json()["detail"].lower()

    def test_request_id_retained_in_responses(self, monkeypatch):
        """Request IDs are preserved in diagnostic headers and error body."""
        monkeypatch.setattr(settings, "ENVIRONMENT", "production")
        custom_req_id = "req-diag-trace-999"
        headers = {"X-Request-ID": custom_req_id}

        resp = client.post("/api/v1/copilot", json={"prompt": "Explain"}, headers=headers)
        assert resp.status_code == 401
        assert resp.headers.get("x-request-id") == custom_req_id
        assert resp.json().get("request_id") == custom_req_id

    def test_secrets_and_tokens_not_exposed_in_error_responses(self, monkeypatch):
        """Neither JWT secrets nor user tokens are leaked in user-facing error bodies."""
        monkeypatch.setattr(settings, "ENVIRONMENT", "development")
        bad_token = make_jwt(secret="wrong-secret-xyz-not-for-leakage")
        headers = {"Authorization": f"Bearer {bad_token}"}

        resp = client.post("/api/v1/copilot", json={"prompt": "Explain"}, headers=headers)
        assert resp.status_code == 401
        body_text = resp.text
        assert TEST_SECRET not in body_text
        assert "wrong-secret-xyz" not in body_text
        assert bad_token not in body_text
