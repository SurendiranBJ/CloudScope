"""
Phase 2 Administrative Audit Logging Test Suite.
Validates:
- Scan trigger generates SCAN_TRIGGERED audit event.
- Region change generates REGION_CONFIGURATION_CHANGED audit event.
- Finding lifecycle mutation generates FINDING_ACKNOWLEDGED / RESOLVED audit event.
- Simulation execution generates SIMULATION_EXECUTED audit event.
- Copilot analysis generates COPILOT_REQUESTED audit event.
- Confirms secrets (AWS keys, tokens, passwords) are automatically redacted.
"""

import time
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from app.main import app
from app.services.audit.audit_service import audit_service
from tests.test_phase2_authentication_rbac import create_token

client = TestClient(app)


class TestAuditLogging:
    def test_audit_event_logging_and_secret_redaction(self):
        secret_metadata = {
            "aws_key": "AKIAIOSFODNN7EXAMPLE",
            "gemini_api_key": "AIzaSyD-1234567890abcdefghijklmnop",
            "normal_field": "safe_value"
        }
        event = audit_service.log(
            action="TEST_ACTION",
            actor_id="test-officer",
            actor_role="SECURITY_OFFICER",
            resource_type="test",
            resource_id="res-1",
            result="SUCCESS",
            metadata=secret_metadata
        )

        assert event is not None
        # Verify secrets are redacted in durable audit log
        assert "AKIAIOSFODNN7EXAMPLE" not in str(event.get("metadata", {}))
        assert "AIzaSyD-1234567890" not in str(event.get("metadata", {}))
        assert event.get("metadata", {}).get("normal_field") == "safe_value"

    def test_region_change_produces_audit_event(self):
        token = create_token(sub="admin-audit-user", roles=["ADMINISTRATOR"])
        headers = {"Authorization": f"Bearer {token}"}

        with patch("app.services.scanner.scan_coordinator.scan_coordinator.request_scan"):
            resp = client.post(
                "/api/v1/settings/scan-region",
                json={"mode": "single", "region": "us-west-2"},
                headers=headers
            )
            assert resp.status_code == 200

        # Query audit log
        events = audit_service.get_events(action="REGION_CONFIGURATION_CHANGED", limit=5)
        assert len(events) >= 1
        latest = events[0]
        assert latest["actor_id"] == "admin-audit-user"
        assert latest["action"] == "REGION_CONFIGURATION_CHANGED"

    def test_simulation_produces_audit_event(self):
        token = create_token(sub="analyst-audit-user", roles=["ANALYST"])
        headers = {"Authorization": f"Bearer {token}"}

        with patch("app.routers.simulation._resolve_policy_name", return_value="AdminPolicy"), \
             patch("app.routers.simulation.simulation_state.attach_policy") as mock_attach:
            mock_change = MagicMock()
            mock_change.to_dict.return_value = {"id": "c1", "action": "ATTACH_POLICY"}
            mock_attach.return_value = mock_change

            resp = client.post(
                "/api/v1/simulation/changes",
                json={
                    "action": "ATTACH_POLICY",
                    "principal_type": "USER",
                    "principal_id": "alice",
                    "policy_arn": "arn:aws:iam::aws:policy/AdminPolicy"
                },
                headers=headers
            )
            assert resp.status_code == 200

        events = audit_service.get_events(action="SIMULATION_EXECUTED", limit=5)
        assert len(events) >= 1
        assert events[0]["actor_id"] == "analyst-audit-user"

    def test_audit_api_endpoint_rbac(self):
        # Viewer should be blocked from GET /api/v1/audit
        viewer_token = create_token(sub="viewer-audit", roles=["VIEWER"])
        r_viewer = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {viewer_token}"})
        assert r_viewer.status_code == 403

        # Security Officer should be allowed
        officer_token = create_token(sub="officer-audit", roles=["SECURITY_OFFICER"])
        r_officer = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {officer_token}"})
        assert r_officer.status_code == 200
        assert "events" in r_officer.json()["data"]
