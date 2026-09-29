"""
Phase 2 Health & Readiness Probes Test Suite.
Validates:
- /live probe succeeds immediately without calling AWS, Redis, or Neo4j.
- /ready probe accurately reports core dependency statuses.
- Container health does not fail because of AWS API connectivity.
- /health/aws reports STS AWS diagnostic only.
- /metrics exposes Prometheus metrics.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from app.main import app

client = TestClient(app)


class TestHealthProbes:
    def test_live_probe_independence(self):
        """Live probe must succeed even when all external dependencies are broken."""
        with patch("app.database.get_driver", side_effect=RuntimeError("Neo4j down")), \
             patch("app.cache.cache.redis_client", None), \
             patch("app.services.aws.session.get_aws_diagnostic_info", side_effect=RuntimeError("AWS down")):

            resp = client.get("/live")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "alive"
            assert "timestamp" in data

    def test_ready_probe_dependency_reporting(self):
        # 1. When dependencies are connected
        mock_driver = MagicMock()
        mock_driver.verify_connectivity.return_value = True

        mock_redis = MagicMock()
        with patch("app.routers.health.get_driver", return_value=mock_driver), \
             patch("app.routers.health.cache.redis_client", mock_redis), \
             patch("app.routers.health.check_db_connectivity", return_value=True):

            resp = client.get("/ready")
            assert resp.status_code == 200
            data = resp.json()["data"]
            assert data["ready"] is True
            assert data["backend"] == "ok"
            assert data["neo4j"] == "connected"
            assert data["redis"] == "connected"

        # 2. When a core dependency is down
        with patch("app.routers.health.get_driver", side_effect=Exception("DB down")), \
             patch("app.routers.health.cache.redis_client", None), \
             patch("app.routers.health.check_db_connectivity", return_value=False):

            resp_degraded = client.get("/ready")
            assert resp_degraded.status_code == 200
            data_degraded = resp_degraded.json()["data"]
            assert data_degraded["ready"] is False
            assert data_degraded["neo4j"] == "disconnected"

    def test_health_aws_diagnostic_endpoint(self):
        with patch("app.routers.health._get_aws_diag") as mock_diag:
            mock_diag.return_value = {
                "authenticated": True,
                "account_id": "999888777666",
                "arn": "arn:aws:iam::999888777666:role/test-role",
                "region": "us-east-1"
            }
            resp = client.get("/health/aws")
            assert resp.status_code == 200
            assert resp.json()["data"]["authenticated"] is True
            assert resp.json()["data"]["account_id"] == "999888777666"

    def test_metrics_endpoint(self):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        text = resp.text
        assert "cloudscope_http_requests_total" in text
        assert "cloudscope_scan_total" in text
