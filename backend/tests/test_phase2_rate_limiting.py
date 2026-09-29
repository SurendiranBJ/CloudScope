"""
Phase 2 API Rate Limiting Test Suite.
Validates:
- Requests within limit threshold succeed (HTTP 200).
- Requests exceeding limit threshold return HTTP 429 Too Many Requests.
- Retry-After response header is provided with valid positive integer.
- Rate limits are segregated by user principal (User A does not exhaust User B's quota).
- Returns structured error code RATE_LIMIT_EXCEEDED.
"""

import time
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from app.security.rate_limiter import RateLimiter, rate_limiter
from tests.test_phase2_authentication_rbac import create_token

client = TestClient(app)


class TestRateLimiting:
    def test_sliding_window_threshold_and_retry_after(self):
        limiter = RateLimiter()
        # 3 requests per 10 seconds limit
        test_key = f"unit-test-{time.time()}"
        assert limiter.is_rate_limited("test", test_key, max_requests=3, window_seconds=10) == (False, 0)
        assert limiter.is_rate_limited("test", test_key, max_requests=3, window_seconds=10) == (False, 0)
        assert limiter.is_rate_limited("test", test_key, max_requests=3, window_seconds=10) == (False, 0)

        # 4th request must be rejected
        limited, retry_after = limiter.is_rate_limited("test", test_key, max_requests=3, window_seconds=10)
        assert limited is True
        assert retry_after > 0
        assert retry_after <= 10

    def test_independent_user_limits(self):
        limiter = RateLimiter()
        user_1 = f"user-1-{time.time()}"
        user_2 = f"user-2-{time.time()}"

        # Exhaust user 1 limit
        limiter.is_rate_limited("cat", user_1, max_requests=1, window_seconds=60)
        limited_1, _ = limiter.is_rate_limited("cat", user_1, max_requests=1, window_seconds=60)
        assert limited_1 is True

        # User 2 limit should remain untouched
        limited_2, _ = limiter.is_rate_limited("cat", user_2, max_requests=1, window_seconds=60)
        assert limited_2 is False

    def test_endpoint_rate_limit_http_429(self, monkeypatch):
        token = create_token(sub=f"ratelimit-admin-{time.time()}", roles=["ADMINISTRATOR"])
        headers = {"Authorization": f"Bearer {token}"}

        # Mock rate limit max to 2 requests
        monkeypatch.setitem(
            from_dict := __import__("app.security.rate_limiter", fromlist=["RATE_LIMIT_CONFIGS"]).RATE_LIMIT_CONFIGS,
            "scan",
            (2, 60)
        )

        with patch("app.routers.scan.scan_coordinator.request_scan", return_value={"status": "STARTED", "scan_id": "s1"}):
            # 1st request
            r1 = client.post("/api/v1/scan", headers=headers)
            assert r1.status_code == 200

            # 2nd request
            r2 = client.post("/api/v1/scan", headers=headers)
            assert r2.status_code == 200

            # 3rd request -> HTTP 429
            r3 = client.post("/api/v1/scan", headers=headers)
            assert r3.status_code == 429
            assert "Retry-After" in r3.headers
            assert r3.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    def test_redis_failure_in_production_fails_closed(self, monkeypatch):
        """In production, Redis failure MUST fail closed without in-memory bypass."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setattr("app.cache.cache.redis_client", None)

        limiter = RateLimiter()
        limited, retry_after = limiter.is_rate_limited("scan", "prod-user", max_requests=10, window_seconds=60)
        assert limited is True
        assert retry_after == 60

