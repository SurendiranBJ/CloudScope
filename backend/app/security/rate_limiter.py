"""
API Rate Limiter backed by Redis sliding window counter, with in-memory fallback.
Supports per-principal rate limiting (by authenticated user subject, or IP fallback).
Returns HTTP 429 with Retry-After header when limit exceeded.
"""

import time
import os
import logging
import threading
from typing import Optional, Dict, List
from fastapi import Request, HTTPException, status, Depends
import redis

from app.security.models import AuthenticatedUser
from app.cache import cache

logger = logging.getLogger(__name__)

# Configurable rate limits: (limit, window_seconds)
RATE_LIMIT_CONFIGS = {
    "scan": (int(os.getenv("RATE_LIMIT_SCAN_MAX", "5")), int(os.getenv("RATE_LIMIT_SCAN_WINDOW", "600"))),  # 5 per 10m
    "copilot": (int(os.getenv("RATE_LIMIT_COPILOT_MAX", "30")), int(os.getenv("RATE_LIMIT_COPILOT_WINDOW", "60"))),  # 30 per 1m
    "simulation": (int(os.getenv("RATE_LIMIT_SIMULATION_MAX", "30")), int(os.getenv("RATE_LIMIT_SIMULATION_WINDOW", "60"))),  # 30 per 1m
    "finding": (int(os.getenv("RATE_LIMIT_FINDING_MAX", "60")), int(os.getenv("RATE_LIMIT_FINDING_WINDOW", "60"))),  # 60 per 1m
    "audit": (int(os.getenv("RATE_LIMIT_AUDIT_MAX", "60")), int(os.getenv("RATE_LIMIT_AUDIT_WINDOW", "60"))),  # 60 per 1m
    "export": (int(os.getenv("RATE_LIMIT_EXPORT_MAX", "20")), int(os.getenv("RATE_LIMIT_EXPORT_WINDOW", "60"))),  # 20 per 1m
    "general": (int(os.getenv("RATE_LIMIT_GENERAL_MAX", "300")), int(os.getenv("RATE_LIMIT_GENERAL_WINDOW", "60"))),  # 300 per 1m
}


class RateLimiter:
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self._redis = redis_client
        self._local_lock = threading.Lock()
        self._local_windows: Dict[str, List[float]] = {}

    @property
    def redis(self) -> Optional[redis.Redis]:
        if self._redis is not None:
            return self._redis
        return cache.redis_client

    def is_rate_limited(self, key_prefix: str, identifier: str, max_requests: int, window_seconds: int) -> tuple[bool, int]:
        """
        Check if an identifier has exceeded its rate limit using a sliding window.
        Returns: (is_limited: bool, retry_after: int)
        """
        now = time.time()
        window_start = now - window_seconds
        limiter_key = f"{key_prefix}:{identifier}"

        prod = os.getenv("ENVIRONMENT", "development").lower() == "production"
        r = self.redis
        if r is not None:
            redis_key = f"rate_limit:{limiter_key}"
            try:
                pipe = r.pipeline()
                # Remove timestamps outside sliding window
                pipe.zremrangebyscore(redis_key, 0, window_start)
                # Count remaining requests in current window
                pipe.zcard(redis_key)
                # Fetch earliest timestamp in window to compute retry_after
                pipe.zrange(redis_key, 0, 0, withscores=True)
                results = pipe.execute()

                current_count = results[1]
                earliest_items = results[2]

                if current_count >= max_requests:
                    if earliest_items:
                        earliest_ts = float(earliest_items[0][1])
                        retry_after = max(1, int(window_seconds - (now - earliest_ts)))
                    else:
                        retry_after = window_seconds
                    return True, retry_after

                # Add current timestamp to window with auto-expiry
                pipe = r.pipeline()
                pipe.zadd(redis_key, {str(now): now})
                pipe.expire(redis_key, window_seconds * 2)
                pipe.execute()

                return False, 0
            except Exception as e:
                if prod:
                    logger.error(f"[RATE_LIMITER] Redis rate limiter failure in production: {e}. Failing closed.")
                    return True, window_seconds
                logger.warning(f"RateLimiter Redis failure, falling back to local window: {e}")
        elif prod:
            logger.error("[RATE_LIMITER] Redis is unavailable in production. Failing closed for rate-limited operation.")
            return True, window_seconds

        # In-Memory sliding window fallback (ONLY in non-production local development)
        with self._local_lock:
            timestamps = self._local_windows.get(limiter_key, [])
            valid_ts = [t for t in timestamps if t > window_start]
            if len(valid_ts) >= max_requests:
                earliest = valid_ts[0]
                retry_after = max(1, int(window_seconds - (now - earliest)))
                self._local_windows[limiter_key] = valid_ts
                return True, retry_after

            valid_ts.append(now)
            self._local_windows[limiter_key] = valid_ts
            return False, 0


# Global RateLimiter instance
rate_limiter = RateLimiter()


from app.security.dependencies import get_current_user


def rate_limit(category: str):
    """
    FastAPI dependency factory to enforce rate limiting on endpoints.
    Uses authenticated user subject if available, otherwise client IP.
    """
    async def dependency(request: Request, user: AuthenticatedUser = Depends(get_current_user)):
        max_reqs, window_secs = RATE_LIMIT_CONFIGS.get(category, RATE_LIMIT_CONFIGS["general"])

        # Extract identifier: prefer authenticated user sub, fallback to client IP
        if user and user.subject:
            identifier = f"user:{user.subject}"
        else:
            client_ip = request.client.host if request.client else "unknown"
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                client_ip = forwarded.split(",")[0].strip()
            identifier = f"ip:{client_ip}"

        limited, retry_after = rate_limiter.is_rate_limited(category, identifier, max_reqs, window_secs)
        if limited:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": f"Rate limit exceeded for category '{category}'. Please try again in {retry_after} seconds."
                    },
                    "retry_after": retry_after
                },
                headers={"Retry-After": str(retry_after)}
            )

    return dependency
