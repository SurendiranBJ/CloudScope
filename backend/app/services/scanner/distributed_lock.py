"""
CloudScope Redis Distributed Scan Lock.

Enforces cross-worker mutual exclusion for scanning across Uvicorn workers,
containers, or cluster replicas using atomic Redis primitives (SET NX EX)
and safe owner-validated Lua release and renewal scripts.
"""

import logging
import os
import time
import uuid
from typing import Any, Dict, Optional
from app.cache import cache

logger = logging.getLogger("cloudscope.lock")

DEFAULT_LOCK_KEY = "cloudscope:scan:lock"
DEFAULT_LEASE_SECONDS = int(os.getenv("SCAN_LOCK_LEASE_SECONDS", "180"))

# Lua script for atomic lease extension (only if owner token matches)
RENEW_LUA_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('expire', KEYS[1], tonumber(ARGV[2]))
else
    return 0
end
"""

# Lua script for atomic release (only if owner token matches)
RELEASE_LUA_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
else
    return 0
end
"""


class DistributedScanLock:
    """Distributed coordination lock backed by Redis with safe lease renewal."""

    def __init__(self, lock_key: str = DEFAULT_LOCK_KEY):
        self.lock_key = lock_key
        self._current_owner_token: Optional[str] = None
        self._acquired_at: Optional[float] = None
        self._lease_seconds: int = DEFAULT_LEASE_SECONDS

    def acquire(self, lease_seconds: Optional[int] = None) -> Optional[str]:
        """Attempt to acquire the distributed scan lock atomically."""
        lease = lease_seconds or self._lease_seconds
        token = str(uuid.uuid4())
        prod = os.getenv("ENVIRONMENT", "development").lower() == "production"
        client = cache.redis_client

        if client is None:
            if prod:
                logger.error("[DISTRIBUTED_LOCK] Redis is unavailable in production. Failing closed.")
                return None
            # Standalone memory fallback ONLY in non-production local development
            if not cache.get(self.lock_key):
                cache.set(self.lock_key, token, ttl_seconds=lease)
                self._current_owner_token = token
                return token
            return None

        try:
            # SET lock_key token NX EX lease
            acquired = client.set(self.lock_key, token, nx=True, ex=lease)
            if acquired:
                self._current_owner_token = token
                self._acquired_at = time.time()
                self._lease_seconds = lease
                logger.info(f"[DISTRIBUTED_LOCK] Acquired scan lock with token {token[:8]}... (lease={lease}s)")
                return token
            else:
                logger.info(f"[DISTRIBUTED_LOCK] Failed to acquire lock (already held by another worker)")
                return None
        except Exception as e:
            if prod:
                logger.error(f"[DISTRIBUTED_LOCK] Redis lock acquire failure in production: {e}. Failing closed.")
                return None
            logger.warning(f"[DISTRIBUTED_LOCK] Redis lock acquire fallback due to: {e}")
            if not cache.get(self.lock_key):
                cache.set(self.lock_key, token, ttl_seconds=lease)
                self._current_owner_token = token
                return token
            return None

    def renew(self, owner_token: str, lease_seconds: Optional[int] = None) -> bool:
        """Extend the lock lease if the calling instance is the owner."""
        lease = lease_seconds or self._lease_seconds
        prod = os.getenv("ENVIRONMENT", "development").lower() == "production"
        client = cache.redis_client

        if client is None:
            if prod:
                return False
            val = cache.get(self.lock_key)
            if val == owner_token:
                cache.set(self.lock_key, owner_token, ttl_seconds=lease)
                return True
            return False

        try:
            res = client.eval(RENEW_LUA_SCRIPT, 1, self.lock_key, owner_token, str(lease))
            if res == 1:
                logger.debug(f"[DISTRIBUTED_LOCK] Renewed lease for token {owner_token[:8]}... (lease={lease}s)")
                return True
            return False
        except Exception as e:
            if prod:
                logger.error(f"[DISTRIBUTED_LOCK] Redis error renewing lock lease in production: {e}")
                return False
            logger.warning(f"[DISTRIBUTED_LOCK] Error renewing lock lease: {e}")
            val = cache.get(self.lock_key)
            if val == owner_token:
                cache.set(self.lock_key, owner_token, ttl_seconds=lease)
                return True
            return False

    def release(self, owner_token: str) -> bool:
        """Safely release the lock only if the supplied token matches the owner."""
        try:
            client = cache.redis_client
            res = client.eval(RELEASE_LUA_SCRIPT, 1, self.lock_key, owner_token)
            if res == 1:
                logger.info(f"[DISTRIBUTED_LOCK] Released lock with token {owner_token[:8]}...")
                if self._current_owner_token == owner_token:
                    self._current_owner_token = None
                return True
            else:
                logger.warning(f"[DISTRIBUTED_LOCK] Refused to release lock: token {owner_token[:8]}... does not match owner")
                return False
        except Exception as e:
            logger.warning(f"[DISTRIBUTED_LOCK] Fallback release: {e}")
            if cache.get(self.lock_key) == owner_token:
                cache.delete(self.lock_key)
                return True
            return False

    def get_lock_info(self) -> Dict[str, Any]:
        """Query active lock status, TTL, and owner."""
        try:
            client = cache.redis_client
            val = client.get(self.lock_key)
            ttl = client.ttl(self.lock_key) if val else -2
            owner = val.decode("utf-8") if isinstance(val, bytes) else str(val) if val else None
            return {
                "is_locked": bool(owner),
                "ttl": max(0, ttl) if ttl > 0 else 0,
                "ttl_seconds": max(0, ttl) if ttl > 0 else 0,
                "owner_token": owner,
                "owner_preview": f"{owner[:8]}..." if owner else None,
            }
        except Exception:
            val = cache.get(self.lock_key)
            owner = str(val) if val else None
            return {
                "is_locked": bool(val),
                "ttl": 0,
                "ttl_seconds": 0,
                "owner_token": owner,
                "owner_preview": f"{owner[:8]}..." if owner else None,
            }


distributed_scan_lock = DistributedScanLock()
scan_lock = distributed_scan_lock
