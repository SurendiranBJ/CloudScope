import socket
import logging
import json
import threading
import redis
import time
from app.config import settings

logger = logging.getLogger("backend")

class CacheManager:
    def __init__(self):
        self.redis_client = None
        self.local_cache = {}
        self._local_expiry = {}
        self._lock = threading.Lock()
        try:
            # Fast socket pre-check to avoid multi-second DNS/IPv6 connection timeout on Windows
            with socket.create_connection((settings.REDIS_HOST, settings.REDIS_PORT), timeout=0.3):
                pass
            self.redis_client = redis.Redis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                decode_responses=True,
                socket_connect_timeout=1,
                socket_timeout=1,
                retry_on_timeout=False
            )
            self.redis_client.ping()
            logger.info(f"Connected to Redis cache at {settings.REDIS_HOST}:{settings.REDIS_PORT}")
        except Exception:
            logger.warning("Redis is not accessible. Falling back to local in-memory caching.")
            self.redis_client = None

    @property
    def is_redis(self) -> bool:
        return self.check_redis()

    def check_redis(self) -> bool:
        """Check live Redis availability instead of only checking client setup."""
        if self.redis_client is None:
            return False
        try:
            return bool(self.redis_client.ping())
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return False

    def get(self, key: str) -> dict | list | None:
        if self.redis_client:
            try:
                val = self.redis_client.get(key)
                if val:
                    return json.loads(val)
            except Exception as e:
                logger.error(f"Redis get error: {str(e)}")
        
        # Local fallback
        with self._lock:
            expires_at = self._local_expiry.get(key)
            if expires_at is not None and expires_at <= time.monotonic():
                self.local_cache.pop(key, None)
                self._local_expiry.pop(key, None)
            val = self.local_cache.get(key)
            # Return a shallow copy if dict/list so callers don't mutate cached references
            if isinstance(val, list):
                return list(val)
            if isinstance(val, dict):
                return dict(val)
            return val

    def set(self, key: str, value: any, ttl_seconds: int | None = None):
        if self.redis_client:
            try:
                if ttl_seconds and ttl_seconds > 0:
                    self.redis_client.setex(key, ttl_seconds, json.dumps(value))
                else:
                    self.redis_client.set(key, json.dumps(value))
            except Exception as e:
                logger.error(f"Redis set error: {str(e)}")
        
        # Local fallback
        with self._lock:
            self.local_cache[key] = value
            if ttl_seconds and ttl_seconds > 0:
                self._local_expiry[key] = time.monotonic() + ttl_seconds
            else:
                self._local_expiry.pop(key, None)

    def set_many(self, mapping: dict, ttl_seconds: int | None = None):
        """Atomically set multiple cache keys simultaneously.
        In Redis, uses a single pipeline transaction.
        When ttl_seconds is None or <= 0, keys are stored persistently without expiration.
        In local fallback, updates dictionary under thread lock.
        """
        if self.redis_client:
            try:
                pipe = self.redis_client.pipeline()
                for k, v in mapping.items():
                    if ttl_seconds and ttl_seconds > 0:
                        pipe.setex(k, ttl_seconds, json.dumps(v))
                    else:
                        pipe.set(k, json.dumps(v))
                pipe.execute()
            except Exception as e:
                logger.error(f"Redis set_many error: {str(e)}")

        with self._lock:
            self.local_cache.update(mapping)
            expiry = time.monotonic() + ttl_seconds if ttl_seconds and ttl_seconds > 0 else None
            for key in mapping:
                if expiry is None:
                    self._local_expiry.pop(key, None)
                else:
                    self._local_expiry[key] = expiry

    def invalidate(self, key: str):
        if self.redis_client:
            try:
                self.redis_client.delete(key)
            except Exception as e:
                logger.error(f"Redis delete error: {str(e)}")
        
        # Local fallback
        with self._lock:
            self.local_cache.pop(key, None)
            self._local_expiry.pop(key, None)

    def delete(self, key: str):
        """Delete a cache entry; alias kept for Redis-compatible callers."""
        self.invalidate(key)

    def clear(self):
        if self.redis_client:
            try:
                self.redis_client.flushdb()
            except Exception as e:
                logger.error(f"Redis flush error: {str(e)}")
        
        # Local fallback
        with self._lock:
            self.local_cache.clear()
            self._local_expiry.clear()

cache = CacheManager()

