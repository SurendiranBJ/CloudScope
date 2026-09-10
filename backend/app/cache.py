import logging
import json
import threading
import redis
from app.config import settings

logger = logging.getLogger("backend")

class CacheManager:
    def __init__(self):
        self.redis_client = None
        self.local_cache = {}
        self._lock = threading.Lock()
        try:
            self.redis_client = redis.Redis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                decode_responses=True,
                socket_connect_timeout=2
            )
            self.redis_client.ping()
            logger.info(f"Connected to Redis cache at {settings.REDIS_HOST}:{settings.REDIS_PORT}")
        except Exception:
            logger.warning("Redis is not accessible. Falling back to local in-memory caching.")
            self.redis_client = None

    @property
    def is_redis(self) -> bool:
        return self.redis_client is not None

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
            val = self.local_cache.get(key)
            # Return a shallow copy if dict/list so callers don't mutate cached references
            if isinstance(val, list):
                return list(val)
            if isinstance(val, dict):
                return dict(val)
            return val

    def set(self, key: str, value: any, ttl_seconds: int = 300):
        if self.redis_client:
            try:
                self.redis_client.setex(key, ttl_seconds, json.dumps(value))
            except Exception as e:
                logger.error(f"Redis set error: {str(e)}")
        
        # Local fallback
        with self._lock:
            self.local_cache[key] = value

    def set_many(self, mapping: dict, ttl_seconds: int = 300):
        """Atomically set multiple cache keys simultaneously.
        In Redis, uses a single pipeline transaction.
        In local fallback, updates dictionary under thread lock.
        """
        if self.redis_client:
            try:
                pipe = self.redis_client.pipeline()
                for k, v in mapping.items():
                    pipe.setex(k, ttl_seconds, json.dumps(v))
                pipe.execute()
            except Exception as e:
                logger.error(f"Redis set_many error: {str(e)}")

        with self._lock:
            self.local_cache.update(mapping)

    def invalidate(self, key: str):
        if self.redis_client:
            try:
                self.redis_client.delete(key)
            except Exception as e:
                logger.error(f"Redis delete error: {str(e)}")
        
        # Local fallback
        with self._lock:
            if key in self.local_cache:
                del self.local_cache[key]

    def clear(self):
        if self.redis_client:
            try:
                self.redis_client.flushdb()
            except Exception as e:
                logger.error(f"Redis flush error: {str(e)}")
        
        # Local fallback
        with self._lock:
            self.local_cache.clear()

cache = CacheManager()

