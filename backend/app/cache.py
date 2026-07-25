import logging
import json
import redis
from app.config import settings

logger = logging.getLogger("backend")

class CacheManager:
    def __init__(self):
        self.redis_client = None
        self.local_cache = {}
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

    def get(self, key: str) -> dict | list | None:
        if self.redis_client:
            try:
                val = self.redis_client.get(key)
                if val:
                    return json.loads(val)
            except Exception as e:
                logger.error(f"Redis get error: {str(e)}")
        
        # Local fallback
        return self.local_cache.get(key)

    def set(self, key: str, value: any, ttl_seconds: int = 300):
        if self.redis_client:
            try:
                self.redis_client.setex(key, ttl_seconds, json.dumps(value))
                return
            except Exception as e:
                logger.error(f"Redis set error: {str(e)}")
        
        # Local fallback
        self.local_cache[key] = value

    def invalidate(self, key: str):
        if self.redis_client:
            try:
                self.redis_client.delete(key)
                return
            except Exception as e:
                logger.error(f"Redis delete error: {str(e)}")
        
        # Local fallback
        if key in self.local_cache:
            del self.local_cache[key]

    def clear(self):
        if self.redis_client:
            try:
                self.redis_client.flushdb()
                return
            except Exception as e:
                logger.error(f"Redis flush error: {str(e)}")
        
        # Local fallback
        self.local_cache.clear()

cache = CacheManager()
