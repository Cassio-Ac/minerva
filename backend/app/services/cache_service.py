"""
Redis Cache Service
High-performance caching layer for Elasticsearch aggregations
"""

import redis
import json
import hashlib
import logging
from typing import Optional, Any, Dict, Callable
from datetime import timedelta
import os

logger = logging.getLogger(__name__)


class CacheService:
    """Redis-based cache service for ES aggregations"""

    def __init__(self):
        """Initialize Redis connection"""
        # Try REDIS_URL first (Docker), then individual vars
        redis_url = os.getenv("REDIS_URL")

        try:
            if redis_url:
                # Use redis URL (e.g., redis://redis:6379/0)
                self.redis = redis.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                )
                logger.info(f"✅ Redis cache connected via URL: {redis_url}")
            else:
                # Use individual host/port/db
                redis_host = os.getenv("REDIS_HOST", "localhost")
                redis_port = int(os.getenv("REDIS_PORT", "6379"))
                redis_db = int(os.getenv("REDIS_DB", "0"))

                self.redis = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    db=redis_db,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                )
                logger.info(f"✅ Redis cache connected: {redis_host}:{redis_port}")

            # Test connection
            self.redis.ping()
            self.enabled = True
        except Exception as e:
            logger.warning(f"⚠️ Redis not available: {e}. Cache disabled.")
            self.redis = None
            self.enabled = False

    def _generate_key(self, prefix: str, params: Dict[str, Any]) -> str:
        """
        Generate cache key from prefix and parameters

        Args:
            prefix: Cache key prefix (e.g., "es:agg", "es:query")
            params: Dictionary of parameters to hash

        Returns:
            Cache key string
        """
        # Sort params for consistent hashing
        sorted_params = json.dumps(params, sort_keys=True)
        param_hash = hashlib.md5(sorted_params.encode()).hexdigest()[:12]
        return f"{prefix}:{param_hash}"

    async def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found
        """
        if not self.enabled:
            return None

        try:
            value = self.redis.get(key)
            if value:
                logger.debug(f"🎯 Cache HIT: {key}")
                return json.loads(value)
            else:
                logger.debug(f"💾 Cache MISS: {key}")
                return None
        except Exception as e:
            logger.error(f"❌ Cache get error for key {key}: {e}")
            return None

    async def set(
        self, key: str, value: Any, ttl: int = 300
    ) -> bool:
        """
        Set value in cache with TTL

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds (default: 5 minutes)

        Returns:
            True if successful, False otherwise
        """
        if not self.enabled:
            return False

        try:
            serialized = json.dumps(value)
            self.redis.setex(key, ttl, serialized)
            logger.debug(f"💾 Cache SET: {key} (ttl={ttl}s)")
            return True
        except Exception as e:
            logger.error(f"❌ Cache set error for key {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """
        Delete key from cache

        Args:
            key: Cache key

        Returns:
            True if deleted, False otherwise
        """
        if not self.enabled:
            return False

        try:
            deleted = self.redis.delete(key)
            logger.debug(f"🗑️ Cache DELETE: {key}")
            return deleted > 0
        except Exception as e:
            logger.error(f"❌ Cache delete error for key {key}: {e}")
            return False

    async def delete_pattern(self, pattern: str) -> int:
        """
        Delete all keys matching pattern

        Args:
            pattern: Pattern to match (e.g., "es:agg:*")

        Returns:
            Number of keys deleted
        """
        if not self.enabled:
            return 0

        try:
            keys = self.redis.keys(pattern)
            if keys:
                deleted = self.redis.delete(*keys)
                logger.info(f"🗑️ Cache DELETE pattern '{pattern}': {deleted} keys")
                return deleted
            return 0
        except Exception as e:
            logger.error(f"❌ Cache delete pattern error for '{pattern}': {e}")
            return 0

    async def get_or_set(
        self,
        key: str,
        fetch_fn: Callable,
        ttl: int = 300
    ) -> Any:
        """
        Get from cache or execute function and cache result

        Args:
            key: Cache key
            fetch_fn: Function to execute if cache miss
            ttl: Time to live in seconds

        Returns:
            Cached or fresh value
        """
        # Try cache first
        cached = await self.get(key)
        if cached is not None:
            return cached

        # Cache miss: execute function
        logger.debug(f"💾 Executing fetch function for key: {key}")
        result = await fetch_fn()

        # Cache result
        await self.set(key, result, ttl)

        return result

    async def clear_all(self) -> bool:
        """
        Clear all cache (use with caution!)

        Returns:
            True if successful
        """
        if not self.enabled:
            return False

        try:
            self.redis.flushdb()
            logger.warning("🗑️ Cache CLEARED (all keys deleted)")
            return True
        except Exception as e:
            logger.error(f"❌ Cache clear error: {e}")
            return False

    async def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics

        Returns:
            Dictionary with cache stats
        """
        if not self.enabled:
            return {
                "enabled": False,
                "message": "Redis cache is disabled"
            }

        try:
            info = self.redis.info()
            return {
                "enabled": True,
                "used_memory": info.get("used_memory_human"),
                "total_keys": self.redis.dbsize(),
                "connected_clients": info.get("connected_clients"),
                "uptime_seconds": info.get("uptime_in_seconds"),
                "hit_rate": self._calculate_hit_rate(info),
            }
        except Exception as e:
            logger.error(f"❌ Cache stats error: {e}")
            return {"enabled": False, "error": str(e)}

    def _calculate_hit_rate(self, info: Dict) -> Optional[float]:
        """Calculate cache hit rate percentage"""
        hits = info.get("keyspace_hits", 0)
        misses = info.get("keyspace_misses", 0)
        total = hits + misses

        if total == 0:
            return None

        return round((hits / total) * 100, 2)

    async def invalidate_index_cache(self, index_name: str) -> int:
        """
        Invalidate all cache entries for a specific index

        Args:
            index_name: Elasticsearch index name

        Returns:
            Number of keys deleted
        """
        pattern = f"es:*:{index_name}:*"
        return await self.delete_pattern(pattern)


# Singleton instance
_cache_service: Optional[CacheService] = None


def get_cache_service() -> CacheService:
    """
    Get or create CacheService singleton

    Returns:
        CacheService instance
    """
    global _cache_service
    if _cache_service is None:
        _cache_service = CacheService()
    return _cache_service
