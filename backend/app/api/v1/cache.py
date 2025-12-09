"""
Cache Management API Endpoints
Admin endpoints for managing Redis cache
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, Dict, Any
import logging

from app.services.cache_service import get_cache_service
from app.models.user import User
from app.core.dependencies import get_current_user

router = APIRouter()
logger = logging.getLogger(__name__)


class CacheStatsResponse(BaseModel):
    """Cache statistics response"""
    enabled: bool
    used_memory: Optional[str] = None
    total_keys: Optional[int] = None
    connected_clients: Optional[int] = None
    uptime_seconds: Optional[int] = None
    hit_rate: Optional[float] = None
    message: Optional[str] = None
    error: Optional[str] = None


class CacheInvalidateRequest(BaseModel):
    """Request to invalidate cache"""
    pattern: Optional[str] = None
    index_name: Optional[str] = None


class CacheInvalidateResponse(BaseModel):
    """Response from cache invalidation"""
    success: bool
    keys_deleted: int
    message: str


@router.get("/stats", response_model=CacheStatsResponse)
async def get_cache_stats(current_user: User = Depends(get_current_user)):
    """
    Get Redis cache statistics

    Requires authentication.
    """
    try:
        cache_service = get_cache_service()
        stats = await cache_service.get_stats()
        return CacheStatsResponse(**stats)
    except Exception as e:
        logger.error(f"Error getting cache stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/invalidate", response_model=CacheInvalidateResponse)
async def invalidate_cache(
    request: CacheInvalidateRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Invalidate cache entries

    Can invalidate by:
    - pattern: Redis key pattern (e.g., "es:query:*")
    - index_name: Invalidate all cache for a specific ES index

    Requires authentication with system configuration permission.
    """
    # Check permission
    if not current_user.can_configure_system:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. System configuration access required."
        )

    try:
        cache_service = get_cache_service()

        if not cache_service.enabled:
            return CacheInvalidateResponse(
                success=False,
                keys_deleted=0,
                message="Cache is disabled"
            )

        keys_deleted = 0

        # Invalidate by index name
        if request.index_name:
            logger.info(f"Invalidating cache for index: {request.index_name}")
            keys_deleted = await cache_service.invalidate_index_cache(request.index_name)
            return CacheInvalidateResponse(
                success=True,
                keys_deleted=keys_deleted,
                message=f"Invalidated {keys_deleted} cache entries for index '{request.index_name}'"
            )

        # Invalidate by pattern
        if request.pattern:
            logger.info(f"Invalidating cache by pattern: {request.pattern}")
            keys_deleted = await cache_service.delete_pattern(request.pattern)
            return CacheInvalidateResponse(
                success=True,
                keys_deleted=keys_deleted,
                message=f"Invalidated {keys_deleted} cache entries matching pattern '{request.pattern}'"
            )

        # No parameters provided
        raise HTTPException(
            status_code=400,
            detail="Either 'pattern' or 'index_name' must be provided"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error invalidating cache: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/clear", response_model=CacheInvalidateResponse)
async def clear_all_cache(current_user: User = Depends(get_current_user)):
    """
    Clear ALL cache entries (use with caution!)

    Requires authentication with system configuration permission.
    """
    # Check permission
    if not current_user.can_configure_system:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. System configuration access required."
        )

    try:
        cache_service = get_cache_service()

        if not cache_service.enabled:
            return CacheInvalidateResponse(
                success=False,
                keys_deleted=0,
                message="Cache is disabled"
            )

        # Get total keys before clearing
        stats = await cache_service.get_stats()
        total_keys = stats.get("total_keys", 0)

        # Clear all cache
        logger.warning(f"⚠️ Clearing ALL cache (user: {current_user.username})")
        success = await cache_service.clear_all()

        if success:
            return CacheInvalidateResponse(
                success=True,
                keys_deleted=total_keys,
                message=f"All cache cleared ({total_keys} keys deleted)"
            )
        else:
            return CacheInvalidateResponse(
                success=False,
                keys_deleted=0,
                message="Failed to clear cache"
            )

    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def cache_health():
    """
    Check Redis cache health (no authentication required)

    Returns:
        - enabled: bool
        - connected: bool
    """
    try:
        cache_service = get_cache_service()

        if not cache_service.enabled:
            return {
                "enabled": False,
                "connected": False,
                "message": "Cache is disabled"
            }

        # Try to ping Redis
        try:
            cache_service.redis.ping()
            return {
                "enabled": True,
                "connected": True,
                "message": "Cache is healthy"
            }
        except:
            return {
                "enabled": True,
                "connected": False,
                "message": "Cache connection failed"
            }
    except Exception as e:
        return {
            "enabled": False,
            "connected": False,
            "error": str(e)
        }
