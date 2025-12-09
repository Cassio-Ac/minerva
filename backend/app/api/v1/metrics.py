"""
System Metrics API Endpoints
Consulta de métricas do sistema
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from app.db.database import get_db
from app.services.metrics_service import get_metrics_service
from app.models.user import User
from app.core.dependencies import get_current_user

router = APIRouter()
logger = logging.getLogger(__name__)


class MetricsSummaryResponse(BaseModel):
    """Response with metrics summary"""
    period_hours: int
    total_requests: int
    avg_response_time_ms: float
    total_errors: int
    error_rate_percent: float
    avg_cache_hit_rate_percent: float
    active_users: int
    timestamp: str


class TimeSeriesPoint(BaseModel):
    """Single point in time series"""
    timestamp: str
    avg_value: float
    min_value: float
    max_value: float
    count: int


class TopEndpoint(BaseModel):
    """Top endpoint with request count"""
    endpoint: str
    requests: int


@router.get("/summary", response_model=MetricsSummaryResponse)
async def get_metrics_summary(
    hours: int = Query(24, ge=1, le=168, description="Number of hours to query (1-168)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get system metrics summary

    Returns aggregated metrics for the specified time period:
    - Total requests
    - Average response time
    - Total errors and error rate
    - Cache hit rate
    - Active users

    Requires authentication.
    """
    try:
        metrics_service = get_metrics_service()
        summary = await metrics_service.get_metrics_summary(db, hours=hours)
        return MetricsSummaryResponse(**summary)
    except Exception as e:
        logger.error(f"Error getting metrics summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/timeseries", response_model=List[TimeSeriesPoint])
async def get_time_series(
    metric_type: str = Query(..., description="Metric type (usage, performance, error, cache, resource)"),
    metric_name: str = Query(..., description="Metric name"),
    hours: int = Query(24, ge=1, le=168, description="Number of hours to query"),
    interval_minutes: int = Query(60, ge=5, le=1440, description="Aggregation interval in minutes"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get time series data for a specific metric

    Returns aggregated data points with avg, min, max values
    for the specified time period and interval.

    Requires authentication.
    """
    try:
        metrics_service = get_metrics_service()
        data = await metrics_service.get_time_series(
            db,
            metric_type=metric_type,
            metric_name=metric_name,
            hours=hours,
            interval_minutes=interval_minutes
        )
        return [TimeSeriesPoint(**point) for point in data]
    except Exception as e:
        logger.error(f"Error getting time series: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/top-endpoints", response_model=List[TopEndpoint])
async def get_top_endpoints(
    hours: int = Query(24, ge=1, le=168, description="Number of hours to query"),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of results"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get top endpoints by request count

    Returns the most accessed endpoints in the specified time period.

    Requires authentication.
    """
    try:
        metrics_service = get_metrics_service()
        endpoints = await metrics_service.get_top_endpoints(db, hours=hours, limit=limit)
        return [TopEndpoint(**ep) for ep in endpoints]
    except Exception as e:
        logger.error(f"Error getting top endpoints: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cleanup")
async def cleanup_old_metrics(
    days: int = Query(30, ge=7, le=365, description="Keep metrics from last N days"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Cleanup old metrics from database

    Deletes metrics older than the specified number of days.

    Requires authentication with system configuration permission.
    """
    # Check permission
    if not current_user.can_configure_system:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. System configuration access required."
        )

    try:
        metrics_service = get_metrics_service()
        deleted_count = await metrics_service.cleanup_old_metrics(db, days=days)

        return {
            "success": True,
            "deleted_count": deleted_count,
            "message": f"Deleted {deleted_count} metrics older than {days} days"
        }
    except Exception as e:
        logger.error(f"Error cleaning up metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def metrics_health():
    """
    Check metrics system health (no authentication required)

    Returns basic health status of the metrics system.
    """
    try:
        return {
            "status": "healthy",
            "message": "Metrics system is operational"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }
