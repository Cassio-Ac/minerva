"""
Malpedia Library API Endpoints

Endpoints for Malpedia Library (RSS + BibTeX) management
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/malpedia-library", tags=["Malpedia Library"])


class SyncResponse(BaseModel):
    """Sync response"""
    status: str
    message: str
    task_id: Optional[str] = None


class StatsResponse(BaseModel):
    """Stats response"""
    source: str
    total_articles: int
    latest_article: Optional[str] = None
    oldest_article: Optional[str] = None
    articles_by_year: list = []
    articles_by_type: list = []
    error: Optional[str] = None


class SyncResult(BaseModel):
    """Sync result"""
    source: str
    total_found: int
    total_indexed: int
    timestamp: str


class FullSyncResult(BaseModel):
    """Full sync result"""
    rss: dict
    bibtex: dict
    total_found: int
    total_indexed: int
    timestamp: str


# ============================================================
# Stats Endpoint
# ============================================================

@router.get("/stats", response_model=StatsResponse)
async def get_malpedia_library_stats():
    """
    Get Malpedia Library statistics from Elasticsearch
    """
    try:
        from app.services.malpedia_library_service import MalpediaLibraryService

        service = MalpediaLibraryService()
        try:
            stats = await service.get_stats()
            return StatsResponse(**stats)
        finally:
            await service.close()

    except Exception as e:
        logger.error(f"Error getting Malpedia Library stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# RSS Sync Endpoints
# ============================================================

@router.post("/sync/rss", response_model=SyncResponse)
async def trigger_rss_sync(
    background_tasks: BackgroundTasks,
    async_mode: bool = Query(default=True, description="Run in background")
):
    """
    Trigger Malpedia Library RSS sync

    - async_mode: If True, runs in background via Celery
    """
    try:
        if async_mode:
            # Use Celery task
            from app.tasks.malpedia_tasks import sync_malpedia_library_rss
            task = sync_malpedia_library_rss.delay()

            return SyncResponse(
                status="started",
                message="Malpedia Library RSS sync started in background",
                task_id=task.id
            )
        else:
            # Run synchronously (for testing)
            from app.services.malpedia_library_service import run_malpedia_library_rss_sync

            result = await run_malpedia_library_rss_sync()

            return SyncResponse(
                status="completed",
                message=f"RSS sync completed: {result.get('total_indexed', 0)} articles indexed"
            )

    except Exception as e:
        logger.error(f"Error triggering RSS sync: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# BibTeX Sync Endpoints
# ============================================================

@router.post("/sync/bibtex", response_model=SyncResponse)
async def trigger_bibtex_sync(
    background_tasks: BackgroundTasks,
    async_mode: bool = Query(default=True, description="Run in background")
):
    """
    Trigger Malpedia Library BibTeX sync

    - async_mode: If True, runs in background via Celery
    """
    try:
        if async_mode:
            # Use Celery task
            from app.tasks.malpedia_tasks import sync_malpedia_library_bibtex
            task = sync_malpedia_library_bibtex.delay()

            return SyncResponse(
                status="started",
                message="Malpedia Library BibTeX sync started in background",
                task_id=task.id
            )
        else:
            # Run synchronously (for testing)
            from app.services.malpedia_library_service import run_malpedia_library_bibtex_sync

            result = await run_malpedia_library_bibtex_sync()

            return SyncResponse(
                status="completed",
                message=f"BibTeX sync completed: {result.get('total_indexed', 0)} articles indexed"
            )

    except Exception as e:
        logger.error(f"Error triggering BibTeX sync: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# Full Sync Endpoints
# ============================================================

@router.post("/sync/full", response_model=SyncResponse)
async def trigger_full_sync():
    """
    Trigger FULL Malpedia Library sync (RSS + BibTeX)

    Warning: This may take several minutes
    """
    try:
        from app.tasks.malpedia_tasks import sync_malpedia_library_full
        task = sync_malpedia_library_full.delay()

        return SyncResponse(
            status="started",
            message="Full Malpedia Library sync started in background (RSS + BibTeX)",
            task_id=task.id
        )

    except Exception as e:
        logger.error(f"Error triggering full sync: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# Direct Sync (for testing without Celery)
# ============================================================

@router.post("/sync-now/rss", response_model=SyncResult)
async def sync_rss_now():
    """
    Run RSS sync immediately (synchronous, for testing)
    """
    try:
        from app.services.malpedia_library_service import run_malpedia_library_rss_sync

        result = await run_malpedia_library_rss_sync()

        return SyncResult(**result)

    except Exception as e:
        logger.error(f"Error syncing RSS: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sync-now/bibtex", response_model=SyncResult)
async def sync_bibtex_now():
    """
    Run BibTeX sync immediately (synchronous, for testing)

    Warning: This may take a minute or two
    """
    try:
        from app.services.malpedia_library_service import run_malpedia_library_bibtex_sync

        result = await run_malpedia_library_bibtex_sync()

        return SyncResult(**result)

    except Exception as e:
        logger.error(f"Error syncing BibTeX: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sync-now/full", response_model=FullSyncResult)
async def sync_full_now():
    """
    Run full sync immediately (synchronous, for testing)

    Warning: This may take several minutes
    """
    try:
        from app.services.malpedia_library_service import run_malpedia_library_full_sync

        result = await run_malpedia_library_full_sync()

        return FullSyncResult(**result)

    except Exception as e:
        logger.error(f"Error syncing full: {e}")
        raise HTTPException(status_code=500, detail=str(e))
