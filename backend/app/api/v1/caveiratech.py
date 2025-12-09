"""
CaveiraTech API Endpoints

Endpoints for CaveiraTech crawler management
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/caveiratech", tags=["CaveiraTech"])


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
    articles_by_month: list = []
    error: Optional[str] = None


class SyncResult(BaseModel):
    """Sync result"""
    source: str
    pages_crawled: int
    total_found: int
    total_indexed: int
    start_page: int
    end_page: int
    timestamp: str


# ============================================================
# Stats Endpoint
# ============================================================

@router.get("/stats", response_model=StatsResponse)
async def get_caveiratech_stats():
    """
    Get CaveiraTech articles statistics from Elasticsearch
    """
    try:
        from app.services.caveiratech_crawler import CaveiraTechCrawlerService

        crawler = CaveiraTechCrawlerService()
        try:
            stats = await crawler.get_stats()
            return StatsResponse(**stats)
        finally:
            await crawler.close()

    except Exception as e:
        logger.error(f"Error getting CaveiraTech stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# Sync Endpoints
# ============================================================

@router.post("/sync", response_model=SyncResponse)
async def trigger_sync(
    background_tasks: BackgroundTasks,
    max_pages: int = Query(default=10, ge=1, le=50, description="Max pages to crawl"),
    async_mode: bool = Query(default=True, description="Run in background")
):
    """
    Trigger CaveiraTech sync

    - max_pages: Number of pages to crawl (default 10)
    - async_mode: If True, runs in background via Celery
    """
    try:
        if async_mode:
            # Use Celery task
            from app.tasks.caveiratech_tasks import sync_caveiratech
            task = sync_caveiratech.delay(max_pages=max_pages)

            return SyncResponse(
                status="started",
                message=f"CaveiraTech sync started in background (max_pages={max_pages})",
                task_id=task.id
            )
        else:
            # Run synchronously (for testing)
            from app.services.caveiratech_crawler import run_caveiratech_sync

            result = await run_caveiratech_sync(max_pages=max_pages)

            return SyncResponse(
                status="completed",
                message=f"Sync completed: {result['total_indexed']} articles indexed from {result['pages_crawled']} pages"
            )

    except Exception as e:
        logger.error(f"Error triggering sync: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/full-sync", response_model=SyncResponse)
async def trigger_full_sync():
    """
    Trigger FULL CaveiraTech sync (all pages)

    Warning: This may take several minutes (300+ pages)
    """
    try:
        from app.tasks.caveiratech_tasks import full_sync_caveiratech
        task = full_sync_caveiratech.delay()

        return SyncResponse(
            status="started",
            message="Full CaveiraTech sync started in background (all pages)",
            task_id=task.id
        )

    except Exception as e:
        logger.error(f"Error triggering full sync: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# Direct Crawl (for testing without Celery)
# ============================================================

@router.post("/crawl-now", response_model=SyncResult)
async def crawl_now(
    max_pages: int = Query(default=5, ge=1, le=20, description="Max pages to crawl")
):
    """
    Run crawler immediately (synchronous, for testing)

    Limited to max 20 pages for safety
    """
    try:
        from app.services.caveiratech_crawler import run_caveiratech_sync

        result = await run_caveiratech_sync(max_pages=max_pages)

        return SyncResult(**result)

    except Exception as e:
        logger.error(f"Error crawling: {e}")
        raise HTTPException(status_code=500, detail=str(e))
