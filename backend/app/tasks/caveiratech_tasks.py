"""
CaveiraTech Celery Tasks

Background tasks for CaveiraTech crawler
"""

import logging
import asyncio
from typing import Optional

from app.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.caveiratech_tasks.sync_caveiratech", bind=True)
def sync_caveiratech(self, max_pages: Optional[int] = 10):
    """
    Periodic task: Sync CaveiraTech articles

    Args:
        max_pages: Maximum pages to crawl (default 10 for incremental)

    Returns:
        Sync stats
    """
    logger.info(f"Starting CaveiraTech sync task (max_pages={max_pages})")

    try:
        from app.services.caveiratech_crawler import run_caveiratech_sync

        result = asyncio.run(run_caveiratech_sync(max_pages=max_pages))

        logger.info(f"CaveiraTech sync completed: {result}")
        return result

    except Exception as e:
        logger.error(f"CaveiraTech sync failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries), max_retries=3)


@celery_app.task(name="app.tasks.caveiratech_tasks.full_sync_caveiratech", bind=True)
def full_sync_caveiratech(self):
    """
    Full sync task: Crawl ALL pages from CaveiraTech

    Warning: This may take several minutes (300+ pages)

    Returns:
        Sync stats
    """
    logger.info("Starting FULL CaveiraTech sync task")

    try:
        from app.services.caveiratech_crawler import run_caveiratech_sync

        # No max_pages = crawl everything
        result = asyncio.run(run_caveiratech_sync(max_pages=None))

        logger.info(f"Full CaveiraTech sync completed: {result}")
        return result

    except Exception as e:
        logger.error(f"Full CaveiraTech sync failed: {e}")
        raise self.retry(exc=e, countdown=120 * (2 ** self.request.retries), max_retries=2)


@celery_app.task(name="app.tasks.caveiratech_tasks.get_caveiratech_stats")
def get_caveiratech_stats():
    """
    Get CaveiraTech stats from Elasticsearch

    Returns:
        Stats dict
    """
    logger.info("Getting CaveiraTech stats")

    try:
        from app.services.caveiratech_crawler import CaveiraTechCrawlerService

        async def _get_stats():
            crawler = CaveiraTechCrawlerService()
            try:
                return await crawler.get_stats()
            finally:
                await crawler.close()

        result = asyncio.run(_get_stats())
        return result

    except Exception as e:
        logger.error(f"Error getting CaveiraTech stats: {e}")
        return {'error': str(e)}
