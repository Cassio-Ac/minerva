"""
RSS Celery Tasks
Background tasks for RSS feed collection
"""

import logging
from typing import List, Optional
import asyncio

from app.celery_app import celery_app
from app.db.database import AsyncSessionLocal
from app.db.elasticsearch import get_sync_es_client
from app.services.rss_collector import RSSCollectorService
from app.models.rss import RSSSettings
from sqlalchemy import select

logger = logging.getLogger(__name__)


def _run_async(coro):
    """Helper to run async code in Celery worker with fresh event loop"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(name="app.tasks.rss_tasks.collect_all_rss_feeds", bind=True)
def collect_all_rss_feeds(self):
    """
    Periodic task: Collect from all active RSS feeds
    Runs according to beat schedule (default: every 6 hours)
    """
    logger.info("🚀 Starting periodic RSS collection task")

    try:
        # Run async collection in sync context with fresh event loop
        result = _run_async(_async_collect_all())

        logger.info(f"✅ Periodic collection completed: {result}")
        return result

    except Exception as e:
        logger.error(f"❌ Periodic collection failed: {e}")
        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries), max_retries=3)


@celery_app.task(name="app.tasks.rss_tasks.collect_specific_sources", bind=True)
def collect_specific_sources(self, source_ids: List[str], triggered_by: str = "api", executed_by: Optional[str] = None):
    """
    On-demand task: Collect from specific RSS sources

    Args:
        source_ids: List of source IDs to collect
        triggered_by: Who triggered (api, manual, etc)
        executed_by: User ID if manual

    Returns:
        Collection stats
    """
    logger.info(f"🔍 Starting on-demand collection for {len(source_ids)} sources")

    try:
        result = _run_async(_async_collect_specific(source_ids, triggered_by, executed_by))

        logger.info(f"✅ On-demand collection completed: {result}")
        return result

    except Exception as e:
        logger.error(f"❌ On-demand collection failed: {e}")
        raise self.retry(exc=e, countdown=30, max_retries=2)


@celery_app.task(name="app.tasks.rss_tasks.collect_category", bind=True)
def collect_category(self, category_ids: List[str], triggered_by: str = "api"):
    """
    On-demand task: Collect from all sources in specific categories

    Args:
        category_ids: List of category IDs
        triggered_by: Who triggered

    Returns:
        Collection stats
    """
    logger.info(f"📚 Starting category collection for {len(category_ids)} categories")

    try:
        result = _run_async(_async_collect_all(category_ids=category_ids, triggered_by=triggered_by))

        logger.info(f"✅ Category collection completed: {result}")
        return result

    except Exception as e:
        logger.error(f"❌ Category collection failed: {e}")
        raise self.retry(exc=e, countdown=30, max_retries=2)


# ==================== Helper async functions ====================

async def _async_collect_all(category_ids: Optional[List[str]] = None, triggered_by: str = "scheduler"):
    """Async helper: Collect from all active sources"""
    async with AsyncSessionLocal() as db:
        # Get settings
        result = await db.execute(select(RSSSettings))
        settings = result.scalar_one_or_none()

        # Check if scheduler is enabled
        if triggered_by == "scheduler" and settings and not settings.scheduler_enabled:
            logger.info("⏸️ Scheduler is disabled in settings, skipping collection")
            return {"status": "skipped", "reason": "scheduler_disabled"}

        # Get Elasticsearch client
        es_client = get_sync_es_client()

        # Create collector service
        index_alias = settings.es_index_alias if settings else "rss-articles"
        collector = RSSCollectorService(es_client, index_alias)

        # Get max articles from settings
        max_articles = settings.max_articles_per_feed if settings else 100

        # Collect from all active sources
        result = await collector.collect_all_active_sources(
            db,
            category_ids=category_ids,
            triggered_by=triggered_by,
            max_articles=max_articles
        )

        return result


async def _async_collect_specific(source_ids: List[str], triggered_by: str, executed_by: Optional[str]):
    """Async helper: Collect from specific sources"""
    from app.models.rss import RSSSource, RSSCategory

    async with AsyncSessionLocal() as db:
        # Get settings
        result = await db.execute(select(RSSSettings))
        settings = result.scalar_one_or_none()

        # Get Elasticsearch client
        es_client = get_sync_es_client()

        # Create collector service
        index_alias = settings.es_index_alias if settings else "rss-articles"
        collector = RSSCollectorService(es_client, index_alias)

        # Get max articles from settings
        max_articles = settings.max_articles_per_feed if settings else 100

        # Collect from each specified source
        total_articles_found = 0
        total_articles_new = 0
        sources_success = 0
        sources_error = 0

        for source_id in source_ids:
            # Get source with category
            query = select(RSSSource, RSSCategory.name).join(
                RSSCategory, RSSSource.category_id == RSSCategory.id
            ).where(RSSSource.id == source_id)

            result = await db.execute(query)
            source_data = result.first()

            if not source_data:
                logger.warning(f"⚠️ Source {source_id} not found")
                sources_error += 1
                continue

            source, category_name = source_data

            if not source.is_active:
                logger.warning(f"⚠️ Source {source.name} is not active")
                sources_error += 1
                continue

            # Collect from source
            collect_result = await collector.collect_source(
                db, source, category_name,
                triggered_by=triggered_by,
                executed_by=executed_by,
                max_articles=max_articles
            )

            if collect_result['status'] == 'success':
                sources_success += 1
                total_articles_found += collect_result.get('articles_found', 0)
                total_articles_new += collect_result.get('articles_new', 0)
            else:
                sources_error += 1

        return {
            "status": "completed",
            "sources_total": len(source_ids),
            "sources_success": sources_success,
            "sources_error": sources_error,
            "articles_found": total_articles_found,
            "articles_new": total_articles_new,
        }
