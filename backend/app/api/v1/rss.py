"""
RSS API Endpoints
REST API for RSS feed management, article search, and chat
"""

import logging
import asyncio
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from sqlalchemy.orm import selectinload

from app.db.database import get_db
from app.db.elasticsearch import get_es_client, get_sync_es_dependency
from app.models.rss import RSSCategory, RSSSource, RSSCollectionRun, RSSSettings
from app.schemas.rss import (
    # Categories
    RSSCategoryCreate, RSSCategoryUpdate, RSSCategoryResponse,
    # Sources
    RSSSourceCreate, RSSSourceUpdate, RSSSourceResponse,
    # Collection
    RSSCollectionRunResponse, RSSCollectRequest, RSSCollectResponse,
    # Articles
    RSSArticleSearchRequest, RSSArticleSearchResponse,
    # Chat
    RSSChatRequest, RSSChatResponse,
    # Settings
    RSSSettingsUpdate, RSSSettingsResponse,
    # Stats
    RSSStatsResponse,
    # Bulk Import
    RSSBulkImportRequest, RSSBulkImportResponse,
)
from app.services.rss_elasticsearch import RSSElasticsearchService
from app.services.rss_collector import RSSCollectorService
from app.services.malpedia_collector import MalpediaCollectorService
from app.core.dependencies import get_current_user, require_role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/rss", tags=["RSS Feeds"])


# ==================== Categories ====================

@router.get("/categories", response_model=List[RSSCategoryResponse])
async def list_categories(
    active_only: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List all RSS categories"""
    query = select(RSSCategory)

    if active_only:
        query = query.where(RSSCategory.is_active == True)

    query = query.order_by(RSSCategory.sort_order, RSSCategory.name)

    result = await db.execute(query)
    categories = result.scalars().all()

    # Add source count for each category
    response = []
    for cat in categories:
        count_query = select(func.count(RSSSource.id)).where(
            RSSSource.category_id == cat.id,
            RSSSource.is_active == True
        )
        count_result = await db.execute(count_query)
        sources_count = count_result.scalar()

        response.append(RSSCategoryResponse(
            id=str(cat.id),
            name=cat.name,
            description=cat.description,
            color=cat.color,
            icon=cat.icon,
            sort_order=cat.sort_order,
            is_active=cat.is_active,
            created_at=cat.created_at,
            updated_at=cat.updated_at,
            sources_count=sources_count
        ))

    return response


@router.post("/categories", response_model=RSSCategoryResponse, status_code=status.HTTP_201_CREATED)
async def create_category(
    category: RSSCategoryCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Create new RSS category (admin only)"""
    db_category = RSSCategory(**category.dict())
    db.add(db_category)
    await db.commit()
    await db.refresh(db_category)

    return RSSCategoryResponse(
        id=str(db_category.id),
        name=db_category.name,
        description=db_category.description,
        color=db_category.color,
        icon=db_category.icon,
        sort_order=db_category.sort_order,
        is_active=db_category.is_active,
        created_at=db_category.created_at,
        updated_at=db_category.updated_at,
        sources_count=0
    )


@router.put("/categories/{category_id}", response_model=RSSCategoryResponse)
async def update_category(
    category_id: str,
    updates: RSSCategoryUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Update RSS category (admin only)"""
    result = await db.execute(select(RSSCategory).where(RSSCategory.id == category_id))
    category = result.scalar_one_or_none()

    if not category:
        raise HTTPException(status_code=404, detail="Category not found")

    # Update fields
    update_data = updates.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(category, key, value)

    await db.commit()
    await db.refresh(category)

    # Get sources count
    count_query = select(func.count(RSSSource.id)).where(RSSSource.category_id == category.id)
    count_result = await db.execute(count_query)
    sources_count = count_result.scalar()

    return RSSCategoryResponse(
        id=str(category.id),
        name=category.name,
        description=category.description,
        color=category.color,
        icon=category.icon,
        sort_order=category.sort_order,
        is_active=category.is_active,
        created_at=category.created_at,
        updated_at=category.updated_at,
        sources_count=sources_count
    )


@router.delete("/categories/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_category(
    category_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Delete RSS category (admin only) - will cascade delete sources"""
    result = await db.execute(select(RSSCategory).where(RSSCategory.id == category_id))
    category = result.scalar_one_or_none()

    if not category:
        raise HTTPException(status_code=404, detail="Category not found")

    await db.delete(category)
    await db.commit()


# ==================== Sources ====================

@router.get("/sources", response_model=List[RSSSourceResponse])
async def list_sources(
    category_id: Optional[str] = None,
    active_only: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List all RSS sources"""
    query = select(RSSSource, RSSCategory.name).join(
        RSSCategory, RSSSource.category_id == RSSCategory.id
    )

    filters = []
    if category_id:
        filters.append(RSSSource.category_id == category_id)
    if active_only:
        filters.append(RSSSource.is_active == True)

    if filters:
        query = query.where(and_(*filters))

    query = query.order_by(RSSCategory.name, RSSSource.name)

    result = await db.execute(query)
    sources_with_categories = result.all()

    return [
        RSSSourceResponse(
            id=str(source.id),
            name=source.name,
            url=source.url,
            category_id=str(source.category_id),
            category_name=category_name,
            refresh_interval_hours=source.refresh_interval_hours,
            is_active=source.is_active,
            description=source.description,
            feed_title=source.feed_title,
            feed_link=source.feed_link,
            last_collected_at=source.last_collected_at,
            last_collection_status=source.last_collection_status,
            last_error_message=source.last_error_message,
            total_articles_collected=source.total_articles_collected,
            extra_config=source.extra_config,
            created_at=source.created_at,
            updated_at=source.updated_at,
        )
        for source, category_name in sources_with_categories
    ]


@router.post("/sources", response_model=RSSSourceResponse, status_code=status.HTTP_201_CREATED)
async def create_source(
    source: RSSSourceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin", "power"))
):
    """Create new RSS source (admin/power users)"""
    # Verify category exists
    cat_result = await db.execute(select(RSSCategory).where(RSSCategory.id == source.category_id))
    category = cat_result.scalar_one_or_none()

    if not category:
        raise HTTPException(status_code=404, detail="Category not found")

    # Create source
    db_source = RSSSource(
        **source.dict(exclude={'created_by'}),
        created_by=current_user.get('id')
    )
    db.add(db_source)
    await db.commit()
    await db.refresh(db_source)

    return RSSSourceResponse(
        id=str(db_source.id),
        name=db_source.name,
        url=db_source.url,
        category_id=str(db_source.category_id),
        category_name=category.name,
        refresh_interval_hours=db_source.refresh_interval_hours,
        is_active=db_source.is_active,
        description=db_source.description,
        feed_title=db_source.feed_title,
        feed_link=db_source.feed_link,
        last_collected_at=db_source.last_collected_at,
        last_collection_status=db_source.last_collection_status,
        last_error_message=db_source.last_error_message,
        total_articles_collected=db_source.total_articles_collected,
        extra_config=db_source.extra_config,
        created_at=db_source.created_at,
        updated_at=db_source.updated_at,
    )


@router.put("/sources/{source_id}", response_model=RSSSourceResponse)
async def update_source(
    source_id: str,
    updates: RSSSourceUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin", "power"))
):
    """Update RSS source (admin/power users)"""
    result = await db.execute(select(RSSSource).where(RSSSource.id == source_id))
    source = result.scalar_one_or_none()

    if not source:
        raise HTTPException(status_code=404, detail="Source not found")

    # Update fields
    update_data = updates.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(source, key, value)

    await db.commit()
    await db.refresh(source)

    # Get category name
    cat_result = await db.execute(select(RSSCategory).where(RSSCategory.id == source.category_id))
    category = cat_result.scalar_one()

    return RSSSourceResponse(
        id=str(source.id),
        name=source.name,
        url=source.url,
        category_id=str(source.category_id),
        category_name=category.name,
        refresh_interval_hours=source.refresh_interval_hours,
        is_active=source.is_active,
        description=source.description,
        feed_title=source.feed_title,
        feed_link=source.feed_link,
        last_collected_at=source.last_collected_at,
        last_collection_status=source.last_collection_status,
        last_error_message=source.last_error_message,
        total_articles_collected=source.total_articles_collected,
        extra_config=source.extra_config,
        created_at=source.created_at,
        updated_at=source.updated_at,
    )


@router.delete("/sources/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_source(
    source_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin", "power"))
):
    """Delete RSS source (admin/power users)"""
    result = await db.execute(select(RSSSource).where(RSSSource.id == source_id))
    source = result.scalar_one_or_none()

    if not source:
        raise HTTPException(status_code=404, detail="Source not found")

    await db.delete(source)
    await db.commit()


# ==================== Collection ====================

@router.post("/collect", response_model=RSSCollectResponse)
async def trigger_collection(
    request: RSSCollectRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Trigger manual RSS collection (public endpoint for Sync Now button)"""
    from app.tasks.rss_tasks import collect_specific_sources, collect_category

    # Determine what to collect
    if request.source_ids:
        # Collect specific sources
        task = collect_specific_sources.delay(
            source_ids=request.source_ids,
            triggered_by="manual",
            executed_by=None  # Anonymous sync from frontend
        )
        message = f"Collection queued for {len(request.source_ids)} sources"

    elif request.category_ids:
        # Collect all sources in categories
        task = collect_category.delay(
            category_ids=request.category_ids,
            triggered_by="manual"
        )
        message = f"Collection queued for {len(request.category_ids)} categories"

    else:
        # Collect all active sources
        from app.tasks.rss_tasks import collect_all_rss_feeds
        task = collect_all_rss_feeds.delay()
        message = "Collection queued for all active sources"

    return RSSCollectResponse(
        task_id=task.id,
        sources_queued=-1,  # Unknown until task runs
        message=message
    )


@router.get("/collection-runs", response_model=List[RSSCollectionRunResponse])
async def list_collection_runs(
    source_id: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List collection run history"""
    query = select(RSSCollectionRun, RSSSource.name).join(
        RSSSource, RSSCollectionRun.source_id == RSSSource.id
    )

    if source_id:
        query = query.where(RSSCollectionRun.source_id == source_id)

    query = query.order_by(RSSCollectionRun.started_at.desc()).limit(limit)

    result = await db.execute(query)
    runs_with_sources = result.all()

    return [
        RSSCollectionRunResponse(
            id=str(run.id),
            source_id=str(run.source_id),
            source_name=source_name,
            started_at=run.started_at,
            finished_at=run.finished_at,
            duration_seconds=run.duration_seconds,
            status=run.status,
            articles_found=run.articles_found,
            articles_new=run.articles_new,
            articles_duplicate=run.articles_duplicate,
            error_message=run.error_message,
            triggered_by=run.triggered_by,
            feed_metadata=run.feed_metadata,
        )
        for run, source_name in runs_with_sources
    ]


# ==================== Articles Search ====================

@router.post("/articles/search", response_model=RSSArticleSearchResponse)
async def search_articles(
    request: RSSArticleSearchRequest,
    es_client = Depends(get_sync_es_dependency)
):
    """Search RSS articles with filters and facets (public endpoint)"""
    # Get settings for index alias
    # (For simplicity, using default for now)
    es_service = RSSElasticsearchService(es_client, "rss-articles")

    # Run sync ES operation in thread pool to avoid blocking event loop
    result = await asyncio.to_thread(
        es_service.search_articles,
        query=request.query,
        categories=request.categories,
        feed_names=request.feed_names,
        tags=request.tags,
        date_from=request.date_from,
        date_to=request.date_to,
        sentiment=request.sentiment,
        limit=request.limit,
        offset=request.offset,
        sort_by=request.sort_by,
        sort_order=request.sort_order,
    )

    from app.schemas.rss import RSSArticle

    return RSSArticleSearchResponse(
        total=result['total'],
        articles=[RSSArticle(**art) for art in result['articles']],
        facets=result.get('facets'),
        took_ms=result.get('took_ms', 0),
    )


# ==================== Stats ====================

@router.get("/stats", response_model=RSSStatsResponse)
async def get_rss_stats(
    db: AsyncSession = Depends(get_db),
    es_client = Depends(get_sync_es_dependency)
):
    """Get global RSS statistics for dashboard (public endpoint)"""
    # PostgreSQL stats
    total_sources = await db.scalar(select(func.count(RSSSource.id)))
    active_sources = await db.scalar(
        select(func.count(RSSSource.id)).where(RSSSource.is_active == True)
    )
    total_categories = await db.scalar(select(func.count(RSSCategory.id)))

    # Last collection time
    last_run_result = await db.execute(
        select(RSSCollectionRun.finished_at)
        .where(RSSCollectionRun.status == "success")
        .order_by(RSSCollectionRun.finished_at.desc())
        .limit(1)
    )
    last_collection_at = last_run_result.scalar_one_or_none()

    # Failed collections today
    from datetime import datetime, timezone
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    failed_today = await db.scalar(
        select(func.count(RSSCollectionRun.id))
        .where(
            RSSCollectionRun.status == "error",
            RSSCollectionRun.started_at >= today_start
        )
    )

    # Average collection duration
    avg_duration_result = await db.execute(
        select(func.avg(RSSCollectionRun.duration_seconds))
        .where(RSSCollectionRun.status == "success")
    )
    avg_duration = avg_duration_result.scalar_one_or_none()

    # Elasticsearch stats (all data from ES)
    es_service = RSSElasticsearchService(es_client, "rss-articles")
    # Run sync ES operation in thread pool
    es_stats = await asyncio.to_thread(es_service.get_stats)

    return RSSStatsResponse(
        total_sources=total_sources or 0,
        active_sources=active_sources or 0,
        total_categories=total_categories or 0,
        total_articles=es_stats.get('total_articles', 0),
        articles_today=es_stats.get('articles_today', 0),
        articles_this_week=es_stats.get('articles_this_week', 0),
        articles_this_month=es_stats.get('articles_this_month', 0),
        last_collection_at=last_collection_at,
        top_sources=es_stats.get('top_sources', []),
        all_sources=es_stats.get('all_sources', []),
        articles_by_category=es_stats.get('articles_by_category', {}),
        timeline=es_stats.get('timeline', []),
        failed_collections_today=failed_today or 0,
        avg_collection_duration_seconds=float(avg_duration) if avg_duration else None,
    )


# ==================== Settings ====================

@router.get("/settings", response_model=RSSSettingsResponse)
async def get_settings(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Get RSS settings (admin only)"""
    result = await db.execute(select(RSSSettings))
    settings = result.scalar_one_or_none()

    if not settings:
        raise HTTPException(status_code=404, detail="Settings not found")

    return RSSSettingsResponse(
        id=str(settings.id),
        scheduler_enabled=settings.scheduler_enabled,
        default_refresh_interval_hours=settings.default_refresh_interval_hours,
        scheduler_cron=settings.scheduler_cron,
        max_articles_per_feed=settings.max_articles_per_feed,
        days_to_keep_articles=settings.days_to_keep_articles,
        enable_deduplication=settings.enable_deduplication,
        enable_nlp_enrichment=settings.enable_nlp_enrichment,
        es_index_alias=settings.es_index_alias,
        notify_on_errors=settings.notify_on_errors,
        notification_webhook=settings.notification_webhook,
        updated_at=settings.updated_at,
    )


@router.put("/settings", response_model=RSSSettingsResponse)
async def update_settings(
    updates: RSSSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Update RSS settings (admin only)"""
    result = await db.execute(select(RSSSettings))
    settings = result.scalar_one_or_none()

    if not settings:
        raise HTTPException(status_code=404, detail="Settings not found")

    # Update fields
    update_data = updates.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(settings, key, value)

    settings.updated_by = current_user.get('id')

    await db.commit()
    await db.refresh(settings)

    return RSSSettingsResponse(
        id=str(settings.id),
        scheduler_enabled=settings.scheduler_enabled,
        default_refresh_interval_hours=settings.default_refresh_interval_hours,
        scheduler_cron=settings.scheduler_cron,
        max_articles_per_feed=settings.max_articles_per_feed,
        days_to_keep_articles=settings.days_to_keep_articles,
        enable_deduplication=settings.enable_deduplication,
        enable_nlp_enrichment=settings.enable_nlp_enrichment,
        es_index_alias=settings.es_index_alias,
        notify_on_errors=settings.notify_on_errors,
        notification_webhook=settings.notification_webhook,
        updated_at=settings.updated_at,
    )


# ==================== Elasticsearch Setup ====================

@router.post("/setup-elasticsearch", status_code=status.HTTP_200_OK)
async def setup_elasticsearch(
    es_client = Depends(get_sync_es_dependency),
    current_user: dict = Depends(require_role("admin"))
):
    """Setup Elasticsearch (ILM + Template + Index) - admin only"""
    es_service = RSSElasticsearchService(es_client, "rss-articles")
    # Run sync ES operation in thread pool
    result = await asyncio.to_thread(
        es_service.setup,
        rollover_days=30,
        delete_days=180,
        shards=1,
        replicas=1
    )

    if result.get('errors'):
        raise HTTPException(status_code=500, detail={"errors": result['errors']})

    return {
        "message": "Elasticsearch setup completed",
        "ilm_created": result['ilm_created'],
        "template_created": result['template_created'],
        "index_created": result['index_created'],
    }


# ==================== Chat with RAG ====================

@router.post("/rss/chat", response_model=RSSChatResponse)
async def chat_with_articles(
    request: RSSChatRequest,
    es_client = Depends(get_es_client),
    current_user: dict = Depends(get_current_user)
):
    """
    Chat with LLM about RSS articles using RAG

    Retrieves relevant articles from Elasticsearch and generates contextual answers
    using the configured LLM provider.
    """
    from app.services.rss_chat import RSSChatService
    from app.services.llm_service_v2 import get_llm_service

    try:
        # Get LLM service
        llm_service = await get_llm_service()

        # Create chat service
        chat_service = RSSChatService(es_client, llm_service, "rss-articles")

        # Generate response
        response = await chat_service.chat(request)

        logger.info(f"💬 Chat completed: {request.query[:50]}... → {response.context_used} articles used")

        return response

    except Exception as e:
        logger.error(f"❌ Chat error: {e}")
        raise HTTPException(status_code=500, detail=f"Chat error: {str(e)}")


@router.post("/rss/summary")
async def generate_summary(
    category: Optional[str] = None,
    days: int = Query(7, ge=1, le=30),
    max_articles: int = Query(20, ge=5, le=100),
    es_client = Depends(get_es_client),
    current_user: dict = Depends(get_current_user)
):
    """
    Generate automatic summary of recent RSS articles

    Useful for daily briefings or category overviews.
    """
    from app.services.rss_chat import RSSChatService
    from app.services.llm_service_v2 import get_llm_service

    try:
        # Get LLM service
        llm_service = await get_llm_service()

        # Create chat service
        chat_service = RSSChatService(es_client, llm_service, "rss-articles")

        # Generate summary
        summary = await chat_service.generate_summary(
            category=category,
            days=days,
            max_articles=max_articles
        )

        category_str = f" ({category})" if category else ""
        logger.info(f"📊 Summary generated: Last {days} days{category_str}")

        return {
            "summary": summary,
            "category": category,
            "days": days,
            "max_articles": max_articles
        }

    except Exception as e:
        logger.error(f"❌ Summary generation error: {e}")
        raise HTTPException(status_code=500, detail=f"Summary error: {str(e)}")


@router.post("/chat", response_model=RSSChatResponse)
async def chat_with_rss(
    chat_request: RSSChatRequest,
    es_client = Depends(get_sync_es_dependency),  # Changed to sync client
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Chat with RSS articles using RAG (Retrieval Augmented Generation)

    Request body:
    {
        "query": "What are the latest AI news?",
        "category": "Inteligência Artificial",  // optional
        "days": 7  // optional, default 7
    }
    """
    from app.services.rss_chat import RSSChatService
    from app.services.llm_service_v2 import get_llm_service_v2

    try:
        # Get LLM service
        llm_service = get_llm_service_v2(db)

        # Initialize LLM client (async operation)
        await llm_service._initialize_client()

        # Create chat service
        chat_service = RSSChatService(es_client, llm_service, "rss-articles")

        # Generate response using the proper request object
        response = await chat_service.chat(chat_request)

        logger.info(f"💬 RSS Chat: {chat_request.query[:50]}... -> {len(response.answer)} chars")

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ RSS chat error: {e}")
        raise HTTPException(status_code=500, detail=f"Chat error: {str(e)}")


# ==================== Malpedia BibTeX ====================

@router.post("/malpedia/import")
async def import_malpedia_file(
    file_path: str = Query(..., description="Path to malpedia.bib file"),
    batch_size: int = Query(1000, description="Batch size for indexing"),
    es_client = Depends(get_sync_es_dependency),
    current_user: dict = Depends(require_role("admin"))
):
    """
    Import Malpedia BibTeX from local file (admin only)

    Example: POST /api/v1/rss/malpedia/import?file_path=/Users/user/malpedia.bib
    """
    try:
        collector = MalpediaCollectorService(es_client, "rss-articles")
        result = collector.import_from_file(file_path, batch_size)

        logger.info(f"Malpedia import: {result.get('status')} | {result.get('entries_new', 0)} new entries")

        return result

    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"❌ Malpedia import error: {e}")
        raise HTTPException(status_code=500, detail=f"Import error: {str(e)}")


@router.post("/malpedia/import-url")
async def import_malpedia_url(
    url: str = Query(
        "https://malpedia.caad.fkie.fraunhofer.de/library/download",
        description="URL to download malpedia.bib"
    ),
    download_path: str = Query("/tmp/malpedia.bib", description="Temporary download path"),
    batch_size: int = Query(1000, description="Batch size for indexing"),
    es_client = Depends(get_sync_es_dependency),
    current_user: dict = Depends(require_role("admin"))
):
    """
    Download and import Malpedia BibTeX from URL (admin only)

    Default URL: https://malpedia.caad.fkie.fraunhofer.de/library/download
    """
    try:
        collector = MalpediaCollectorService(es_client, "rss-articles")
        result = collector.import_from_url(url, download_path, batch_size)

        logger.info(f"Malpedia URL import: {result.get('status')} | {result.get('entries_new', 0)} new entries")

        return result

    except Exception as e:
        logger.error(f"❌ Malpedia URL import error: {e}")
        raise HTTPException(status_code=500, detail=f"Import error: {str(e)}")


@router.get("/malpedia/stats")
async def get_malpedia_stats(
    es_client = Depends(get_sync_es_dependency),
    current_user: dict = Depends(get_current_user)
):
    """Get Malpedia statistics from Elasticsearch"""
    try:
        collector = MalpediaCollectorService(es_client, "rss-articles")
        stats = collector.get_stats()

        logger.info(f"Malpedia stats: {stats.get('total_entries', 0)} total entries")

        return stats

    except Exception as e:
        logger.error(f"❌ Malpedia stats error: {e}")
        raise HTTPException(status_code=500, detail=f"Stats error: {str(e)}")
