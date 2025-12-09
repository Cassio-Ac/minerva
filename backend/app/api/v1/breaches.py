"""
Breach API Endpoints
REST API for data breach and leak detection
"""

import logging
import asyncio
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.elasticsearch import get_sync_es_dependency
from app.schemas.breach import (
    BreachSearchRequest,
    BreachSearchResponse,
    BreachStats,
    BreachChatRequest,
    BreachChatResponse,
    BreachEntry,
    BreachFacets
)
from app.services.breach_search import BreachSearchService
from app.services.breach_chat import BreachChatService
from app.core.dependencies import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/breaches", tags=["Data Breaches"])


@router.post("/search", response_model=BreachSearchResponse)
async def search_breaches(
    request: BreachSearchRequest,
    es_client = Depends(get_sync_es_dependency)
):
    """Search data breaches with filters (public endpoint)"""
    service = BreachSearchService(es_client, "breachdetect_v3")

    # Run sync ES operation in thread pool
    result = await asyncio.to_thread(
        service.search_breaches,
        query=request.query,
        sources=request.sources,
        types=request.types,
        authors=request.authors,
        date_from=request.date_from,
        date_to=request.date_to,
        limit=request.limit,
        offset=request.offset,
        sort_by=request.sort_by,
        sort_order=request.sort_order,
    )

    return BreachSearchResponse(
        total=result['total'],
        breaches=[BreachEntry(**b) for b in result['breaches']],
        facets=BreachFacets(**result.get('facets', {})),
        took_ms=result.get('took_ms', 0),
    )


@router.get("/stats", response_model=BreachStats)
async def get_breach_stats(
    es_client = Depends(get_sync_es_dependency)
):
    """Get global breach statistics (public endpoint)"""
    service = BreachSearchService(es_client, "breachdetect_v3")

    # Run sync ES operation in thread pool
    stats = await asyncio.to_thread(service.get_stats)

    return BreachStats(**stats)


@router.post("/chat", response_model=BreachChatResponse)
async def chat_with_breaches(
    chat_request: BreachChatRequest,
    es_client = Depends(get_sync_es_dependency),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Chat with breach data using RAG

    Request body:
    {
        "query": "What are the latest ransomware attacks?",
        "breach_type": "ransomware",  // optional
        "source": "ransomware.live",  // optional
        "days": 30  // optional, default 30
    }
    """
    from app.services.llm_service_v2 import get_llm_service_v2

    try:
        # Get LLM service
        llm_service = get_llm_service_v2(db)
        await llm_service._initialize_client()

        # Create chat service
        chat_service = BreachChatService(es_client, llm_service, "breachdetect_v3")

        # Generate response
        response = await chat_service.chat(chat_request)

        logger.info(f"💬 Breach Chat: {chat_request.query[:50]}... -> {len(response.answer)} chars")

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Breach chat error: {e}")
        raise HTTPException(status_code=500, detail=f"Chat error: {str(e)}")
