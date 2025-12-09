"""
CVE (Common Vulnerabilities and Exposures) API Endpoints
"""
import asyncio
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.elasticsearch import get_sync_es_dependency
from app.core.dependencies import get_current_user
from app.models.user import User
from app.schemas.cve import (
    CVESearchRequest,
    CVESearchResponse,
    CVEStats,
    CVEChatRequest,
    CVEChatResponse,
)
from app.services.cve_search import CVESearchService
from app.services.cve_chat import CVEChatService
from app.services.llm_service_v2 import LLMServiceV2

router = APIRouter(prefix="/cves", tags=["CVEs"])


@router.post("/search", response_model=CVESearchResponse)
async def search_cves(
    request: CVESearchRequest,
    es_client = Depends(get_sync_es_dependency),
):
    """
    Search CVEs with filters

    This endpoint is PUBLIC - no authentication required
    """
    try:
        search_service = CVESearchService(es_client)

        # Run sync ES operation in thread pool
        result = await asyncio.to_thread(
            search_service.search_cves,
            query=request.query,
            sources=request.sources,
            types=request.types,
            severity_levels=request.severity_levels,
            date_from=request.date_from,
            date_to=request.date_to,
            limit=request.limit,
            offset=request.offset,
            sort_by=request.sort_by,
            sort_order=request.sort_order,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error searching CVEs: {str(e)}")


@router.get("/stats", response_model=CVEStats)
async def get_cve_stats(
    es_client = Depends(get_sync_es_dependency),
):
    """
    Get CVE statistics

    This endpoint is PUBLIC - no authentication required
    """
    try:
        search_service = CVESearchService(es_client)

        # Run sync ES operation in thread pool
        stats = await asyncio.to_thread(search_service.get_stats)
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting CVE stats: {str(e)}")


@router.post("/chat", response_model=CVEChatResponse)
async def chat_with_cves(
    chat_request: CVEChatRequest,
    es_client = Depends(get_sync_es_dependency),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Chat with CVEs using RAG

    This endpoint requires authentication
    """
    # Check if user has LLM permissions
    if not current_user.can_use_llm:
        raise HTTPException(
            status_code=403,
            detail="User does not have permission to use LLM features"
        )

    try:
        # Initialize LLM service
        llm_service = LLMServiceV2(db)
        await llm_service.initialize()

        # Initialize chat service
        chat_service = CVEChatService(es_client, llm_service)

        # Generate response
        response = await chat_service.chat(chat_request)

        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error in CVE chat: {str(e)}")
