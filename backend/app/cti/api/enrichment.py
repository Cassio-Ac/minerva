"""
CTI Enrichment Management API

Endpoints para gerenciar o cache de enrichment:
- Visualizar estatísticas do cache
- Forçar re-enrichment de actors específicos
- Executar enrichment em batch de todos os actors
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional
import logging

from app.api.v1.auth import get_current_user
from ..services.enrichment_cache_service import get_enrichment_cache_service
# from ..services.misp_galaxy_service import get_misp_galaxy_service  # TODO: Update to use new MISPGalaxyService class

router = APIRouter(prefix="/enrichment", tags=["CTI Enrichment"])
logger = logging.getLogger(__name__)


# ==================== SCHEMAS ====================

class EnrichActorRequest(BaseModel):
    """Request to enrich specific actors"""
    actors: List[str]
    force: bool = False  # Force re-enrichment even if cached


class EnrichActorResponse(BaseModel):
    """Response with enrichment results"""
    actor: str
    techniques_count: int
    techniques: List[str]
    from_cache: bool


class BatchEnrichmentResponse(BaseModel):
    """Response for batch enrichment"""
    status: str
    message: str
    job_id: Optional[str] = None


class CacheStatsResponse(BaseModel):
    """Cache statistics"""
    index_exists: bool
    total_cached: int
    recent_enrichments: Optional[List[dict]] = None


class ActorGeopoliticalData(BaseModel):
    """Geopolitical data from MISP Galaxy"""
    found: bool
    country: Optional[str] = None
    state_sponsor: Optional[str] = None
    military_unit: Optional[str] = None
    targeted_countries: List[str] = []
    targeted_sectors: List[str] = []
    incident_type: Optional[str] = None
    attribution_confidence: Optional[str] = None
    additional_aliases: List[str] = []
    misp_refs: List[str] = []
    description: Optional[str] = None


# ==================== ENDPOINTS ====================

@router.get("/cache/stats", response_model=CacheStatsResponse)
async def get_cache_stats(
    current_user: dict = Depends(get_current_user)
):
    """
    Get cache statistics

    Returns information about:
    - Total actors cached
    - Recent enrichments
    - Cache health
    """
    try:
        cache_service = get_enrichment_cache_service()
        stats = await cache_service.get_cache_stats()
        return stats

    except Exception as e:
        logger.error(f"❌ Error getting cache stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting cache stats: {str(e)}"
        )


@router.post("/enrich", response_model=List[EnrichActorResponse])
async def enrich_actors(
    request: EnrichActorRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Enrich specific actors

    - **actors**: List of actor names to enrich
    - **force**: If True, bypass cache and force fresh enrichment

    Returns enrichment results for each actor
    """
    try:
        cache_service = get_enrichment_cache_service()
        results = []

        for actor_name in request.actors:
            logger.info(f"🔨 Enriching actor: {actor_name} (force={request.force})")

            # Check cache first (unless force=True)
            # Use a very long max_age to avoid cache expiration (30 days)
            from_cache = False
            if not request.force:
                cached = await cache_service.get_cached_techniques(actor_name, max_age_hours=720)
                if cached is not None:
                    results.append(EnrichActorResponse(
                        actor=actor_name,
                        techniques_count=len(cached),
                        techniques=cached,
                        from_cache=True
                    ))
                    continue

            # Perform enrichment
            techniques = await cache_service.enrich_and_cache_actor(actor_name)

            results.append(EnrichActorResponse(
                actor=actor_name,
                techniques_count=len(techniques),
                techniques=techniques,
                from_cache=False
            ))

        return results

    except Exception as e:
        logger.error(f"❌ Error enriching actors: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error enriching actors: {str(e)}"
        )


@router.post("/batch/enrich-all", response_model=BatchEnrichmentResponse)
async def batch_enrich_all_actors(
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Enrich ALL actors in batch (background task)

    This will:
    1. Get all actors from Malpedia
    2. Enrich each actor
    3. Save to cache

    **Note**: This runs in the background and may take several minutes.

    Requires: Admin role
    """
    # Check if user is admin
    if current_user.get('role') != 'admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can trigger batch enrichment"
        )

    try:
        cache_service = get_enrichment_cache_service()

        # Add to background tasks
        background_tasks.add_task(cache_service.enrich_and_cache_all_actors)

        logger.info(f"🚀 Batch enrichment started by {current_user.get('username')}")

        return BatchEnrichmentResponse(
            status="started",
            message="Batch enrichment started in background. Check cache stats for progress."
        )

    except Exception as e:
        logger.error(f"❌ Error starting batch enrichment: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error starting batch enrichment: {str(e)}"
        )


@router.delete("/cache/clear")
async def clear_cache(
    current_user: dict = Depends(get_current_user)
):
    """
    Clear enrichment cache

    **Warning**: This will delete all cached enrichments.

    Requires: Admin role
    """
    # Check if user is admin
    if current_user.get('role') != 'admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can clear cache"
        )

    try:
        from app.db.elasticsearch import get_es_client
        es = await get_es_client()

        # Delete index
        INDEX_NAME = "cti_enrichment_cache"
        exists = await es.indices.exists(index=INDEX_NAME)

        if exists:
            await es.indices.delete(index=INDEX_NAME)
            logger.info(f"🗑️  Cache cleared by {current_user.get('username')}")
            return {"status": "success", "message": "Cache cleared successfully"}
        else:
            return {"status": "success", "message": "Cache was already empty"}

    except Exception as e:
        logger.error(f"❌ Error clearing cache: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error clearing cache: {str(e)}"
        )


# TODO: Restore geopolitical endpoint with new MISPGalaxyService implementation
# @router.get("/geopolitical/{actor_name}", response_model=ActorGeopoliticalData)
# async def get_actor_geopolitical_data(
#     actor_name: str,
#     current_user: dict = Depends(get_current_user)
# ):
#     """
#     Get geopolitical data for a threat actor from MISP Galaxy
#
#     Returns:
#     - Country of origin
#     - State sponsor
#     - Military unit (if applicable)
#     - Targeted countries
#     - Targeted sectors
#     - Incident type
#     - Attribution confidence
#     - Additional aliases
#     - MISP references
#
#     Example: /api/v1/cti/enrichment/geopolitical/APT28
#     """
#     try:
#         misp_service = get_misp_galaxy_service()
#         data = misp_service.enrich_actor(actor_name)
#
#         logger.info(f"📍 Geopolitical data for {actor_name}: {data.get('country', 'N/A')}")
#
#         return ActorGeopoliticalData(**data)
#
#     except Exception as e:
#         logger.error(f"❌ Error getting geopolitical data: {e}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Error getting geopolitical data: {str(e)}"
#         )
