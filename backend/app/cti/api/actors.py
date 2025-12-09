"""
CTI Actors API - Threat Actor endpoints

Endpoints completamente isolados do resto da aplicação.
Prefix: /api/v1/cti/actors
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query

from app.core.dependencies import get_current_user
from app.cti.services.malpedia_service import get_malpedia_service
from app.cti.schemas.actor import ActorListResponse, ActorDetailResponse

logger = logging.getLogger(__name__)

# Router isolado para CTI Actors
router = APIRouter(prefix="/actors", tags=["CTI - Actors"])


@router.get("", response_model=ActorListResponse)
async def list_actors(
    search: Optional[str] = Query(None, description="Search query"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    server_id: Optional[str] = Query(None, description="ES server ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    List threat actors

    - **search**: Search in name, aliases, description
    - **page**: Page number (1-indexed)
    - **page_size**: Items per page (max 100)
    - **server_id**: Optional ES server ID

    Returns list of actors sorted by name.
    """
    try:
        service = get_malpedia_service(server_id=server_id)
        result = await service.get_actors(
            search=search,
            page=page,
            page_size=page_size
        )

        return ActorListResponse(
            total=result["total"],
            actors=result["actors"],
            page=result["page"],
            page_size=result["page_size"]
        )

    except Exception as e:
        logger.error(f"❌ Error listing actors: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing actors: {str(e)}"
        )


@router.get("/{actor_name}", response_model=ActorDetailResponse)
async def get_actor_detail(
    actor_name: str,
    server_id: Optional[str] = Query(None, description="ES server ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get detailed information about a specific actor

    - **actor_name**: Actor name (case-sensitive)
    - **server_id**: Optional ES server ID

    Returns actor details with:
    - Basic info (name, aliases, description)
    - Related malware families
    - References
    - Statistics (total families, techniques)
    """
    try:
        service = get_malpedia_service(server_id=server_id)

        # Get actor
        actor = await service.get_actor_by_name(actor_name)
        if not actor:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Actor not found: {actor_name}"
            )

        # Get related families
        families = actor.get("familias_relacionadas", [])
        total_families = len(families) if families else 0

        # TODO: Get techniques when ATT&CK enrichment is implemented
        total_techniques = 0
        techniques = []

        return ActorDetailResponse(
            name=actor["name"],
            aka=actor.get("aka"),
            explicacao=actor.get("explicacao"),
            familias_relacionadas=families,
            url=actor.get("url"),
            referencias=actor.get("referencias"),
            total_families=total_families,
            total_techniques=total_techniques,
            techniques=techniques
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error getting actor {actor_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting actor: {str(e)}"
        )


@router.get("/meta/countries")
async def get_actor_countries(
    server_id: Optional[str] = Query(None, description="ES server ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get list of all unique countries from threat actors

    - **server_id**: Optional ES server ID

    Returns list of country names sorted alphabetically.
    """
    try:
        service = get_malpedia_service(server_id=server_id)

        # Get all actors
        result = await service.get_actors(page=1, page_size=1000)
        actors = result.get("actors", [])

        # Extract unique countries
        countries = set()
        for actor in actors:
            country = actor.get("country")
            if country:
                countries.add(country)

        return {
            "countries": sorted(list(countries))
        }

    except Exception as e:
        logger.error(f"❌ Error getting actor countries: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting actor countries: {str(e)}"
        )


@router.get("/{actor_name}/families")
async def get_actor_families(
    actor_name: str,
    server_id: Optional[str] = Query(None, description="ES server ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get list of malware families associated with an actor

    - **actor_name**: Actor name
    - **server_id**: Optional ES server ID

    Returns list of family names.
    """
    try:
        service = get_malpedia_service(server_id=server_id)

        # Get families
        families = await service.get_actor_families(actor_name)

        return {
            "actor": actor_name,
            "total": len(families),
            "families": families
        }

    except Exception as e:
        logger.error(f"❌ Error getting families for actor {actor_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting families: {str(e)}"
        )
