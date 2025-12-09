"""
CTI Families API - Malware Family endpoints

Endpoints completamente isolados do resto da aplicação.
Prefix: /api/v1/cti/families
"""

import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query

from app.core.dependencies import get_current_user
from app.cti.services.malpedia_service import get_malpedia_service
from app.cti.schemas.family import FamilyListResponse, FamilyDetailResponse, FamilyFilterRequest

logger = logging.getLogger(__name__)

# Router isolado para CTI Families
router = APIRouter(prefix="/families", tags=["CTI - Families"])


@router.get("", response_model=FamilyListResponse)
async def list_families(
    search: Optional[str] = Query(None, description="Search query"),
    os_filter: Optional[str] = Query(None, description="Filter by OS (comma-separated)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    server_id: Optional[str] = Query(None, description="ES server ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    List malware families

    - **search**: Search in name, aliases, description
    - **os_filter**: Filter by OS (e.g., "Windows,Linux")
    - **page**: Page number (1-indexed)
    - **page_size**: Items per page (max 100)
    - **server_id**: Optional ES server ID

    Returns list of families sorted by name.
    """
    try:
        # Parse OS filter
        os_list = None
        if os_filter:
            os_list = [os.strip() for os in os_filter.split(",") if os.strip()]

        service = get_malpedia_service(server_id=server_id)
        result = await service.get_families(
            search=search,
            os_filter=os_list,
            page=page,
            page_size=page_size
        )

        return FamilyListResponse(
            total=result["total"],
            families=result["families"],
            page=result["page"],
            page_size=result["page_size"]
        )

    except Exception as e:
        logger.error(f"❌ Error listing families: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing families: {str(e)}"
        )


@router.get("/{family_name}", response_model=FamilyDetailResponse)
async def get_family_detail(
    family_name: str,
    include_yara: bool = Query(False, description="Include YARA rules content"),
    server_id: Optional[str] = Query(None, description="ES server ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get detailed information about a specific malware family

    - **family_name**: Family name (case-sensitive)
    - **include_yara**: Include YARA rule content (can be large)
    - **server_id**: Optional ES server ID

    Returns family details with:
    - Basic info (name, OS, aliases, description)
    - YARA rules (optionally with content)
    - References
    - Actors using this family
    - ATT&CK techniques (when enrichment is available)
    """
    try:
        service = get_malpedia_service(server_id=server_id)

        # Get family
        family = await service.get_family_by_name(family_name, include_yara=include_yara)
        if not family:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Family not found: {family_name}"
            )

        # Get actors using this family
        actors = await service.get_family_actors(family_name)

        # TODO: Get techniques when ATT&CK enrichment is implemented
        techniques = []

        return FamilyDetailResponse(
            name=family["name"],
            os=family.get("os"),
            aka=family.get("aka"),
            descricao=family.get("descricao"),
            url=family.get("url"),
            referencias=family.get("referencias"),
            yara_rules=family.get("yara_rules"),
            actors=actors,
            techniques=techniques
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error getting family {family_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting family: {str(e)}"
        )


@router.get("/{family_name}/actors")
async def get_family_actors(
    family_name: str,
    server_id: Optional[str] = Query(None, description="ES server ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get list of threat actors using this family

    - **family_name**: Family name
    - **server_id**: Optional ES server ID

    Returns list of actor names.
    """
    try:
        service = get_malpedia_service(server_id=server_id)

        # Get actors
        actors = await service.get_family_actors(family_name)

        return {
            "family": family_name,
            "total": len(actors),
            "actors": actors
        }

    except Exception as e:
        logger.error(f"❌ Error getting actors for family {family_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting actors: {str(e)}"
        )


@router.get("/{family_name}/yara")
async def get_family_yara(
    family_name: str,
    server_id: Optional[str] = Query(None, description="ES server ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get YARA rules for a malware family

    - **family_name**: Family name
    - **server_id**: Optional ES server ID

    Returns YARA rules with full content.
    """
    try:
        service = get_malpedia_service(server_id=server_id)

        # Get family with YARA content
        family = await service.get_family_by_name(family_name, include_yara=True)
        if not family:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Family not found: {family_name}"
            )

        yara_rules = family.get("yara_rules", [])
        if not yara_rules:
            logger.warning(f"⚠️ No YARA rules found for family: {family_name}")

        return {
            "family": family_name,
            "total_rules": len(yara_rules),
            "yara_rules": yara_rules
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error getting YARA for family {family_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting YARA rules: {str(e)}"
        )
