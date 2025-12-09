"""
CPF (Cadastro de Pessoas Físicas) API Endpoints
"""
import asyncio
from fastapi import APIRouter, Depends, HTTPException

from app.db.elasticsearch import get_sync_es_dependency
from app.schemas.cpf import (
    CPFSearchRequest,
    CPFSearchResponse,
    CPFStats,
    CPFEntry,
)
from app.services.cpf_search import CPFSearchService

router = APIRouter(prefix="/cpf", tags=["CPF"])


@router.post("/search", response_model=CPFSearchResponse)
async def search_cpf(
    request: CPFSearchRequest,
    es_client=Depends(get_sync_es_dependency),
):
    """
    Search CPF records with filters

    This endpoint is PUBLIC - no authentication required
    """
    try:
        search_service = CPFSearchService(es_client)

        # Run sync ES operation in thread pool
        result = await asyncio.to_thread(
            search_service.search_cpf,
            query=request.query,
            cpf=request.cpf,
            nome=request.nome,
            sexo=request.sexo,
            nasc_from=request.nasc_from,
            nasc_to=request.nasc_to,
            idade_min=request.idade_min,
            idade_max=request.idade_max,
            limit=request.limit,
            offset=request.offset,
            sort_by=request.sort_by,
            sort_order=request.sort_order,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error searching CPF: {str(e)}")


@router.get("/stats", response_model=CPFStats)
async def get_cpf_stats(
    es_client=Depends(get_sync_es_dependency),
):
    """
    Get CPF statistics

    This endpoint is PUBLIC - no authentication required
    """
    try:
        search_service = CPFSearchService(es_client)

        # Run sync ES operation in thread pool
        stats = await asyncio.to_thread(search_service.get_stats)
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting CPF stats: {str(e)}")


@router.get("/{cpf}", response_model=CPFEntry)
async def get_cpf_by_id(
    cpf: str,
    es_client=Depends(get_sync_es_dependency),
):
    """
    Get a single CPF record by CPF number

    This endpoint is PUBLIC - no authentication required
    """
    try:
        search_service = CPFSearchService(es_client)

        # Run sync ES operation in thread pool
        result = await asyncio.to_thread(search_service.get_by_cpf, cpf)

        if not result:
            raise HTTPException(status_code=404, detail="CPF not found")

        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting CPF: {str(e)}")
