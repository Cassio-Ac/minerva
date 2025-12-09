"""
Dashboards API Endpoints
CRUD operations for dashboards
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
import logging

from app.models.dashboard import Dashboard, DashboardListItem
from app.schemas.dashboard import DashboardCreate, DashboardUpdate
from app.services.dashboard_service import get_dashboard_service

router = APIRouter()
logger = logging.getLogger(__name__)
dashboard_service = get_dashboard_service()


@router.post("/", response_model=Dashboard, status_code=201)
async def create_dashboard(dashboard: DashboardCreate):
    """
    Cria um novo dashboard

    - **title**: Nome do dashboard (obrigatório)
    - **description**: Descrição opcional
    - **index**: Índice Elasticsearch
    - **widgets**: Lista de widgets (opcional)
    """
    logger.info(f"Creating dashboard: {dashboard.title}")

    try:
        new_dashboard = await dashboard_service.create(dashboard)
        return new_dashboard
    except Exception as e:
        logger.error(f"Error creating dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=List[DashboardListItem])
async def list_dashboards(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Max number of records"),
    index: Optional[str] = Query(None, description="Filter by ES index"),
    tags: Optional[str] = Query(None, description="Filter by tags (comma-separated)")
):
    """
    Lista todos os dashboards

    Suporta paginação e filtros:
    - **skip**: Número de registros para pular
    - **limit**: Número máximo de registros
    - **index**: Filtrar por índice Elasticsearch
    - **tags**: Filtrar por tags (separadas por vírgula)
    """
    logger.info(f"Listing dashboards (skip={skip}, limit={limit})")

    try:
        tags_list = tags.split(",") if tags else None
        dashboards = await dashboard_service.list(
            skip=skip,
            limit=limit,
            index=index,
            tags=tags_list
        )
        return dashboards
    except Exception as e:
        logger.error(f"Error listing dashboards: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{dashboard_id}", response_model=Dashboard)
async def get_dashboard(dashboard_id: str):
    """
    Obtém um dashboard específico pelo ID

    - **dashboard_id**: UUID do dashboard
    """
    logger.info(f"Getting dashboard: {dashboard_id}")

    dashboard = await dashboard_service.get(dashboard_id)
    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")

    return dashboard


@router.patch("/{dashboard_id}", response_model=Dashboard)
async def update_dashboard(dashboard_id: str, updates: DashboardUpdate):
    """
    Atualiza um dashboard existente

    - **dashboard_id**: UUID do dashboard
    - **updates**: Campos a atualizar (parcial)
    """
    logger.info(f"Updating dashboard: {dashboard_id}")

    dashboard = await dashboard_service.update(dashboard_id, updates)
    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")

    # Broadcast de posições atualizadas (se houver widgets)
    if updates.widgets is not None and len(updates.widgets) > 0:
        from app.websocket import broadcast_positions_updated

        # Extrair posições dos widgets
        positions = {w["id"]: w["position"] for w in updates.widgets if "id" in w and "position" in w}

        if positions:
            await broadcast_positions_updated(dashboard_id, positions)

    logger.info(f"✅ Dashboard {dashboard_id} updated (v{dashboard.metadata.version})")
    return dashboard


@router.delete("/{dashboard_id}", status_code=204)
async def delete_dashboard(dashboard_id: str):
    """
    Deleta um dashboard

    - **dashboard_id**: UUID do dashboard
    """
    logger.info(f"Deleting dashboard: {dashboard_id}")

    success = await dashboard_service.delete(dashboard_id)
    if not success:
        raise HTTPException(status_code=404, detail="Dashboard not found")

    return None


@router.post("/{dashboard_id}/duplicate", response_model=Dashboard, status_code=201)
async def duplicate_dashboard(dashboard_id: str, new_title: Optional[str] = None):
    """
    Duplica um dashboard existente

    - **dashboard_id**: UUID do dashboard a duplicar
    - **new_title**: Novo título (opcional)
    """
    logger.info(f"Duplicating dashboard: {dashboard_id}")

    # TODO: Implementar duplicação
    # original = await elasticsearch_service.get_dashboard(dashboard_id)
    # if not original:
    #     raise HTTPException(status_code=404, detail="Dashboard not found")

    # duplicate = original.copy()
    # duplicate.id = str(uuid4())
    # duplicate.title = new_title or f"{original.title} (Copy)"
    # await elasticsearch_service.save_dashboard(duplicate)

    raise HTTPException(status_code=501, detail="Not implemented yet")
