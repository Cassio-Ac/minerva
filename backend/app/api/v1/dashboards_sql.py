"""
Dashboards API Endpoints - SQL Version
CRUD operations for dashboards using PostgreSQL
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import logging

from app.db.database import get_db
from app.models.dashboard import Dashboard, DashboardListItem
from app.schemas.dashboard import DashboardCreate, DashboardUpdate
from app.services.dashboard_service_sql import get_dashboard_service_sql

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/", response_model=Dashboard, status_code=201)
async def create_dashboard(dashboard: DashboardCreate, db: AsyncSession = Depends(get_db)):
    """
    Cria um novo dashboard

    - **title**: Nome do dashboard (obrigatório)
    - **description**: Descrição opcional
    - **index**: Índice Elasticsearch
    - **widgets**: Lista de widgets (opcional)
    """
    logger.info(f"Creating dashboard: {dashboard.title}")
    service = get_dashboard_service_sql()

    try:
        return await service.create(db, dashboard)
    except Exception as e:
        logger.error(f"Error creating dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=List[DashboardListItem])
async def list_dashboards(
    skip: int = Query(0, ge=0, description="Número de registros para pular"),
    limit: int = Query(10, ge=1, le=100, description="Máximo de registros"),
    index: Optional[str] = Query(None, description="Filtrar por índice ES"),
    tags: Optional[str] = Query(None, description="Filtrar por tags (separadas por vírgula)"),
    db: AsyncSession = Depends(get_db),
):
    """
    Lista dashboards com filtros opcionais

    - **skip**: Paginação - registros para pular
    - **limit**: Paginação - máximo de registros
    - **index**: Filtrar por índice Elasticsearch
    - **tags**: Filtrar por tags
    """
    logger.info(f"Listing dashboards (skip={skip}, limit={limit}, index={index}, tags={tags})")
    service = get_dashboard_service_sql()

    try:
        tags_list = tags.split(",") if tags else None
        return await service.list(db, skip=skip, limit=limit, index=index, tags=tags_list)
    except Exception as e:
        logger.error(f"Error listing dashboards: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{dashboard_id}", response_model=Dashboard)
async def get_dashboard(dashboard_id: str, db: AsyncSession = Depends(get_db)):
    """
    Busca dashboard por ID

    - **dashboard_id**: UUID do dashboard
    """
    logger.info(f"Getting dashboard: {dashboard_id}")
    service = get_dashboard_service_sql()

    try:
        dashboard = await service.get(db, dashboard_id)
        if not dashboard:
            raise HTTPException(status_code=404, detail="Dashboard not found")
        return dashboard
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{dashboard_id}", response_model=Dashboard)
async def update_dashboard(
    dashboard_id: str, updates: DashboardUpdate, db: AsyncSession = Depends(get_db)
):
    """
    Atualiza dashboard

    - **dashboard_id**: UUID do dashboard
    - **updates**: Campos para atualizar (title, description, widgets, layout, tags)
    """
    logger.info(f"Updating dashboard: {dashboard_id}")
    service = get_dashboard_service_sql()

    try:
        dashboard = await service.update(db, dashboard_id, updates)
        if not dashboard:
            raise HTTPException(status_code=404, detail="Dashboard not found")
        return dashboard
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{dashboard_id}", status_code=204)
async def delete_dashboard(dashboard_id: str, db: AsyncSession = Depends(get_db)):
    """
    Deleta dashboard

    - **dashboard_id**: UUID do dashboard
    """
    logger.info(f"Deleting dashboard: {dashboard_id}")
    service = get_dashboard_service_sql()

    try:
        success = await service.delete_dashboard(db, dashboard_id)
        if not success:
            raise HTTPException(status_code=404, detail="Dashboard not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{dashboard_id}/duplicate", response_model=Dashboard, status_code=201)
async def duplicate_dashboard(
    dashboard_id: str, new_title: Optional[str] = None, db: AsyncSession = Depends(get_db)
):
    """
    Duplica um dashboard existente

    - **dashboard_id**: UUID do dashboard original
    - **new_title**: Título do novo dashboard (opcional)
    """
    logger.info(f"Duplicating dashboard: {dashboard_id}")
    service = get_dashboard_service_sql()

    try:
        # Buscar dashboard original
        original = await service.get(db, dashboard_id)
        if not original:
            raise HTTPException(status_code=404, detail="Dashboard not found")

        # Criar novo dashboard baseado no original
        title = new_title if new_title else f"{original.title} (Cópia)"
        dashboard_data = DashboardCreate(
            title=title,
            description=original.description,
            index=original.index,
            server_id=original.server_id,
            layout=original.layout,
            widgets=original.widgets,
            tags=original.metadata.tags,
        )

        return await service.create(db, dashboard_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error duplicating dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))
