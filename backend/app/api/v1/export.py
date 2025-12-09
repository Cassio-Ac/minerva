"""
Export API
Endpoints para exportar dashboards em PDF e PNG
"""

import os
import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Literal

from app.db.database import get_db
from app.core.dependencies import get_current_user
from app.models.user import User
from app.services.dashboard_service_sql import DashboardServiceSQL, get_dashboard_service_sql
from app.services.export_service import ExportService
from app.services.download_service import DownloadService
from app.services.elasticsearch_service import ElasticsearchService

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/dashboards/{dashboard_id}/export/pdf")
async def export_dashboard_pdf(
    dashboard_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Exporta dashboard para PDF

    **Permissions**: Authenticated users

    **Returns**: Download info with file ID
    """
    try:
        # Buscar dashboard
        service = get_dashboard_service_sql()
        dashboard = await service.get(db, dashboard_id)
        if not dashboard:
            raise HTTPException(status_code=404, detail="Dashboard not found")

        # Converter para dicts
        dashboard_dict = {
            "id": str(dashboard.id),
            "title": dashboard.title,
            "description": dashboard.description or ""
        }

        # Executar queries para obter dados frescos
        es_service = ElasticsearchService()
        widgets_dict = []

        for w in dashboard.widgets:
            # Tentar usar results em cache primeiro
            widget_data = w.data.results if hasattr(w.data, 'results') and w.data.results else None

            # Se não tem dados em cache, executar query
            if not widget_data and hasattr(w.data, 'query') and w.data.query:
                try:
                    logger.info(f"Executing query for widget {w.title} (no cached results)")
                    # Usar índice do widget ou do dashboard
                    widget_index = w.index if hasattr(w, 'index') and w.index else dashboard.index

                    # Executar query sem cache para ter dados frescos
                    query_results = await es_service.execute_query(
                        index=widget_index,
                        query=w.data.query,
                        server_id=dashboard.server_id if hasattr(dashboard, 'server_id') else None,
                        use_cache=False  # Não usar cache no export para ter dados atualizados
                    )
                    widget_data = query_results
                    logger.info(f"✅ Query executed successfully for widget {w.title}")
                except Exception as e:
                    logger.warning(f"Failed to execute query for widget {w.title}: {e}")

            widgets_dict.append({
                "id": str(w.id),
                "title": w.title,
                "type": w.type,
                "data": widget_data,
                "query": w.data.query if hasattr(w.data, 'query') else None,
                "config": w.data.config if hasattr(w.data, 'config') else {}
            })

        # Gerar PDF
        pdf_path = await ExportService.export_dashboard_pdf(
            dashboard=dashboard_dict,
            widgets=widgets_dict
        )

        # Criar registro de download
        filename = os.path.basename(pdf_path)
        download = await DownloadService.create_download(
            db=db,
            user_id=str(current_user.id),
            file_path=pdf_path,
            original_name=f"{dashboard.title}.pdf",
            file_type="pdf",
            description=f"Dashboard: {dashboard.title}",
            dashboard_id=dashboard_id
        )

        return {
            "success": True,
            "download_id": str(download.id),
            "filename": filename,
            "message": "Dashboard exported to PDF successfully"
        }

    except Exception as e:
        logger.error(f"Error exporting dashboard to PDF: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dashboards/{dashboard_id}/export/png")
async def export_dashboard_png(
    dashboard_id: str,
    width: int = Query(1920, description="Screenshot width"),
    height: int = Query(1080, description="Screenshot height"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Exporta dashboard como screenshot PNG

    **Permissions**: Authenticated users

    **Returns**: Download info with file ID

    **Note**: Requer Playwright instalado (playwright install chromium)
    """
    try:
        # Buscar dashboard
        service = get_dashboard_service_sql()
        dashboard = await service.get(db, dashboard_id)
        if not dashboard:
            raise HTTPException(status_code=404, detail="Dashboard not found")

        # Construir URL do dashboard
        # TODO: Pegar URL base do config
        dashboard_url = f"http://localhost:5173/dashboard?id={dashboard_id}"

        # Gerar screenshot PNG
        png_path = await ExportService.export_dashboard_png(
            dashboard_id=dashboard_id,
            dashboard_url=dashboard_url,
            width=width,
            height=height
        )

        # Criar registro de download
        filename = os.path.basename(png_path)
        download = await DownloadService.create_download(
            db=db,
            user_id=str(current_user.id),
            file_path=png_path,
            original_name=f"{dashboard.title}.png",
            file_type="png",
            description=f"Dashboard: {dashboard.title} (Screenshot {width}x{height})",
            dashboard_id=dashboard_id
        )

        return {
            "success": True,
            "download_id": str(download.id),
            "filename": filename,
            "message": "Dashboard exported to PNG successfully"
        }

    except Exception as e:
        logger.error(f"Error exporting dashboard to PNG: {e}")
        raise HTTPException(status_code=500, detail=str(e))
