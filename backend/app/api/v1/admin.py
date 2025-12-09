"""
Admin API
Endpoints administrativos para métricas do sistema e gerenciamento
"""

import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.core.dependencies import get_current_user
from app.models.user import User
from app.db.models import Dashboard as DashboardDB
from app.db.models import Conversation as ConversationDB
from app.models.download import Download
from app.models.llm_provider import LLMProvider
from app.models.mcp_server import MCPServer

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/admin/metrics")
async def get_system_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retorna métricas do sistema

    **Permissions**: Admin only (can_configure_system)

    **Returns**: Métricas do sistema
    """
    # Verificar permissão de admin
    if not current_user.can_configure_system:
        raise HTTPException(status_code=403, detail="Acesso negado. Apenas administradores.")

    try:
        # Total de usuários
        total_users_result = await db.execute(select(func.count()).select_from(User))
        total_users = total_users_result.scalar() or 0

        # Total de dashboards
        total_dashboards_result = await db.execute(select(func.count()).select_from(DashboardDB))
        total_dashboards = total_dashboards_result.scalar() or 0

        # Total de conversas
        total_conversations_result = await db.execute(select(func.count()).select_from(ConversationDB))
        total_conversations = total_conversations_result.scalar() or 0

        # Total de downloads
        total_downloads_result = await db.execute(select(func.count()).select_from(Download))
        total_downloads = total_downloads_result.scalar() or 0

        # Usuários ativos hoje (last_login hoje)
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        active_today_result = await db.execute(
            select(func.count()).select_from(User).where(User.last_login >= today_start)
        )
        active_users_today = active_today_result.scalar() or 0

        # Requisições LLM hoje (contagem de conversas atualizadas hoje)
        # Cada conversa atualizada hoje representa pelo menos 1 interação
        llm_requests_result = await db.execute(
            select(func.count()).select_from(ConversationDB).where(ConversationDB.updated_at >= today_start)
        )
        llm_requests_today = llm_requests_result.scalar() or 0

        # Servidores MCP cadastrados
        mcp_servers_result = await db.execute(select(func.count()).select_from(MCPServer))
        mcp_servers_count = mcp_servers_result.scalar() or 0

        # Provedores LLM cadastrados
        llm_providers_result = await db.execute(select(func.count()).select_from(LLMProvider))
        llm_providers_count = llm_providers_result.scalar() or 0

        return {
            "total_users": total_users,
            "total_dashboards": total_dashboards,
            "total_conversations": total_conversations,
            "total_downloads": total_downloads,
            "active_users_today": active_users_today,
            "llm_requests_today": llm_requests_today,
            "mcp_servers_count": mcp_servers_count,
            "llm_providers_count": llm_providers_count
        }

    except Exception as e:
        logger.error(f"Error fetching system metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))
