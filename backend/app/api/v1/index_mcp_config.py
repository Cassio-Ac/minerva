"""
Index MCP Configuration API
Endpoints para gerenciar configuração de MCPs por índice
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from pydantic import BaseModel

from app.core.dependencies import get_current_user
from app.models.user import User
from app.services.index_mcp_config_service import IndexMCPConfigService
from app.db.database import get_db

router = APIRouter()


# Pydantic schemas
class IndexMCPConfigCreate(BaseModel):
    """Schema para criar configuração"""
    es_server_id: str
    index_name: str
    mcp_server_id: str
    priority: int = 10
    is_enabled: bool = True
    auto_inject_context: bool = True
    config: Optional[dict] = None


class IndexMCPConfigUpdate(BaseModel):
    """Schema para atualizar configuração"""
    priority: Optional[int] = None
    is_enabled: Optional[bool] = None
    auto_inject_context: Optional[bool] = None
    config: Optional[dict] = None


class IndexMCPConfigResponse(BaseModel):
    """Schema de resposta"""
    id: str
    es_server_id: str
    index_name: str
    mcp_server_id: str
    priority: int
    is_enabled: bool
    auto_inject_context: bool
    config: Optional[dict]
    created_at: str
    updated_at: str
    created_by_id: Optional[str]


@router.post("/", response_model=IndexMCPConfigResponse)
async def create_config(
    data: IndexMCPConfigCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Criar nova configuração de MCP para um índice

    Requer permissão can_configure_system
    """
    if not current_user.can_configure_system:
        raise HTTPException(status_code=403, detail="Permission denied")

    try:
        config = await IndexMCPConfigService.create_config(
            db=db,
            es_server_id=data.es_server_id,
            index_name=data.index_name,
            mcp_server_id=data.mcp_server_id,
            priority=data.priority,
            is_enabled=data.is_enabled,
            auto_inject_context=data.auto_inject_context,
            config=data.config,
            created_by_id=str(current_user.id),
        )

        return config.to_dict()

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/", response_model=List[IndexMCPConfigResponse])
async def list_configs(
    es_server_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Listar todas as configurações

    Query params:
    - es_server_id: Filtrar por servidor ES (opcional)
    """
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"📋 Listing index-mcp-config (user={current_user.username}, es_server_id={es_server_id})")

    try:
        configs = await IndexMCPConfigService.get_all_configs(
            db=db,
            es_server_id=es_server_id
        )

        logger.info(f"✅ Found {len(configs)} configurations")
        return [config.to_dict() for config in configs]
    except Exception as e:
        logger.error(f"❌ Error listing configs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/index/{es_server_id}/{index_name}", response_model=List[IndexMCPConfigResponse])
async def get_configs_by_index(
    es_server_id: str,
    index_name: str,
    enabled_only: bool = False,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Buscar configurações para um índice específico

    Path params:
    - es_server_id: ID do servidor Elasticsearch
    - index_name: Nome do índice

    Query params:
    - enabled_only: Retornar apenas configurações ativas
    """
    configs = await IndexMCPConfigService.get_configs_by_index(
        db=db,
        es_server_id=es_server_id,
        index_name=index_name,
        enabled_only=enabled_only
    )

    return [config.to_dict() for config in configs]


@router.get("/{config_id}", response_model=IndexMCPConfigResponse)
async def get_config(
    config_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Buscar configuração por ID"""
    config = await IndexMCPConfigService.get_config_by_id(db, config_id)

    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")

    return config.to_dict()


@router.patch("/{config_id}", response_model=IndexMCPConfigResponse)
async def update_config(
    config_id: str,
    data: IndexMCPConfigUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Atualizar configuração

    Requer permissão can_configure_system
    """
    if not current_user.can_configure_system:
        raise HTTPException(status_code=403, detail="Permission denied")

    config = await IndexMCPConfigService.update_config(
        db=db,
        config_id=config_id,
        priority=data.priority,
        is_enabled=data.is_enabled,
        auto_inject_context=data.auto_inject_context,
        config=data.config,
    )

    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")

    return config.to_dict()


@router.delete("/{config_id}")
async def delete_config(
    config_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Deletar configuração

    Requer permissão can_configure_system
    """
    if not current_user.can_configure_system:
        raise HTTPException(status_code=403, detail="Permission denied")

    success = await IndexMCPConfigService.delete_config(db, config_id)

    if not success:
        raise HTTPException(status_code=404, detail="Configuration not found")

    return {"status": "success", "message": "Configuration deleted"}


@router.delete("/index/{es_server_id}/{index_name}")
async def delete_configs_by_index(
    es_server_id: str,
    index_name: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Deletar todas as configurações de um índice

    Requer permissão can_configure_system
    """
    if not current_user.can_configure_system:
        raise HTTPException(status_code=403, detail="Permission denied")

    count = await IndexMCPConfigService.delete_configs_by_index(
        db=db,
        es_server_id=es_server_id,
        index_name=index_name
    )

    return {
        "status": "success",
        "message": f"Deleted {count} configuration(s)"
    }


@router.get("/index/{es_server_id}/{index_name}/mcp-servers", response_model=List[str])
async def get_mcp_servers_for_index(
    es_server_id: str,
    index_name: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Obter lista de MCP server IDs habilitados para um índice

    Retorna lista ordenada por prioridade
    Útil para auto-inject de contexto no LLM
    """
    mcp_server_ids = await IndexMCPConfigService.get_mcp_servers_for_index(
        db=db,
        es_server_id=es_server_id,
        index_name=index_name
    )

    return mcp_server_ids
