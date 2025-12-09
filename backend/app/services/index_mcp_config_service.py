"""
Index MCP Configuration Service
Gerencia configuração de MCPs por índice do Elasticsearch
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4

from app.models.index_mcp_config import IndexMCPConfig


class IndexMCPConfigService:
    """Service para gerenciar configurações de MCP por índice"""

    @staticmethod
    async def create_config(
        db: AsyncSession,
        es_server_id: str,
        index_name: str,
        mcp_server_id: str,
        priority: int = 10,
        is_enabled: bool = True,
        auto_inject_context: bool = True,
        config: Optional[Dict[str, Any]] = None,
        created_by_id: Optional[str] = None,
    ) -> IndexMCPConfig:
        """
        Criar nova configuração de MCP para um índice

        Args:
            es_server_id: ID do servidor Elasticsearch
            index_name: Nome do índice
            mcp_server_id: ID do servidor MCP
            priority: Prioridade (menor = maior prioridade)
            is_enabled: Se está habilitado
            auto_inject_context: Auto-injetar contexto no LLM
            config: Configurações adicionais (JSON)
            created_by_id: ID do usuário criador

        Returns:
            IndexMCPConfig criado
        """
        mcp_config = IndexMCPConfig(
            id=uuid4(),
            es_server_id=UUID(es_server_id),
            index_name=index_name,
            mcp_server_id=UUID(mcp_server_id),
            priority=priority,
            is_enabled=is_enabled,
            auto_inject_context=auto_inject_context,
            config=config or {},
            created_by_id=UUID(created_by_id) if created_by_id else None,
        )

        db.add(mcp_config)
        await db.commit()
        await db.refresh(mcp_config)

        return mcp_config

    @staticmethod
    async def get_config_by_id(
        db: AsyncSession,
        config_id: str
    ) -> Optional[IndexMCPConfig]:
        """Buscar configuração por ID"""
        stmt = select(IndexMCPConfig).where(IndexMCPConfig.id == UUID(config_id))
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_configs_by_index(
        db: AsyncSession,
        es_server_id: str,
        index_name: str,
        enabled_only: bool = False
    ) -> List[IndexMCPConfig]:
        """
        Buscar todas as configurações de MCP para um índice

        Args:
            es_server_id: ID do servidor ES
            index_name: Nome do índice
            enabled_only: Retornar apenas configurações ativas

        Returns:
            Lista de configurações ordenadas por prioridade
        """
        stmt = select(IndexMCPConfig).where(
            and_(
                IndexMCPConfig.es_server_id == UUID(es_server_id),
                IndexMCPConfig.index_name == index_name
            )
        )

        if enabled_only:
            stmt = stmt.where(IndexMCPConfig.is_enabled == True)

        stmt = stmt.order_by(IndexMCPConfig.priority.asc())

        result = await db.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def get_all_configs(
        db: AsyncSession,
        es_server_id: Optional[str] = None
    ) -> List[IndexMCPConfig]:
        """
        Buscar todas as configurações

        Args:
            es_server_id: Filtrar por servidor ES (opcional)

        Returns:
            Lista de todas as configurações
        """
        stmt = select(IndexMCPConfig)

        if es_server_id:
            stmt = stmt.where(IndexMCPConfig.es_server_id == UUID(es_server_id))

        stmt = stmt.order_by(
            IndexMCPConfig.index_name.asc(),
            IndexMCPConfig.priority.asc()
        )

        result = await db.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def update_config(
        db: AsyncSession,
        config_id: str,
        priority: Optional[int] = None,
        is_enabled: Optional[bool] = None,
        auto_inject_context: Optional[bool] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> Optional[IndexMCPConfig]:
        """
        Atualizar configuração existente

        Args:
            config_id: ID da configuração
            priority: Nova prioridade
            is_enabled: Novo status
            auto_inject_context: Novo valor de auto-inject
            config: Novas configurações JSON

        Returns:
            Configuração atualizada ou None
        """
        # Buscar configuração
        mcp_config = await IndexMCPConfigService.get_config_by_id(db, config_id)

        if not mcp_config:
            return None

        # Atualizar campos
        if priority is not None:
            mcp_config.priority = priority
        if is_enabled is not None:
            mcp_config.is_enabled = is_enabled
        if auto_inject_context is not None:
            mcp_config.auto_inject_context = auto_inject_context
        if config is not None:
            mcp_config.config = config

        await db.commit()
        await db.refresh(mcp_config)

        return mcp_config

    @staticmethod
    async def delete_config(
        db: AsyncSession,
        config_id: str
    ) -> bool:
        """
        Deletar configuração

        Args:
            config_id: ID da configuração

        Returns:
            True se deletado, False se não encontrado
        """
        stmt = delete(IndexMCPConfig).where(IndexMCPConfig.id == UUID(config_id))
        result = await db.execute(stmt)
        await db.commit()

        return result.rowcount > 0

    @staticmethod
    async def delete_configs_by_index(
        db: AsyncSession,
        es_server_id: str,
        index_name: str
    ) -> int:
        """
        Deletar todas as configurações de um índice

        Args:
            es_server_id: ID do servidor ES
            index_name: Nome do índice

        Returns:
            Número de configurações deletadas
        """
        stmt = delete(IndexMCPConfig).where(
            and_(
                IndexMCPConfig.es_server_id == UUID(es_server_id),
                IndexMCPConfig.index_name == index_name
            )
        )
        result = await db.execute(stmt)
        await db.commit()

        return result.rowcount

    @staticmethod
    async def get_mcp_servers_for_index(
        db: AsyncSession,
        es_server_id: str,
        index_name: str
    ) -> List[str]:
        """
        Obter lista de MCP server IDs habilitados para um índice, ordenados por prioridade

        Args:
            es_server_id: ID do servidor ES
            index_name: Nome do índice

        Returns:
            Lista de MCP server IDs
        """
        configs = await IndexMCPConfigService.get_configs_by_index(
            db=db,
            es_server_id=es_server_id,
            index_name=index_name,
            enabled_only=True
        )

        return [str(config.mcp_server_id) for config in configs]
