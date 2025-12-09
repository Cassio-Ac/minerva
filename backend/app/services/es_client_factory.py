"""
Elasticsearch Client Factory
Cria clientes ES dinamicamente baseado em servidor configurado
"""

from typing import Optional, Dict
import logging
from elasticsearch import AsyncElasticsearch
from app.services.es_server_service import get_es_server_service
from app.db.elasticsearch import get_es_client

logger = logging.getLogger(__name__)


class ESClientFactory:
    """Factory para criar clientes ES por servidor"""

    # Cache de clientes por server_id
    _clients: Dict[str, AsyncElasticsearch] = {}

    @classmethod
    async def get_client(
        cls, server_id: Optional[str] = None
    ) -> AsyncElasticsearch:
        """
        Retorna cliente ES para o servidor especificado

        Args:
            server_id: ID do servidor ES. Se None, usa cliente padrão

        Returns:
            Cliente AsyncElasticsearch configurado
        """
        # Se não especificou server_id, usar cliente padrão
        if server_id is None:
            logger.debug("Using default ES client")
            return await get_es_client()

        # Verificar se já tem cliente em cache
        if server_id in cls._clients:
            logger.debug(f"Using cached ES client for server: {server_id}")
            return cls._clients[server_id]

        # Buscar configuração do servidor
        es_server_service = get_es_server_service()
        server = await es_server_service.get(server_id)

        if not server:
            logger.warning(
                f"Server {server_id} not found, falling back to default"
            )
            return await get_es_client()

        # Criar novo cliente
        logger.info(f"Creating new ES client for server: {server.name}")

        client = AsyncElasticsearch(
            hosts=[server.connection.url],
            basic_auth=(
                (server.connection.username, server.connection.password)
                if server.connection.username
                else None
            ),
            verify_certs=server.connection.verify_ssl,
            request_timeout=server.connection.timeout,
        )

        # Armazenar em cache
        cls._clients[server_id] = client

        return client

    @classmethod
    async def close_client(cls, server_id: str):
        """
        Fecha e remove cliente do cache

        Args:
            server_id: ID do servidor
        """
        if server_id in cls._clients:
            logger.info(f"Closing ES client for server: {server_id}")
            await cls._clients[server_id].close()
            del cls._clients[server_id]

    @classmethod
    async def close_all_clients(cls):
        """Fecha todos os clientes em cache"""
        logger.info("Closing all cached ES clients")
        for server_id, client in cls._clients.items():
            await client.close()
        cls._clients.clear()


# Singleton instance
_factory: Optional[ESClientFactory] = None


def get_es_client_factory() -> ESClientFactory:
    """Retorna instância da factory"""
    global _factory
    if _factory is None:
        _factory = ESClientFactory()
    return _factory
