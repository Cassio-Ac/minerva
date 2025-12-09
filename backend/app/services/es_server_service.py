"""
Elasticsearch Server Service
Gerencia CRUD de servidores Elasticsearch
"""

from typing import List, Optional, Dict, Any
import logging
from elasticsearch import AsyncElasticsearch
from app.models.elasticsearch_server import (
    ElasticsearchServer,
    ESServerCreate,
    ESServerUpdate,
    ESServerTestResult,
    ESIndexInfo,
)
from app.db.elasticsearch import get_es_client

logger = logging.getLogger(__name__)


class ESServerService:
    """Service para gerenciar servidores Elasticsearch"""

    INDEX_NAME = "dashboard_servers"

    async def create(self, server_create: ESServerCreate) -> ElasticsearchServer:
        """
        Cria novo servidor ES

        Args:
            server_create: Dados do servidor

        Returns:
            Servidor criado
        """
        es = await get_es_client()

        # Criar objeto completo
        server = ElasticsearchServer(
            name=server_create.name,
            description=server_create.description,
            connection=server_create.connection,
            is_default=server_create.is_default,
        )

        # Se for default, remover flag de outros servidores
        if server.is_default:
            await self._unset_all_defaults()

        # Salvar no Elasticsearch
        await es.index(
            index=self.INDEX_NAME,
            id=server.id,
            document=server.model_dump(),
            refresh=True,
        )

        logger.info(f"✅ Created ES server: {server.name} ({server.id})")
        return server

    async def get(self, server_id: str) -> Optional[ElasticsearchServer]:
        """
        Busca servidor por ID

        Args:
            server_id: ID do servidor

        Returns:
            Servidor ou None se não encontrado
        """
        es = await get_es_client()

        try:
            result = await es.get(index=self.INDEX_NAME, id=server_id)
            return ElasticsearchServer(**result["_source"])
        except Exception as e:
            logger.warning(f"Server {server_id} not found: {e}")
            return None

    async def list(
        self, active_only: bool = False, include_stats: bool = False
    ) -> List[ElasticsearchServer]:
        """
        Lista todos os servidores

        Args:
            active_only: Retornar apenas servidores ativos
            include_stats: Incluir estatísticas atualizadas

        Returns:
            Lista de servidores
        """
        es = await get_es_client()

        # Construir query
        query: Dict[str, Any] = {"match_all": {}}
        if active_only:
            query = {"term": {"is_active": True}}

        # Buscar sem sort (para evitar erro quando índice está vazio ou sem mapping)
        result = await es.search(
            index=self.INDEX_NAME, query=query, size=100
        )

        servers = []
        for hit in result["hits"]["hits"]:
            server = ElasticsearchServer(**hit["_source"])

            # Atualizar stats se solicitado
            if include_stats:
                try:
                    await self._update_server_stats(server)
                except Exception as e:
                    logger.warning(f"Failed to update stats for {server.name}: {e}")

            servers.append(server)

        # Ordenar por nome em Python
        servers.sort(key=lambda x: x.name.lower())

        logger.info(f"📋 Listed {len(servers)} ES servers")
        return servers

    async def update(
        self, server_id: str, updates: ESServerUpdate
    ) -> Optional[ElasticsearchServer]:
        """
        Atualiza servidor

        Args:
            server_id: ID do servidor
            updates: Campos a atualizar

        Returns:
            Servidor atualizado ou None
        """
        es = await get_es_client()

        # Buscar servidor atual
        server = await self.get(server_id)
        if not server:
            return None

        # Aplicar updates
        update_data = updates.model_dump(exclude_unset=True)

        if "name" in update_data:
            server.name = update_data["name"]
        if "description" in update_data:
            server.description = update_data["description"]
        if "connection" in update_data:
            server.connection = update_data["connection"]
        if "is_active" in update_data:
            server.is_active = update_data["is_active"]
        if "is_default" in update_data:
            if update_data["is_default"]:
                await self._unset_all_defaults()
            server.is_default = update_data["is_default"]

        # Atualizar metadata
        from datetime import datetime

        server.metadata.updated_at = datetime.now()

        # Salvar
        await es.index(
            index=self.INDEX_NAME,
            id=server_id,
            document=server.model_dump(),
            refresh=True,
        )

        logger.info(f"✏️ Updated ES server: {server.name} ({server_id})")
        return server

    async def delete(self, server_id: str) -> bool:
        """
        Deleta servidor

        Args:
            server_id: ID do servidor

        Returns:
            True se deletado com sucesso
        """
        es = await get_es_client()

        try:
            await es.delete(index=self.INDEX_NAME, id=server_id, refresh=True)
            logger.info(f"🗑️ Deleted ES server: {server_id}")
            return True
        except Exception as e:
            logger.error(f"Error deleting server {server_id}: {e}")
            return False

    async def test_connection(self, server_id: str) -> ESServerTestResult:
        """
        Testa conexão com servidor ES

        Args:
            server_id: ID do servidor

        Returns:
            Resultado do teste
        """
        server = await self.get(server_id)
        if not server:
            return ESServerTestResult(
                success=False, message="Server not found", error="Server not found"
            )

        return await self._test_es_connection(server)

    async def get_indices(self, server_id: str) -> List[ESIndexInfo]:
        """
        Lista índices do servidor

        Args:
            server_id: ID do servidor

        Returns:
            Lista de índices
        """
        server = await self.get(server_id)
        if not server:
            return []

        try:
            # Criar cliente temporário para este servidor
            es_client = AsyncElasticsearch(
                hosts=[server.connection.url],
                basic_auth=(
                    (server.connection.username, server.connection.password)
                    if server.connection.username
                    else None
                ),
                verify_certs=server.connection.verify_ssl,
                request_timeout=server.connection.timeout,
            )

            # Buscar stats de índices
            stats = await es_client.indices.stats()
            cat_indices = await es_client.cat.indices(format="json")

            await es_client.close()

            # Processar resultados
            indices = []
            for idx in cat_indices:
                name = idx.get("index", "")
                # Ignorar índices do sistema
                if name.startswith("."):
                    continue

                # Converter store.size (vem como string tipo "249b", "1.2kb", etc)
                store_size_str = idx.get("store.size", "0")
                try:
                    # Remover sufixos (b, kb, mb, gb) e converter
                    import re
                    size_match = re.match(r'([\d.]+)([a-z]+)?', str(store_size_str))
                    if size_match:
                        number = float(size_match.group(1))
                        unit = size_match.group(2) or 'b'
                        # Converter para bytes
                        multipliers = {'b': 1, 'kb': 1024, 'mb': 1024**2, 'gb': 1024**3}
                        size_in_bytes = int(number * multipliers.get(unit.lower(), 1))
                    else:
                        size_in_bytes = 0
                except:
                    size_in_bytes = 0

                indices.append(
                    ESIndexInfo(
                        name=name,
                        doc_count=int(idx.get("docs.count", 0) or 0),
                        size_in_bytes=size_in_bytes,
                        health=idx.get("health"),
                        status=idx.get("status"),
                        primary_shards=int(idx.get("pri", 0) or 0),
                        replica_shards=int(idx.get("rep", 0) or 0),
                    )
                )

            logger.info(f"📚 Listed {len(indices)} indices from server {server.name}")
            return sorted(indices, key=lambda x: x.name)

        except Exception as e:
            logger.error(f"Error listing indices from {server.name}: {e}")
            return []

    async def get_default_server(self) -> Optional[ElasticsearchServer]:
        """
        Retorna o servidor padrão

        Returns:
            Servidor padrão ou None
        """
        es = await get_es_client()

        result = await es.search(
            index=self.INDEX_NAME, query={"term": {"is_default": True}}, size=1
        )

        if result["hits"]["total"]["value"] > 0:
            return ElasticsearchServer(**result["hits"]["hits"][0]["_source"])

        return None

    # Private methods

    async def _unset_all_defaults(self):
        """Remove flag default de todos os servidores"""
        es = await get_es_client()

        # Buscar todos os servidores default
        result = await es.search(
            index=self.INDEX_NAME, query={"term": {"is_default": True}}, size=100
        )

        # Atualizar cada um
        for hit in result["hits"]["hits"]:
            await es.update(
                index=self.INDEX_NAME,
                id=hit["_id"],
                doc={"is_default": False},
                refresh=True,
            )

    async def _test_es_connection(
        self, server: ElasticsearchServer
    ) -> ESServerTestResult:
        """
        Testa conexão com servidor ES

        Args:
            server: Servidor a testar

        Returns:
            Resultado do teste
        """
        try:
            # Criar cliente temporário
            es_client = AsyncElasticsearch(
                hosts=[server.connection.url],
                basic_auth=(
                    (server.connection.username, server.connection.password)
                    if server.connection.username
                    else None
                ),
                verify_certs=server.connection.verify_ssl,
                request_timeout=server.connection.timeout,
            )

            # Testar conexão
            info = await es_client.info()
            health = await es_client.cluster.health()

            # Buscar stats de índices
            cat_indices = await es_client.cat.indices(format="json")

            # Contar índices (excluindo sistema)
            user_indices = [idx for idx in cat_indices if not idx.get("index", "").startswith(".")]
            total_indices = len(user_indices)

            # Somar total de documentos
            total_docs = sum(int(idx.get("docs.count", 0) or 0) for idx in user_indices)

            await es_client.close()

            # Atualizar metadata do servidor
            from datetime import datetime

            server.metadata.last_test = datetime.now()
            server.metadata.last_test_status = "success"
            server.metadata.version = info.get("version", {}).get("number")
            server.metadata.last_error = None

            # Atualizar stats
            server.stats.cluster_name = info.get("cluster_name")
            server.stats.cluster_health = health.get("status")
            server.stats.node_count = health.get("number_of_nodes", 0)
            server.stats.total_indices = total_indices
            server.stats.total_documents = total_docs

            # Salvar updates
            es = await get_es_client()
            await es.index(
                index=self.INDEX_NAME,
                id=server.id,
                document=server.model_dump(),
                refresh=True,
            )

            return ESServerTestResult(
                success=True,
                message="Connection successful",
                version=server.metadata.version,
                cluster_name=server.stats.cluster_name,
                cluster_health=server.stats.cluster_health,
                node_count=server.stats.node_count,
            )

        except Exception as e:
            # Atualizar metadata com erro
            from datetime import datetime

            server.metadata.last_test = datetime.now()
            server.metadata.last_test_status = "failed"
            server.metadata.last_error = str(e)

            es = await get_es_client()
            await es.index(
                index=self.INDEX_NAME,
                id=server.id,
                document=server.model_dump(),
                refresh=True,
            )

            logger.error(f"❌ Connection test failed for {server.name}: {e}")
            return ESServerTestResult(
                success=False, message="Connection failed", error=str(e)
            )

    async def _update_server_stats(self, server: ElasticsearchServer):
        """Atualiza estatísticas do servidor"""
        try:
            es_client = AsyncElasticsearch(
                hosts=[server.connection.url],
                basic_auth=(
                    (server.connection.username, server.connection.password)
                    if server.connection.username
                    else None
                ),
                verify_certs=server.connection.verify_ssl,
                request_timeout=server.connection.timeout,
            )

            stats = await es_client.indices.stats()
            health = await es_client.cluster.health()

            await es_client.close()

            # Atualizar stats
            total_docs = sum(
                idx.get("total", {}).get("docs", {}).get("count", 0)
                for idx in stats.get("indices", {}).values()
            )

            server.stats.total_indices = len(stats.get("indices", {}))
            server.stats.total_documents = total_docs
            server.stats.cluster_health = health.get("status")
            server.stats.node_count = health.get("number_of_nodes", 0)

        except Exception as e:
            logger.warning(f"Failed to update stats for {server.name}: {e}")


# Singleton instance
_es_server_service: Optional[ESServerService] = None


def get_es_server_service() -> ESServerService:
    """Retorna instância do service"""
    global _es_server_service
    if _es_server_service is None:
        _es_server_service = ESServerService()
    return _es_server_service
