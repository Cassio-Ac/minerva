"""
Elasticsearch Client
Cliente async para conexão com Elasticsearch
"""

from elasticsearch import AsyncElasticsearch, Elasticsearch
from typing import Optional, Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class ElasticsearchClient:
    """Cliente Elasticsearch Singleton"""

    _instance: Optional[AsyncElasticsearch] = None
    _default_config: Optional[Dict[str, str]] = None

    @classmethod
    def initialize(cls, url: str, username: Optional[str] = None, password: Optional[str] = None):
        """Inicializa conexão com ES"""
        if username and password:
            cls._instance = AsyncElasticsearch(
                [url],
                basic_auth=(username, password),
                verify_certs=False,
                request_timeout=120,  # 2 minutos para buscas pesadas (Data Lake 230M docs)
            )
        else:
            cls._instance = AsyncElasticsearch(
                [url],
                verify_certs=False,
                request_timeout=120,  # 2 minutos para buscas pesadas
            )

        cls._default_config = {
            "url": url,
            "username": username or "",
            "password": password or "",
        }

        logger.info(f"✅ Elasticsearch client initialized: {url}")

    @classmethod
    def get_client(cls) -> AsyncElasticsearch:
        """Retorna instância do cliente"""
        if cls._instance is None:
            # Se não foi inicializado, tenta usar variável de ambiente ou localhost
            from app.core.config import settings

            url = settings.ES_URL or "http://localhost:9200"
            username = settings.ES_USERNAME
            password = settings.ES_PASSWORD

            cls.initialize(url, username, password)

        return cls._instance

    @classmethod
    async def close(cls):
        """Fecha conexão"""
        if cls._instance:
            await cls._instance.close()
            cls._instance = None
            logger.info("✅ Elasticsearch connection closed")

    @classmethod
    async def ping(cls) -> bool:
        """Testa conexão"""
        try:
            client = cls.get_client()
            return await client.ping()
        except Exception as e:
            logger.error(f"❌ Elasticsearch ping failed: {e}")
            return False

    @classmethod
    async def create_index(cls, index_name: str, mappings: Optional[Dict] = None):
        """Cria índice se não existir"""
        try:
            client = cls.get_client()

            if await client.indices.exists(index=index_name):
                logger.info(f"Index {index_name} already exists")
                return

            body = {}
            if mappings:
                body["mappings"] = mappings

            await client.indices.create(index=index_name, body=body)
            logger.info(f"✅ Index {index_name} created")

        except Exception as e:
            logger.error(f"❌ Error creating index {index_name}: {e}")
            raise


# Funções helper
async def get_es_client() -> AsyncElasticsearch:
    """Helper para obter cliente ES"""
    return ElasticsearchClient.get_client()


async def ping_elasticsearch() -> bool:
    """Helper para testar conexão"""
    return await ElasticsearchClient.ping()


def get_sync_es_client() -> Elasticsearch:
    """
    Helper para obter cliente ES síncrono (para RSS e outras tasks)
    Cria uma nova instância do cliente sync baseado na configuração padrão
    """
    from app.core.config import settings

    url = settings.ES_URL or "http://localhost:9200"
    username = settings.ES_USERNAME
    password = settings.ES_PASSWORD

    if username and password:
        return Elasticsearch(
            [url],
            basic_auth=(username, password),
            verify_certs=False,
            request_timeout=120,  # 2 minutos para buscas pesadas
        )
    else:
        return Elasticsearch(
            [url],
            verify_certs=False,
            request_timeout=120,  # 2 minutos para buscas pesadas
        )


def get_sync_es_dependency() -> Elasticsearch:
    """
    Dependency para FastAPI endpoints que precisam de cliente ES síncrono
    """
    return get_sync_es_client()


# Inicializar índices necessários
async def initialize_indices():
    """Inicializa índices do dashboard"""

    # Índice de dashboards
    dashboards_mapping = {
        "properties": {
            "id": {"type": "keyword"},
            "title": {"type": "text"},
            "description": {"type": "text"},
            "index": {"type": "keyword"},
            "layout": {"type": "object"},
            "widgets": {"type": "nested"},
            "metadata": {
                "properties": {
                    "created_at": {"type": "date"},
                    "updated_at": {"type": "date"},
                    "created_by": {"type": "keyword"},
                    "is_public": {"type": "boolean"},
                    "tags": {"type": "keyword"},
                    "version": {"type": "integer"},
                }
            },
        }
    }

    await ElasticsearchClient.create_index("dashboards", dashboards_mapping)

    # Índice de servidores ES
    servers_mapping = {
        "properties": {
            "name": {"type": "keyword"},
            "url": {"type": "keyword"},
            "username": {"type": "keyword"},
            "password": {"type": "keyword"},  # Será criptografado
            "description": {"type": "text"},
            "created_at": {"type": "date"},
            "is_active": {"type": "boolean"},
        }
    }

    await ElasticsearchClient.create_index("dashboard_servers", servers_mapping)

    # Índice de conversations
    conversations_mapping = {
        "properties": {
            "id": {"type": "keyword"},
            "title": {"type": "text"},
            "index": {"type": "keyword"},
            "server_id": {"type": "keyword"},
            "created_by": {"type": "keyword"},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"},
            "messages": {
                "type": "nested",
                "properties": {
                    "id": {"type": "keyword"},
                    "role": {"type": "keyword"},
                    "content": {"type": "text"},
                    "timestamp": {"type": "date"},
                    "widget": {"type": "object", "enabled": True},
                }
            },
        }
    }

    await ElasticsearchClient.create_index("conversations", conversations_mapping)

    logger.info("✅ All indices initialized")
