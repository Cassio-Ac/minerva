"""
Elasticsearch Servers API Endpoints - SQL Version
Gerenciamento de servidores Elasticsearch usando PostgreSQL
"""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
import logging

from app.db.database import get_db
from app.models.elasticsearch_server import (
    ElasticsearchServer,
    ESServerCreate,
    ESServerUpdate,
    ESServerTestResult,
    ESIndexInfo,
)
from app.services.es_server_service_sql import get_es_server_service_sql
from app.services.es_server_service import get_es_server_service  # For test/indices operations

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/", response_model=ElasticsearchServer, status_code=201)
async def create_server(server: ESServerCreate, db: AsyncSession = Depends(get_db)):
    """
    Cria um novo servidor Elasticsearch

    - **name**: Nome amigável do servidor
    - **description**: Descrição opcional
    - **connection**: Configuração de conexão (URL, credenciais, etc)
    - **is_default**: Se deve ser o servidor padrão
    """
    logger.info(f"Creating ES server: {server.name}")

    service = get_es_server_service_sql()
    created_server = await service.create(db, server)

    logger.info(f"✅ ES server created: {created_server.id}")
    return created_server


@router.get("/", response_model=List[ElasticsearchServer])
async def list_servers(
    active_only: bool = False,
    include_stats: bool = False,
    db: AsyncSession = Depends(get_db)
):
    """
    Lista todos os servidores Elasticsearch

    - **active_only**: Retornar apenas servidores ativos
    - **include_stats**: Incluir estatísticas atualizadas (pode ser lento)
    """
    logger.info(f"Listing ES servers (active_only={active_only}, include_stats={include_stats})")

    service = get_es_server_service_sql()
    servers = await service.list(db, active_only=active_only)

    logger.info(f"📋 Found {len(servers)} ES servers")
    return servers


@router.get("/default", response_model=ElasticsearchServer)
async def get_default_server(db: AsyncSession = Depends(get_db)):
    """
    Retorna o servidor padrão

    Útil para quando o usuário não selecionar um servidor específico.
    """
    logger.info("Getting default ES server")

    service = get_es_server_service_sql()
    server = await service.get_default(db)

    if not server:
        raise HTTPException(status_code=404, detail="No default server configured")

    return server


@router.get("/{server_id}", response_model=ElasticsearchServer)
async def get_server(server_id: str, db: AsyncSession = Depends(get_db)):
    """
    Busca servidor por ID

    - **server_id**: UUID do servidor
    """
    logger.info(f"Getting ES server: {server_id}")

    service = get_es_server_service_sql()
    server = await service.get(db, server_id)

    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    return server


@router.patch("/{server_id}", response_model=ElasticsearchServer)
async def update_server(server_id: str, updates: ESServerUpdate, db: AsyncSession = Depends(get_db)):
    """
    Atualiza um servidor Elasticsearch

    - **server_id**: UUID do servidor
    - **updates**: Campos a atualizar (parcial)
    """
    logger.info(f"Updating ES server: {server_id}")

    service = get_es_server_service_sql()
    updated_server = await service.update(db, server_id, updates)

    if not updated_server:
        raise HTTPException(status_code=404, detail="Server not found")

    logger.info(f"✅ ES server updated: {server_id}")
    return updated_server


@router.delete("/{server_id}", status_code=204)
async def delete_server(server_id: str, db: AsyncSession = Depends(get_db)):
    """
    Deleta um servidor Elasticsearch

    - **server_id**: UUID do servidor
    """
    logger.info(f"Deleting ES server: {server_id}")

    service = get_es_server_service_sql()
    success = await service.delete_server(db, server_id)

    if not success:
        raise HTTPException(status_code=404, detail="Server not found")

    logger.info(f"🗑️ ES server deleted: {server_id}")
    return None


@router.post("/{server_id}/test", response_model=ESServerTestResult)
async def test_server_connection(server_id: str):
    """
    Testa conexão com servidor Elasticsearch

    Verifica se consegue conectar ao servidor e retorna informações básicas
    como versão, cluster health, etc.

    - **server_id**: UUID do servidor
    """
    logger.info(f"Testing connection to ES server: {server_id}")

    service = get_es_server_service()
    result = await service.test_connection(server_id)

    if result.success:
        logger.info(f"✅ Connection test successful: {server_id}")
    else:
        logger.warning(f"❌ Connection test failed: {server_id} - {result.error}")

    return result


@router.get("/{server_id}/indices", response_model=List[ESIndexInfo])
async def list_server_indices(server_id: str, db: AsyncSession = Depends(get_db)):
    """
    Lista todos os índices de um servidor Elasticsearch

    - **server_id**: UUID do servidor
    """
    logger.info(f"Listing indices from ES server: {server_id}")

    service_sql = get_es_server_service_sql()
    indices = await service_sql.get_indices(db, server_id)

    logger.info(f"📚 Found {len(indices)} indices in server {server_id}")
    return indices
