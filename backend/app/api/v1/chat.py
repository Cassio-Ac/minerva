"""
Chat API Endpoints
LLM interactions for natural language queries
"""

from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
import logging

from app.db.database import get_db
from app.core.dependencies import get_current_user
from app.models.user import User
from app.services.index_authorization_service import get_index_authorization_service

router = APIRouter()
logger = logging.getLogger(__name__)


class ChatMessage(BaseModel):
    """Mensagem de chat"""
    role: str  # "user" | "assistant"
    content: str


class TimeRange(BaseModel):
    """Time range for temporal filtering"""
    type: str  # 'preset' or 'custom'
    preset: Optional[str] = None
    from_: Optional[str] = Field(None, alias='from')
    to: Optional[str] = None
    label: str

    class Config:
        populate_by_name = True


class ChatRequest(BaseModel):
    """Request para chat"""
    message: str
    index: str
    server_id: Optional[str] = None
    time_range: Optional[TimeRange] = None
    context: Optional[List[ChatMessage]] = None


class ChatResponse(BaseModel):
    """Response do chat"""
    explanation: str
    visualization_type: Optional[str] = None
    query: Optional[Dict[str, Any]] = None
    needs_clarification: bool = False
    widget: Optional[Dict[str, Any]] = None


@router.post("/", response_model=ChatResponse)
async def chat_with_ai(
    request: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Processa mensagem do usuário com LLM

    O LLM:
    1. Interpreta a mensagem em linguagem natural
    2. Gera query Elasticsearch apropriada
    3. Determina tipo de visualização
    4. Retorna explicação em português

    - **message**: Mensagem do usuário
    - **index**: Índice Elasticsearch a consultar
    - **server_id**: ID do servidor ES (opcional)
    - **context**: Histórico de mensagens (opcional)

    **Permissões:**
    - ADMIN e POWER: Acesso irrestrito a qualquer índice
    - OPERATOR: Só pode acessar índices com permissão explícita
    - READER: Sem acesso ao chat
    """
    # 1. Verificar se usuário pode usar LLM
    if not current_user.can_use_llm:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User role does not have permission to use chat/LLM features"
        )

    # 2. Verificar se usuário tem acesso ao índice
    # Precisamos criar uma sessão síncrona para o auth service
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.db.database import DATABASE_URL

    sync_engine = create_engine(DATABASE_URL.replace('+asyncpg', ''))
    SessionLocal = sessionmaker(bind=sync_engine)
    sync_db = SessionLocal()

    try:
        auth_service = get_index_authorization_service(sync_db)

        can_access = auth_service.can_access_index(
            user=current_user,
            index_name=request.index,
            es_server_id=request.server_id or "default",
            action="read"
        )

        if not can_access:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User does not have permission to access index '{request.index}'"
            )
    finally:
        sync_db.close()

    logger.info(
        f"User {current_user.username} processing chat message for index {request.index} "
        f"(server: {request.server_id or 'default'}): {request.message}"
    )

    from app.services.llm_service_v2 import get_llm_service_v2

    try:
        llm_service = get_llm_service_v2(db)
        result = await llm_service.process_message(
            message=request.message,
            index=request.index,
            server_id=request.server_id,
            time_range=request.time_range,
            context=request.context
        )

        return ChatResponse(**result)

    except Exception as e:
        logger.error(f"Error processing chat message: {e}")

        # Extract status code from OpenAI/Anthropic/Databricks errors
        error_str = str(e)
        status_code = 500  # Default to internal server error

        # Check for common API error codes in the error message
        if "Error code: 429" in error_str or "429" in error_str:
            status_code = 429  # Too Many Requests / Rate limit / Quota exceeded
        elif "Error code: 401" in error_str or "401" in error_str:
            status_code = 401  # Unauthorized / Invalid API key
        elif "Error code: 403" in error_str or "403" in error_str:
            status_code = 403  # Forbidden
        elif "Error code: 404" in error_str or "404" in error_str:
            status_code = 404  # Not found / Invalid endpoint

        raise HTTPException(status_code=status_code, detail=str(e))


class ExecuteQueryRequest(BaseModel):
    """Request para executar query"""
    index: str
    query: Dict[str, Any]
    server_id: Optional[str] = None
    time_range: Optional[TimeRange] = None


@router.post("/execute", response_model=Dict[str, Any])
async def execute_query(request: ExecuteQueryRequest):
    """
    Executa uma query Elasticsearch

    - **index**: Nome do índice
    - **query**: Query Elasticsearch
    - **server_id**: ID do servidor ES (opcional)
    - **time_range**: Período temporal para filtro (opcional)
    """
    logger.info(
        f"Executing ES query on index: {request.index} "
        f"(server: {request.server_id or 'default'}, time_range: {request.time_range})"
    )

    from app.services.elasticsearch_service import get_es_service

    try:
        # Aplicar filtro temporal na query se fornecido
        query = request.query.copy()
        if request.time_range:
            query = _inject_time_filter(query, request.time_range)
            logger.info(f"Time filter injected: {request.time_range.from_} to {request.time_range.to}")

        es_service = get_es_service()
        result = await es_service.execute_query(
            index=request.index,
            query=query,
            server_id=request.server_id
        )
        return result

    except Exception as e:
        logger.error(f"Error executing query: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _inject_time_filter(query: Dict[str, Any], time_range: TimeRange) -> Dict[str, Any]:
    """
    Atualiza filtro temporal na query Elasticsearch

    Se já existe um filtro range em campo DATE, atualiza os valores gte/lte
    Se não existe, injeta novo filtro com @timestamp

    Args:
        query: Query original
        time_range: Período temporal

    Returns:
        Query com filtro temporal aplicado/atualizado
    """
    time_from = time_range.from_ or "now-30d"
    time_to = time_range.to or "now"

    # Procurar por filtro range existente em campo DATE
    date_field_found = None
    filter_index = None

    if "query" in query and "bool" in query["query"] and "filter" in query["query"]["bool"]:
        filters = query["query"]["bool"]["filter"]

        # Converter para lista se for dict
        if isinstance(filters, dict):
            filters = [filters]
            query["query"]["bool"]["filter"] = filters

        # Procurar filtro range existente
        for idx, f in enumerate(filters):
            if "range" in f:
                # Pegar primeiro campo dentro de range (deve ser campo de data)
                date_field = list(f["range"].keys())[0] if f["range"] else None
                if date_field:
                    date_field_found = date_field
                    filter_index = idx
                    logger.info(f"Found existing date filter on field: {date_field}")
                    break

    # Se encontrou filtro existente, atualizar valores
    if date_field_found and filter_index is not None:
        query["query"]["bool"]["filter"][filter_index]["range"][date_field_found] = {
            "gte": time_from,
            "lte": time_to
        }
        logger.info(f"Updated existing date filter: {date_field_found} = {time_from} to {time_to}")
        return query

    # Se não encontrou, injetar novo filtro com @timestamp
    time_filter = {
        "range": {
            "@timestamp": {
                "gte": time_from,
                "lte": time_to
            }
        }
    }

    # Se já tem query.bool.filter, adicionar o time filter
    if "query" in query and "bool" in query["query"]:
        if "filter" not in query["query"]["bool"]:
            query["query"]["bool"]["filter"] = []

        # Se filter é dict (single filter), converter para array
        if isinstance(query["query"]["bool"]["filter"], dict):
            query["query"]["bool"]["filter"] = [query["query"]["bool"]["filter"]]

        # Adicionar time filter
        query["query"]["bool"]["filter"].append(time_filter)
        logger.info(f"Injected new date filter: @timestamp = {time_from} to {time_to}")

    # Se não tem bool, criar estrutura
    elif "query" in query:
        original_query = query["query"]
        query["query"] = {
            "bool": {
                "must": [original_query] if original_query else [],
                "filter": [time_filter]
            }
        }
        logger.info(f"Created bool structure with date filter: @timestamp = {time_from} to {time_to}")

    # Se não tem query, criar do zero
    else:
        query["query"] = {
            "bool": {
                "filter": [time_filter]
            }
        }
        logger.info(f"Created new query with date filter: @timestamp = {time_from} to {time_to}")

    return query
