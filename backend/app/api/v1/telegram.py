"""
Telegram Search API Endpoints
REST API for Telegram message search, user search, and statistics
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query

from app.schemas.telegram import (
    TelegramMessageSearchRequest,
    TelegramMessageSearchResponse,
    TelegramUserSearchRequest,
    TelegramUserSearchResponse,
    TelegramMessageContextRequest,
    TelegramMessageContextResponse,
    TelegramStatisticsResponse,
    TelegramGroupStatisticsResponse,
    TelegramUserStatisticsResponse,
    TelegramGroupsResponse,
    TelegramGroupMessagesResponse,
    TelegramTimelineResponse,
)
from app.services.telegram_search_service import get_telegram_service
from app.core.dependencies import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/telegram", tags=["Telegram Intelligence"])


# ==================== Search Endpoints ====================

@router.post("/search/messages", response_model=TelegramMessageSearchResponse)
async def search_messages(
    request: TelegramMessageSearchRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Busca mensagens por texto com paginação

    - **text**: Texto a buscar
    - **is_exact_search**: Se True, busca exata (substring). Se False, busca inteligente
    - **page**: Número da página (começa em 1)
    - **page_size**: Tamanho da página (padrão: 50, max: 100)
    - **server_id**: ID do servidor Elasticsearch (opcional)
    """
    try:
        service = get_telegram_service()

        result = await service.search_messages(
            text=request.text,
            is_exact_search=request.is_exact_search,
            page=request.page,
            page_size=request.page_size,
            server_id=request.server_id
        )

        # Add _index to each message so frontend knows where it came from
        messages_with_index = []
        for hit in result['hits']:
            msg = hit['_source']
            # Keep the FULL index name (e.g., telegram_messages_puxadasgratis)
            index_name = hit['_index']
            group_username = index_name.replace('telegram_messages_', '')
            msg['_index'] = index_name  # FULL index name
            msg['_actual_group_username'] = group_username  # Just the username part
            messages_with_index.append(msg)

        return TelegramMessageSearchResponse(
            total=result['total'],
            messages=messages_with_index,
            search_type=result['search_type'],
            page=result['page'],
            page_size=result['page_size'],
            has_more=result['has_more']
        )

    except Exception as e:
        logger.error(f"❌ Error in search_messages: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error searching messages: {str(e)}"
        )


@router.post("/search/users", response_model=TelegramUserSearchResponse)
async def search_by_user(
    request: TelegramUserSearchRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Busca mensagens por usuário (user_id, username ou nome completo) com paginação

    - **search_term**: Termo de busca (user_id, username ou nome)
    - **page**: Número da página (começa em 1)
    - **page_size**: Tamanho da página (padrão: 50, max: 100)
    - **server_id**: ID do servidor Elasticsearch (opcional)
    """
    try:
        service = get_telegram_service()

        result = await service.search_by_user(
            search_term=request.search_term,
            page=request.page,
            page_size=request.page_size,
            server_id=request.server_id
        )

        # Add _index to each message so frontend knows where it came from
        messages_with_index = []
        for hit in result['hits']:
            msg = hit['_source']
            # Keep the FULL index name (e.g., telegram_messages_puxadasgratis)
            index_name = hit['_index']
            group_username = index_name.replace('telegram_messages_', '')
            msg['_index'] = index_name  # FULL index name
            msg['_actual_group_username'] = group_username  # Just the username part
            messages_with_index.append(msg)

        return TelegramUserSearchResponse(
            total=result['total'],
            messages=messages_with_index,
            search_term=result['search_term'],
            page=result['page'],
            page_size=result['page_size'],
            has_more=result['has_more']
        )

    except Exception as e:
        logger.error(f"❌ Error in search_by_user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error searching by user: {str(e)}"
        )


@router.get("/messages/context", response_model=TelegramMessageContextResponse)
async def get_message_context(
    index_name: str = Query(..., description="Nome do índice"),
    msg_id: int = Query(..., description="ID da mensagem"),
    group_id: Optional[int] = Query(None, description="ID do grupo (para filtrar em índices compartilhados)"),
    before: int = Query(10, ge=0, le=50, description="Mensagens antes"),
    after: int = Query(10, ge=0, le=50, description="Mensagens depois"),
    server_id: Optional[str] = Query(None, description="ID do servidor ES"),
    current_user: dict = Depends(get_current_user)
):
    """
    Busca contexto de uma mensagem (N mensagens antes e depois)

    - **index_name**: Nome do índice onde a mensagem está
    - **msg_id**: ID da mensagem
    - **before**: Quantidade de mensagens antes (padrão: 10, max: 50)
    - **after**: Quantidade de mensagens depois (padrão: 10, max: 50)
    - **server_id**: ID do servidor Elasticsearch (opcional)
    """
    try:
        service = get_telegram_service()

        result = await service.get_message_context(
            index_name=index_name,
            msg_id=msg_id,
            group_id=group_id,
            before=before,
            after=after,
            server_id=server_id
        )

        return TelegramMessageContextResponse(
            total=result['total'],
            messages=[hit['_source'] for hit in result['messages']],
            selected_message_id=result['selected_message_id'],
            selected_index=result.get('selected_index'),
            group_title=result.get('group_title'),
            group_username=result.get('group_username')
        )

    except Exception as e:
        logger.error(f"❌ Error in get_message_context: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting message context: {str(e)}"
        )


# ==================== Statistics Endpoints ====================

@router.get("/statistics", response_model=TelegramStatisticsResponse)
async def get_statistics(
    period_days: Optional[int] = Query(None, description="Período em dias (None = all time)"),
    server_id: Optional[str] = Query(None, description="ID do servidor ES"),
    current_user: dict = Depends(get_current_user)
):
    """
    Estatísticas gerais de grupos e usuários

    - **period_days**: Período em dias (None = all time, 1, 7, 15, 30)
    - **server_id**: ID do servidor Elasticsearch (opcional)

    Retorna:
    - Total de mensagens
    - Top 20 grupos com mais mensagens
    - Top 20 usuários que mais enviaram mensagens
    """
    try:
        service = get_telegram_service()

        result = await service.get_statistics(
            period_days=period_days,
            server_id=server_id
        )

        return TelegramStatisticsResponse(**result)

    except Exception as e:
        logger.error(f"❌ Error in get_statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting statistics: {str(e)}"
        )


@router.get("/statistics/group/{group_username}", response_model=TelegramGroupStatisticsResponse)
async def get_group_statistics(
    group_username: str,
    period_days: Optional[int] = Query(None, description="Período em dias (None = all time)"),
    server_id: Optional[str] = Query(None, description="ID do servidor ES"),
    current_user: dict = Depends(get_current_user)
):
    """
    Estatísticas de um grupo específico

    - **group_username**: Username do grupo (ex: 'example_group')
    - **period_days**: Período em dias (None = all time, 1, 7, 15, 30)
    - **server_id**: ID do servidor Elasticsearch (opcional)

    Retorna:
    - Total de mensagens do grupo
    - Nome do grupo
    - Top 20 usuários mais ativos no grupo
    """
    try:
        service = get_telegram_service()

        result = await service.get_group_statistics(
            group_username=group_username,
            period_days=period_days,
            server_id=server_id
        )

        return TelegramGroupStatisticsResponse(**result)

    except Exception as e:
        logger.error(f"❌ Error in get_group_statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting group statistics: {str(e)}"
        )


@router.get("/statistics/user/{user_id}", response_model=TelegramUserStatisticsResponse)
async def get_user_statistics(
    user_id: int,
    period_days: Optional[int] = Query(None, description="Período em dias (None = all time)"),
    server_id: Optional[str] = Query(None, description="ID do servidor ES"),
    current_user: dict = Depends(get_current_user)
):
    """
    Estatísticas de um usuário específico

    - **user_id**: ID do usuário (ex: 123456789)
    - **period_days**: Período em dias (None = all time, 1, 7, 15, 30)
    - **server_id**: ID do servidor Elasticsearch (opcional)

    Retorna:
    - Total de mensagens do usuário
    - Username e nome do usuário
    - Top 20 grupos onde o usuário mais interage
    """
    try:
        service = get_telegram_service()

        result = await service.get_user_statistics(
            user_id=user_id,
            period_days=period_days,
            server_id=server_id
        )

        return TelegramUserStatisticsResponse(**result)

    except Exception as e:
        logger.error(f"❌ Error in get_user_statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting user statistics: {str(e)}"
        )


# ==================== Groups Endpoints ====================

@router.get("/groups", response_model=TelegramGroupsResponse)
async def list_groups(
    server_id: Optional[str] = Query(None, description="ID do servidor ES"),
    current_user: dict = Depends(get_current_user)
):
    """
    Lista todos os grupos disponíveis

    - **server_id**: ID do servidor Elasticsearch (opcional)

    Retorna lista de grupos ordenada por título
    """
    try:
        service = get_telegram_service()

        groups = await service.list_groups(server_id=server_id)

        return TelegramGroupsResponse(
            total=len(groups),
            groups=[hit['_source'] for hit in groups]
        )

    except Exception as e:
        logger.error(f"❌ Error in list_groups: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing groups: {str(e)}"
        )


@router.get("/groups/{group_username}/messages", response_model=TelegramGroupMessagesResponse)
async def get_group_messages(
    group_username: str,
    page: int = Query(1, ge=1, description="Número da página"),
    page_size: int = Query(20, ge=1, le=100, description="Tamanho da página"),
    server_id: Optional[str] = Query(None, description="ID do servidor ES"),
    current_user: dict = Depends(get_current_user)
):
    """
    Lê mensagens de um grupo com paginação

    - **group_username**: Username do grupo
    - **page**: Número da página (começa em 1)
    - **page_size**: Tamanho da página (padrão: 20, max: 100)
    - **server_id**: ID do servidor Elasticsearch (opcional)

    Retorna mensagens do grupo ordenadas por data (mais recentes primeiro)
    """
    try:
        service = get_telegram_service()

        result = await service.get_group_messages(
            group_username=group_username,
            page=page,
            page_size=page_size,
            server_id=server_id
        )

        # Processar mensagens
        messages = [hit['_source'] for hit in result['mensagens']]

        return TelegramGroupMessagesResponse(
            mensagens=messages,
            total=result['total'],
            titulo=result['titulo'],
            username=result['username'],
            page=result['page'],
            page_size=result['page_size'],
            total_pages=result['total_pages']
        )

    except Exception as e:
        logger.error(f"❌ Error in get_group_messages: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting group messages: {str(e)}"
        )


# ==================== Timeline Endpoint ====================

@router.get("/timeline", response_model=TelegramTimelineResponse)
async def get_timeline(
    days: int = Query(30, ge=1, le=90, description="Número de dias (max: 90)"),
    server_id: Optional[str] = Query(None, description="ID do servidor ES"),
    current_user: dict = Depends(get_current_user)
):
    """
    Timeline de mensagens por dia

    - **days**: Número de dias para timeline (padrão: 30, max: 90)
    - **server_id**: ID do servidor Elasticsearch (opcional)

    Retorna contagem de mensagens agrupadas por dia
    """
    try:
        service = get_telegram_service()

        result = await service.get_timeline(
            days=days,
            server_id=server_id
        )

        return TelegramTimelineResponse(**result)

    except Exception as e:
        logger.error(f"❌ Error in get_timeline: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting timeline: {str(e)}"
        )
