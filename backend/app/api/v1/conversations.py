"""
Conversation API Endpoints
CRUD operations for conversations
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import logging

from app.db.database import get_db
from app.models.conversation import (
    Conversation,
    ConversationMessage,
    ConversationListItem,
)
from app.schemas.conversation import (
    ConversationCreate,
    ConversationUpdate,
    MessageCreate,
)
from app.services.conversation_service_sql import get_conversation_service_sql

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("", response_model=Conversation, status_code=201)
async def create_conversation(data: ConversationCreate, db: AsyncSession = Depends(get_db)):
    """
    Cria nova conversa
    """
    service = get_conversation_service_sql()

    try:
        # Criar conversa com mensagem inicial do assistente
        conversation = Conversation(
            title=data.title,
            index=data.index,
            server_id=data.server_id,
            created_by=data.created_by,
            messages=[
                ConversationMessage(
                    role="assistant",
                    content=f"Olá! Estou aqui para ajudar você a explorar o índice **{data.index}**.\n\nVocê pode me fazer perguntas como:\n- \"Mostre um gráfico de pizza com as categorias\"\n- \"Qual é o total de registros?\"\n- \"Crie um gráfico de linha mostrando a evolução temporal\"\n- \"Quais são os top 10 valores do campo X?\"\n\nTodas as visualizações que eu criar aparecerão aqui no chat!",
                )
            ],
        )

        return await service.create(db, conversation)

    except Exception as e:
        logger.error(f"Error creating conversation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("", response_model=List[ConversationListItem])
async def list_conversations(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    index: Optional[str] = Query(None),
    created_by: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Lista conversas com filtros opcionais
    """
    service = get_conversation_service_sql()

    try:
        return await service.list(db, skip=skip, limit=limit, index=index, created_by=created_by)
    except Exception as e:
        logger.error(f"Error listing conversations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{conversation_id}", response_model=Conversation)
async def get_conversation(conversation_id: str, db: AsyncSession = Depends(get_db)):
    """
    Busca conversa por ID
    """
    service = get_conversation_service_sql()

    try:
        conversation = await service.get(db, conversation_id)
        if not conversation:
            raise HTTPException(status_code=404, detail="Conversation not found")
        return conversation

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting conversation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{conversation_id}", response_model=Conversation)
async def update_conversation(
    conversation_id: str, data: ConversationUpdate, db: AsyncSession = Depends(get_db)
):
    """
    Atualiza informações da conversa (ex: título)
    """
    service = get_conversation_service_sql()

    try:
        conversation = await service.get(db, conversation_id)
        if not conversation:
            raise HTTPException(status_code=404, detail="Conversation not found")

        # Atualizar campos
        if data.title is not None:
            conversation.title = data.title

        return await service.update(db, conversation_id, conversation)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating conversation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{conversation_id}/messages", response_model=Conversation)
async def add_message(
    conversation_id: str, data: MessageCreate, db: AsyncSession = Depends(get_db)
):
    """
    Adiciona mensagem a uma conversa
    """
    service = get_conversation_service_sql()

    try:
        message = ConversationMessage(
            role=data.role,
            content=data.content,
            widget=data.widget,
        )

        conversation = await service.add_message(db, conversation_id, message)
        if not conversation:
            raise HTTPException(status_code=404, detail="Conversation not found")

        return conversation

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding message: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{conversation_id}", status_code=204)
async def delete_conversation(conversation_id: str, db: AsyncSession = Depends(get_db)):
    """
    Deleta conversa
    """
    service = get_conversation_service_sql()

    try:
        success = await service.delete_conversation(db, conversation_id)
        if not success:
            raise HTTPException(status_code=404, detail="Conversation not found")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting conversation: {e}")
        raise HTTPException(status_code=500, detail=str(e))
