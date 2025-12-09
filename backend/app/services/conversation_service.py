"""
Conversation Service
CRUD operations for conversations in Elasticsearch
"""

from typing import List, Optional
from datetime import datetime
import logging

from app.db.elasticsearch import get_es_client
from app.models.conversation import (
    Conversation,
    ConversationMessage,
    ConversationListItem,
    ChatWidget,
)

logger = logging.getLogger(__name__)


class ConversationService:
    """Service para operações de Conversation"""

    INDEX_NAME = "conversations"

    async def create(self, conversation: Conversation) -> Conversation:
        """Cria uma nova conversa"""
        es = await get_es_client()

        # Preparar para salvamento
        conversation_dict = conversation.model_dump(mode='json')

        # Salvar no ES
        try:
            await es.index(
                index=self.INDEX_NAME,
                id=conversation.id,
                document=conversation_dict,
                refresh=True,
            )

            logger.info(f"✅ Conversation created: {conversation.id}")
            return conversation

        except Exception as e:
            logger.error(f"❌ Error creating conversation: {e}")
            raise

    async def get(self, conversation_id: str) -> Optional[Conversation]:
        """Busca conversa por ID"""
        es = await get_es_client()

        try:
            result = await es.get(index=self.INDEX_NAME, id=conversation_id)
            conversation_dict = result["_source"]
            return Conversation(**conversation_dict)

        except Exception as e:
            logger.error(f"❌ Error getting conversation {conversation_id}: {e}")
            return None

    async def update(self, conversation_id: str, conversation: Conversation) -> Optional[Conversation]:
        """Atualiza conversa completa"""
        es = await get_es_client()

        try:
            # Atualizar timestamp
            conversation.updated_at = datetime.now()

            # Preparar para salvamento
            conversation_dict = conversation.model_dump(mode='json')

            # Salvar no ES
            await es.index(
                index=self.INDEX_NAME,
                id=conversation_id,
                document=conversation_dict,
                refresh=True,
            )

            logger.info(f"✅ Conversation updated: {conversation_id}")
            return conversation

        except Exception as e:
            logger.error(f"❌ Error updating conversation {conversation_id}: {e}")
            raise

    async def add_message(
        self,
        conversation_id: str,
        message: ConversationMessage,
    ) -> Optional[Conversation]:
        """Adiciona mensagem a uma conversa existente"""
        es = await get_es_client()

        try:
            # Buscar conversa atual
            conversation = await self.get(conversation_id)
            if not conversation:
                logger.error(f"❌ Conversation {conversation_id} not found")
                return None

            # Adicionar nova mensagem
            conversation.messages.append(message)
            conversation.updated_at = datetime.now()

            # Salvar atualização
            conversation_dict = conversation.model_dump(mode='json')
            await es.index(
                index=self.INDEX_NAME,
                id=conversation_id,
                document=conversation_dict,
                refresh=True,
            )

            logger.info(f"✅ Message added to conversation: {conversation_id}")
            return conversation

        except Exception as e:
            logger.error(f"❌ Error adding message to conversation {conversation_id}: {e}")
            raise

    async def delete(self, conversation_id: str) -> bool:
        """Deleta conversa"""
        es = await get_es_client()

        try:
            await es.delete(index=self.INDEX_NAME, id=conversation_id, refresh=True)
            logger.info(f"✅ Conversation deleted: {conversation_id}")
            return True

        except Exception as e:
            logger.error(f"❌ Error deleting conversation {conversation_id}: {e}")
            return False

    async def list(
        self,
        skip: int = 0,
        limit: int = 50,
        index: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> List[ConversationListItem]:
        """Lista conversas com filtros"""
        es = await get_es_client()

        # Construir query
        query = {"bool": {"must": []}}

        if index:
            query["bool"]["must"].append({"term": {"index": index}})

        if created_by:
            query["bool"]["must"].append({"term": {"created_by": created_by}})

        if not query["bool"]["must"]:
            query = {"match_all": {}}

        try:
            result = await es.search(
                index=self.INDEX_NAME,
                query=query,
                from_=skip,
                size=limit,
                sort=[{"updated_at": {"order": "desc"}}],
            )

            conversations = []
            for hit in result["hits"]["hits"]:
                data = hit["_source"]
                conversations.append(
                    ConversationListItem(
                        id=data["id"],
                        title=data["title"],
                        index=data["index"],
                        message_count=len(data.get("messages", [])),
                        created_at=data["created_at"],
                        updated_at=data["updated_at"],
                    )
                )

            logger.info(f"✅ Listed {len(conversations)} conversations")
            return conversations

        except Exception as e:
            logger.error(f"❌ Error listing conversations: {e}")
            return []


# Singleton instance
_conversation_service: Optional[ConversationService] = None


def get_conversation_service() -> ConversationService:
    """Retorna instância do service"""
    global _conversation_service
    if _conversation_service is None:
        _conversation_service = ConversationService()
    return _conversation_service
