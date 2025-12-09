"""
Conversation Service - SQL Version
CRUD operations for conversations in PostgreSQL
"""

from typing import List, Optional
from datetime import datetime
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from app.db.models import Conversation as ConversationDB
from app.models.conversation import (
    Conversation,
    ConversationMessage,
    ConversationListItem,
)

logger = logging.getLogger(__name__)


class ConversationServiceSQL:
    """Service para operações de Conversation usando PostgreSQL"""

    async def create(self, db: AsyncSession, conversation: Conversation) -> Conversation:
        """Cria uma nova conversa"""
        try:
            # Converter Pydantic model para SQLAlchemy model
            db_conversation = ConversationDB(
                id=conversation.id,
                title=conversation.title,
                index=conversation.index,
                server_id=conversation.server_id,
                messages=[msg.model_dump(mode='json') for msg in conversation.messages],
                created_by=conversation.created_by,
                created_at=conversation.created_at,
                updated_at=conversation.updated_at,
            )

            db.add(db_conversation)
            await db.flush()
            await db.refresh(db_conversation)

            logger.info(f"✅ Conversation created in SQL: {conversation.id}")
            return self._to_pydantic(db_conversation)

        except Exception as e:
            logger.error(f"❌ Error creating conversation: {e}")
            raise

    async def get(self, db: AsyncSession, conversation_id: str) -> Optional[Conversation]:
        """Busca conversa por ID"""
        try:
            stmt = select(ConversationDB).where(ConversationDB.id == conversation_id)
            result = await db.execute(stmt)
            db_conversation = result.scalar_one_or_none()

            if db_conversation:
                return self._to_pydantic(db_conversation)
            return None

        except Exception as e:
            logger.error(f"❌ Error getting conversation {conversation_id}: {e}")
            return None

    async def update(
        self, db: AsyncSession, conversation_id: str, conversation: Conversation
    ) -> Optional[Conversation]:
        """Atualiza conversa completa"""
        try:
            # Atualizar timestamp
            conversation.updated_at = datetime.utcnow()

            stmt = (
                update(ConversationDB)
                .where(ConversationDB.id == conversation_id)
                .values(
                    title=conversation.title,
                    index=conversation.index,
                    server_id=conversation.server_id,
                    messages=[msg.model_dump(mode='json') for msg in conversation.messages],
                    updated_at=conversation.updated_at,
                )
                .returning(ConversationDB)
            )

            result = await db.execute(stmt)
            await db.flush()
            db_conversation = result.scalar_one_or_none()

            if db_conversation:
                logger.info(f"✅ Conversation updated in SQL: {conversation_id}")
                return self._to_pydantic(db_conversation)
            return None

        except Exception as e:
            logger.error(f"❌ Error updating conversation {conversation_id}: {e}")
            raise

    async def add_message(
        self, db: AsyncSession, conversation_id: str, message: ConversationMessage
    ) -> Optional[Conversation]:
        """Adiciona mensagem a uma conversa existente"""
        try:
            # Buscar conversa atual
            conversation = await self.get(db, conversation_id)
            if not conversation:
                logger.error(f"❌ Conversation {conversation_id} not found")
                return None

            # Adicionar nova mensagem
            conversation.messages.append(message)
            conversation.updated_at = datetime.utcnow()

            # Atualizar no banco
            return await self.update(db, conversation_id, conversation)

        except Exception as e:
            logger.error(f"❌ Error adding message to conversation {conversation_id}: {e}")
            raise

    async def delete_conversation(self, db: AsyncSession, conversation_id: str) -> bool:
        """Deleta conversa"""
        try:
            stmt = delete(ConversationDB).where(ConversationDB.id == conversation_id)
            result = await db.execute(stmt)
            await db.flush()

            if result.rowcount > 0:
                logger.info(f"✅ Conversation deleted from SQL: {conversation_id}")
                return True
            return False

        except Exception as e:
            logger.error(f"❌ Error deleting conversation {conversation_id}: {e}")
            return False

    async def list(
        self,
        db: AsyncSession,
        skip: int = 0,
        limit: int = 50,
        index: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> List[ConversationListItem]:
        """Lista conversas com filtros"""
        try:
            stmt = select(ConversationDB)

            # Aplicar filtros
            if index:
                stmt = stmt.where(ConversationDB.index == index)
            if created_by:
                stmt = stmt.where(ConversationDB.created_by == created_by)

            # Ordenar por updated_at desc
            stmt = stmt.order_by(ConversationDB.updated_at.desc())

            # Paginação
            stmt = stmt.offset(skip).limit(limit)

            result = await db.execute(stmt)
            db_conversations = result.scalars().all()

            # Converter para ConversationListItem
            conversations = []
            for db_conv in db_conversations:
                conversations.append(
                    ConversationListItem(
                        id=db_conv.id,
                        title=db_conv.title,
                        index=db_conv.index,
                        message_count=len(db_conv.messages),
                        created_at=db_conv.created_at,
                        updated_at=db_conv.updated_at,
                    )
                )

            logger.info(f"✅ Listed {len(conversations)} conversations from SQL")
            return conversations

        except Exception as e:
            logger.error(f"❌ Error listing conversations: {e}")
            return []

    def _to_pydantic(self, db_conversation: ConversationDB) -> Conversation:
        """Converte SQLAlchemy model para Pydantic model"""
        return Conversation(
            id=db_conversation.id,
            title=db_conversation.title,
            index=db_conversation.index,
            server_id=db_conversation.server_id,
            messages=[ConversationMessage(**msg) for msg in db_conversation.messages],
            created_by=db_conversation.created_by,
            created_at=db_conversation.created_at,
            updated_at=db_conversation.updated_at,
        )


# Singleton instance
_conversation_service_sql: Optional[ConversationServiceSQL] = None


def get_conversation_service_sql() -> ConversationServiceSQL:
    """Retorna instância do service"""
    global _conversation_service_sql
    if _conversation_service_sql is None:
        _conversation_service_sql = ConversationServiceSQL()
    return _conversation_service_sql
