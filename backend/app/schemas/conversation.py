"""
Conversation Schemas
Request/Response schemas for Conversation API
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

from app.models.conversation import ConversationMessage, ChatWidget


class ConversationCreate(BaseModel):
    """Schema para criar nova conversa"""
    title: str = Field(..., min_length=1, max_length=200)
    index: Optional[str] = Field(None, description="Primary Elasticsearch index (optional)")
    server_id: Optional[str] = Field(None, description="ES server ID")
    created_by: str = Field(..., description="User ID (required)")

    class Config:
        json_schema_extra = {
            "example": {
                "title": "Análise de Vazamentos - Sessão 1",
                "index": "vazamentos",
                "server_id": "es-server-uuid-123",
                "created_by": "user-123"
            }
        }


class ConversationUpdate(BaseModel):
    """Schema para atualizar conversa"""
    title: Optional[str] = Field(None, min_length=1, max_length=200)

    class Config:
        json_schema_extra = {
            "example": {
                "title": "Análise de Vazamentos - Sessão 1 (Atualizada)"
            }
        }


class MessageCreate(BaseModel):
    """Schema para adicionar mensagem a conversa"""
    role: str = Field(..., description="Message role: 'user' or 'assistant'")
    content: str = Field(..., description="Message content")
    widget: Optional[ChatWidget] = Field(None, description="Widget attached to message")

    class Config:
        json_schema_extra = {
            "example": {
                "role": "user",
                "content": "Mostre um gráfico de pizza das categorias",
                "widget": None
            }
        }
