"""
Conversation Models
Define estruturas de dados para Conversas com IA
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import uuid4


class ChatWidget(BaseModel):
    """Widget criado no chat (com query + dados completos)"""
    title: str = Field(..., description="Widget title")
    type: str = Field(..., description="Visualization type (pie, bar, line, etc)")
    query: Dict[str, Any] = Field(..., description="Elasticsearch query used")
    data: Dict[str, Any] = Field(..., description="Query results and Plotly config")
    config: Optional[Dict[str, Any]] = Field(None, description="Additional widget configuration")


class ConversationMessage(BaseModel):
    """Mensagem individual em uma conversa"""
    id: str = Field(default_factory=lambda: str(uuid4()), description="Message UUID")
    role: str = Field(..., description="Message role: 'user' or 'assistant'")
    content: str = Field(..., description="Message text content")
    timestamp: datetime = Field(default_factory=datetime.now, description="Message timestamp")
    widget: Optional[ChatWidget] = Field(None, description="Widget attached to message (if any)")


class Conversation(BaseModel):
    """Conversa completa com histórico de mensagens"""
    id: str = Field(default_factory=lambda: str(uuid4()), description="Conversation UUID")
    title: str = Field(..., min_length=1, max_length=200, description="Conversation title")
    index: Optional[str] = Field(None, description="Primary Elasticsearch index (optional, conversations can span multiple indices)")
    server_id: Optional[str] = Field(None, description="Elasticsearch server ID")
    messages: List[ConversationMessage] = Field(default_factory=list, description="Message history")
    created_at: datetime = Field(default_factory=datetime.now, description="Creation timestamp")
    updated_at: datetime = Field(default_factory=datetime.now, description="Last update timestamp")
    created_by: str = Field(..., description="User ID who created conversation")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "conv-uuid-123",
                "title": "Análise de Vazamentos - Sessão 1",
                "index": "vazamentos",
                "server_id": "es-server-uuid-123",
                "messages": [
                    {
                        "id": "msg-uuid-1",
                        "role": "user",
                        "content": "Mostre um gráfico de pizza das categorias",
                        "timestamp": "2025-11-06T10:00:00Z"
                    },
                    {
                        "id": "msg-uuid-2",
                        "role": "assistant",
                        "content": "Aqui está o gráfico de pizza mostrando a distribuição por categoria",
                        "timestamp": "2025-11-06T10:00:05Z",
                        "widget": {
                            "title": "Distribuição por Categoria",
                            "type": "pie",
                            "query": {"aggs": {"categories": {"terms": {"field": "category.keyword"}}}},
                            "data": {
                                "results": {"buckets": [{"key": "A", "doc_count": 100}]},
                                "config": {"data": [{"type": "pie", "labels": ["A"], "values": [100]}]}
                            }
                        }
                    }
                ],
                "created_at": "2025-11-06T10:00:00Z",
                "updated_at": "2025-11-06T10:05:00Z"
            }
        }


class ConversationListItem(BaseModel):
    """Conversation list item (resumo)"""
    id: str
    title: str
    index: str
    message_count: int = 0
    created_at: datetime
    updated_at: datetime

    class Config:
        json_schema_extra = {
            "example": {
                "id": "conv-uuid-123",
                "title": "Análise de Vazamentos - Sessão 1",
                "index": "vazamentos",
                "message_count": 15,
                "created_at": "2025-11-06T10:00:00Z",
                "updated_at": "2025-11-06T12:30:00Z"
            }
        }
