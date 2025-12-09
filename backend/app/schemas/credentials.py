"""
Schemas para o módulo Credentials

Consulta Externa e Data Lake
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import datetime
from uuid import UUID


# ============================================================
# External Query Schemas
# ============================================================

class ExternalQueryRequest(BaseModel):
    """Request para consulta externa"""
    query_value: str = Field(..., description="Valor a consultar (tipo detectado automaticamente)")
    auto_download: bool = Field(default=True, description="Baixar resultado automaticamente")


class ExternalQueryResponse(BaseModel):
    """Response de consulta externa"""
    id: UUID
    query_type: str  # Tipo detectado automaticamente
    query_type_display: Optional[str] = None  # Nome amigável do tipo
    query_value: str
    bot_name: str
    found: bool
    result_count: int
    result_preview: Optional[str] = None
    html_url: Optional[str] = None  # URL para visualizar o HTML
    download_url: Optional[str] = None  # URL para baixar o arquivo
    status: str
    error_message: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ExternalQueryHistoryItem(BaseModel):
    """Item do histórico de consultas"""
    id: UUID
    query_type: str
    query_value: str
    bot_name: Optional[str]
    found: bool
    result_count: int
    status: str
    created_at: datetime
    created_by: Optional[str]
    html_available: bool = False  # Se o HTML ainda está disponível
    days_remaining: int = 0  # Dias restantes até expirar

    class Config:
        from_attributes = True


class ExternalQueryHistory(BaseModel):
    """Lista de histórico de consultas"""
    total: int
    queries: List[ExternalQueryHistoryItem]


# ============================================================
# Bot Configuration Schemas
# ============================================================

class TelegramBotConfig(BaseModel):
    """Configuração de um bot do Telegram"""
    bot_id: str
    bot_name: str
    description: str
    supported_query_types: List[str]
    is_active: bool = True


class TelegramAccountConfig(BaseModel):
    """Configuração de conta Telegram para consultas"""
    session_name: str
    phone: str
    is_default: bool = False
    last_used: Optional[datetime] = None


# ============================================================
# HTML Result Schema
# ============================================================

class HTMLResultResponse(BaseModel):
    """Response com conteúdo HTML"""
    query_id: UUID
    query_value: str
    html_content: str
    file_name: str
    created_at: datetime


# ============================================================
# Stats Schema
# ============================================================

class CredentialsStats(BaseModel):
    """Estatísticas do módulo Credentials"""
    total_queries: int
    queries_today: int
    queries_with_results: int
    success_rate: float
    top_query_types: dict
    recent_queries: List[ExternalQueryHistoryItem]
