"""
Telegram Search Schemas
Pydantic models for Telegram search and statistics API
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


# ==================== Request Schemas ====================

class TelegramMessageSearchRequest(BaseModel):
    """Request para busca de mensagens"""
    text: str = Field(..., description="Texto a buscar nas mensagens")
    is_exact_search: bool = Field(default=False, description="Se True, busca exata. Se False, busca inteligente")
    page: int = Field(default=1, ge=1, description="Número da página (começa em 1)")
    page_size: int = Field(default=50, ge=1, le=100, description="Tamanho da página")
    server_id: Optional[str] = Field(default=None, description="ID do servidor Elasticsearch")


class TelegramUserSearchRequest(BaseModel):
    """Request para busca por usuário"""
    search_term: str = Field(..., description="Termo de busca (user_id, username ou nome)")
    page: int = Field(default=1, ge=1, description="Número da página (começa em 1)")
    page_size: int = Field(default=50, ge=1, le=100, description="Tamanho da página")
    server_id: Optional[str] = Field(default=None, description="ID do servidor Elasticsearch")


class TelegramMessageContextRequest(BaseModel):
    """Request para contexto de mensagem"""
    index_name: str = Field(..., description="Nome do índice onde a mensagem está")
    msg_id: int = Field(..., description="ID da mensagem")
    before: int = Field(default=10, ge=0, le=50, description="Quantidade de mensagens antes")
    after: int = Field(default=10, ge=0, le=50, description="Quantidade de mensagens depois")
    server_id: Optional[str] = Field(default=None, description="ID do servidor Elasticsearch")


# ==================== Response Schemas ====================

class SenderInfo(BaseModel):
    """Informações do remetente"""
    user_id: Optional[int] = None
    username: Optional[str] = None
    full_name: Optional[str] = None


class GroupInfo(BaseModel):
    """Informações do grupo"""
    group_username: Optional[str] = None
    group_title: Optional[str] = None


class TelegramMessage(BaseModel):
    """Mensagem do Telegram"""
    id: int
    date: datetime
    message: Optional[str] = None
    sender_info: Optional[SenderInfo] = None
    group_info: Optional[GroupInfo] = None

    class Config:
        from_attributes = True


class TelegramMessageSearchResponse(BaseModel):
    """Response de busca de mensagens"""
    total: int = Field(..., description="Total de mensagens encontradas (estimado)")
    messages: List[Dict[str, Any]] = Field(default_factory=list, description="Lista de mensagens")
    search_type: str = Field(..., description="Tipo de busca utilizada")
    page: int = Field(..., description="Página atual")
    page_size: int = Field(..., description="Tamanho da página")
    has_more: bool = Field(..., description="Se há mais páginas disponíveis")


class TelegramUserSearchResponse(BaseModel):
    """Response de busca por usuário"""
    total: int = Field(..., description="Total de mensagens encontradas (estimado)")
    messages: List[Dict[str, Any]] = Field(default_factory=list, description="Lista de mensagens")
    search_term: str = Field(..., description="Termo buscado")
    page: int = Field(..., description="Página atual")
    page_size: int = Field(..., description="Tamanho da página")
    has_more: bool = Field(..., description="Se há mais páginas disponíveis")


class TelegramMessageContextResponse(BaseModel):
    """Response de contexto de mensagem"""
    total: int = Field(..., description="Total de mensagens no contexto")
    messages: List[Dict[str, Any]] = Field(default_factory=list, description="Mensagens do contexto")
    selected_message_id: int = Field(..., description="ID da mensagem selecionada")
    selected_index: Optional[int] = Field(None, description="Índice da mensagem selecionada na lista")
    group_title: Optional[str] = Field(None, description="Título do grupo")
    group_username: Optional[str] = Field(None, description="Username do grupo")


# ==================== Statistics Schemas ====================

class GroupBucket(BaseModel):
    """Bucket de grupo em agregação"""
    key: str = Field(..., description="Username do grupo")
    doc_count: int = Field(..., description="Quantidade de mensagens")
    titulo: Optional[Dict[str, Any]] = Field(default=None, description="Título do grupo")


class UserBucket(BaseModel):
    """Bucket de usuário em agregação"""
    key: int = Field(..., description="User ID")
    doc_count: int = Field(..., description="Quantidade de mensagens")
    username: Optional[Dict[str, Any]] = Field(default=None, description="Username")
    full_name: Optional[Dict[str, Any]] = Field(default=None, description="Nome completo")
    top_grupos: Optional[Dict[str, Any]] = Field(default=None, description="Top grupos do usuário")


class TelegramStatisticsResponse(BaseModel):
    """Response de estatísticas gerais"""
    total_mensagens: int = Field(..., description="Total de mensagens")
    total_grupos: int = Field(..., description="Total de grupos únicos")
    total_usuarios: int = Field(..., description="Total de usuários pesquisáveis (com username)")
    grupos: List[Dict[str, Any]] = Field(default_factory=list, description="Top grupos")
    usuarios: List[Dict[str, Any]] = Field(default_factory=list, description="Top usuários")
    period_days: Optional[int] = Field(None, description="Período em dias (None = all time)")


class TelegramGroupStatisticsResponse(BaseModel):
    """Response de estatísticas de grupo"""
    total_mensagens: int = Field(..., description="Total de mensagens do grupo")
    grupo_nome: str = Field(..., description="Nome do grupo")
    grupo_username: str = Field(..., description="Username do grupo")
    usuarios: List[Dict[str, Any]] = Field(default_factory=list, description="Top usuários do grupo")
    period_days: Optional[int] = Field(None, description="Período em dias (None = all time)")


class TelegramUserStatisticsResponse(BaseModel):
    """Response de estatísticas de usuário"""
    total_mensagens: int = Field(..., description="Total de mensagens do usuário")
    user_id: int = Field(..., description="ID do usuário")
    username: str = Field(..., description="Username do usuário")
    nome: str = Field(..., description="Nome do usuário")
    grupos: List[Dict[str, Any]] = Field(default_factory=list, description="Grupos onde o usuário interage")
    period_days: Optional[int] = Field(None, description="Período em dias (None = all time)")


# ==================== Group Listing Schemas ====================

class TelegramGroup(BaseModel):
    """Grupo do Telegram"""
    title: str
    username: str
    id: int

    class Config:
        from_attributes = True


class TelegramGroupsResponse(BaseModel):
    """Response de listagem de grupos"""
    total: int = Field(..., description="Total de grupos")
    groups: List[Dict[str, Any]] = Field(default_factory=list, description="Lista de grupos")


class TelegramGroupMessagesResponse(BaseModel):
    """Response de mensagens de um grupo"""
    mensagens: List[Dict[str, Any]] = Field(default_factory=list, description="Mensagens do grupo")
    total: int = Field(..., description="Total de mensagens")
    titulo: str = Field(..., description="Título do grupo")
    username: str = Field(..., description="Username do grupo")
    page: int = Field(..., description="Página atual")
    page_size: int = Field(..., description="Tamanho da página")
    total_pages: int = Field(..., description="Total de páginas")


# ==================== Timeline Schema ====================

class TimelineDataPoint(BaseModel):
    """Ponto de dados na timeline"""
    date: str = Field(..., description="Data (yyyy-MM-dd)")
    count: int = Field(..., description="Contagem de mensagens")


class TelegramTimelineResponse(BaseModel):
    """Response de timeline de mensagens"""
    total_days: int = Field(..., description="Total de dias na timeline")
    days: int = Field(..., description="Período solicitado (dias)")
    timeline: List[TimelineDataPoint] = Field(default_factory=list, description="Dados da timeline")
