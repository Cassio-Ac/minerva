"""
Elasticsearch Server Models
Define estruturas de dados para servidores Elasticsearch
"""

from pydantic import BaseModel, Field, HttpUrl, field_validator
from typing import Optional, Literal
from datetime import datetime
from uuid import uuid4


class ESServerConnection(BaseModel):
    """Configuração de conexão ES"""
    url: str = Field(..., description="URL do servidor Elasticsearch (http://host:port)")
    username: Optional[str] = Field(None, description="Username para autenticação")
    password: Optional[str] = Field(None, description="Password (será criptografada)")
    verify_ssl: bool = Field(default=True, description="Verificar certificado SSL")
    timeout: int = Field(default=30, ge=5, le=300, description="Timeout em segundos")

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Valida formato da URL"""
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL deve começar com http:// ou https://')
        if v.endswith('/'):
            v = v[:-1]  # Remove trailing slash
        return v


class ESServerMetadata(BaseModel):
    """Metadados do servidor"""
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    last_test: Optional[datetime] = None
    last_test_status: Optional[Literal['success', 'failed', 'pending']] = None
    last_error: Optional[str] = None
    version: Optional[str] = Field(None, description="Versão do Elasticsearch")


class ESServerStats(BaseModel):
    """Estatísticas do servidor"""
    total_indices: int = 0
    total_documents: int = 0
    cluster_health: Optional[Literal['green', 'yellow', 'red']] = None
    cluster_name: Optional[str] = None
    node_count: int = 0


class ElasticsearchServer(BaseModel):
    """Servidor Elasticsearch completo"""
    id: str = Field(default_factory=lambda: str(uuid4()), description="UUID do servidor")
    name: str = Field(..., min_length=1, max_length=100, description="Nome amigável do servidor")
    description: Optional[str] = Field(None, max_length=500, description="Descrição do servidor")

    connection: ESServerConnection
    metadata: ESServerMetadata = Field(default_factory=ESServerMetadata)
    stats: ESServerStats = Field(default_factory=ESServerStats)

    is_active: bool = Field(default=True, description="Servidor ativo/inativo")
    is_default: bool = Field(default=False, description="Servidor padrão")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "Production ES Cluster",
                "description": "Cluster principal de produção",
                "connection": {
                    "url": "https://es-prod.company.com:9200",
                    "username": "elastic",
                    "password": "changeme",
                    "verify_ssl": True,
                    "timeout": 30
                },
                "is_active": True,
                "is_default": True,
                "metadata": {
                    "created_at": "2025-11-06T10:00:00Z",
                    "updated_at": "2025-11-06T10:00:00Z",
                    "last_test": "2025-11-06T14:00:00Z",
                    "last_test_status": "success",
                    "version": "8.12.0"
                },
                "stats": {
                    "total_indices": 150,
                    "total_documents": 5000000,
                    "cluster_health": "green",
                    "cluster_name": "production-cluster",
                    "node_count": 5
                }
            }
        }


class ESServerCreate(BaseModel):
    """Schema para criar servidor"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    connection: ESServerConnection
    is_default: bool = Field(default=False)


class ESServerUpdate(BaseModel):
    """Schema para atualizar servidor"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    connection: Optional[ESServerConnection] = None
    is_active: Optional[bool] = None
    is_default: Optional[bool] = None


class ESServerTestResult(BaseModel):
    """Resultado do teste de conexão"""
    success: bool
    message: str
    version: Optional[str] = None
    cluster_name: Optional[str] = None
    cluster_health: Optional[Literal['green', 'yellow', 'red']] = None
    node_count: Optional[int] = None
    error: Optional[str] = None


class ESIndexInfo(BaseModel):
    """Informações de um índice"""
    name: str
    doc_count: int = 0
    size_in_bytes: int = 0
    health: Optional[Literal['green', 'yellow', 'red']] = None
    status: Optional[Literal['open', 'close']] = None
    primary_shards: int = 0
    replica_shards: int = 0
