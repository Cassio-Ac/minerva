"""
Server Configuration Models
Suporte para múltiplos servidores Elasticsearch
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class ElasticsearchServer(BaseModel):
    """Configuração de um servidor Elasticsearch"""
    name: str = Field(..., description="Nome do servidor (ex: 'producao', 'dev')")
    url: str = Field(..., description="URL do Elasticsearch (ex: 'http://localhost:9200')")
    username: Optional[str] = Field(None, description="Username para autenticação")
    password: Optional[str] = Field(None, description="Password para autenticação")
    description: Optional[str] = Field(None, description="Descrição do servidor")
    created_at: datetime = Field(default_factory=datetime.now)
    is_active: bool = Field(default=True, description="Servidor ativo")

    class Config:
        json_schema_extra = {
            "example": {
                "name": "producao",
                "url": "http://localhost:9200",
                "username": "elastic",
                "password": "changeme",
                "description": "Elasticsearch de produção",
                "is_active": True
            }
        }


class ServerList(BaseModel):
    """Lista de servidores configurados"""
    servers: List[ElasticsearchServer]
    default_server: Optional[str] = None


class ServerTestResult(BaseModel):
    """Resultado do teste de conexão"""
    success: bool
    message: str
    cluster_info: Optional[dict] = None
    error: Optional[str] = None
