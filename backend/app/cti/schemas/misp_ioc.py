"""
MISP IOC Schemas

Pydantic schemas para validação e serialização de IOCs.
"""
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from uuid import UUID


class MISPFeedBase(BaseModel):
    """Base schema para feed MISP"""

    name: str = Field(..., description="Nome do feed")
    url: str = Field(..., description="URL do feed")
    feed_type: str = Field(default="misp", description="Tipo do feed")
    is_active: bool = Field(default=True, description="Feed ativo")
    is_public: bool = Field(default=True, description="Feed público")
    sync_frequency: str = Field(default="daily", description="Frequência de sync")


class MISPFeedCreate(MISPFeedBase):
    """Schema para criar feed"""

    pass


class MISPFeedUpdate(BaseModel):
    """Schema para atualizar feed"""

    name: Optional[str] = None
    url: Optional[str] = None
    feed_type: Optional[str] = None
    is_active: Optional[bool] = None
    is_public: Optional[bool] = None
    sync_frequency: Optional[str] = None


class MISPFeed(MISPFeedBase):
    """Schema completo de feed"""

    id: UUID
    last_sync_at: Optional[datetime] = None
    total_iocs_imported: int = 0
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class MISPIoCBase(BaseModel):
    """Base schema para IOC"""

    ioc_type: str = Field(..., description="Tipo do IOC")
    ioc_subtype: Optional[str] = Field(None, description="Subtipo do IOC")
    ioc_value: str = Field(..., description="Valor do IOC")
    context: Optional[str] = Field(None, description="Contexto do IOC")
    malware_family: Optional[str] = Field(None, description="Família de malware")
    threat_actor: Optional[str] = Field(None, description="Threat actor")
    tags: Optional[List[str]] = Field(None, description="Tags")
    first_seen: Optional[datetime] = Field(None, description="Primeira observação")
    last_seen: Optional[datetime] = Field(None, description="Última observação")
    tlp: str = Field(default="white", description="TLP level")
    confidence: str = Field(default="medium", description="Nível de confiança")
    to_ids: bool = Field(default=False, description="Flag de detecção")


class MISPIoCCreate(MISPIoCBase):
    """Schema para criar IOC"""

    feed_id: UUID


class MISPIoC(MISPIoCBase):
    """Schema completo de IOC"""

    id: UUID
    feed_id: UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class MISPIoCSearch(BaseModel):
    """Schema de resposta para busca de IOC"""

    found: bool
    ioc: Optional[MISPIoC] = None
    message: Optional[str] = None


class MISPIoCStats(BaseModel):
    """Schema de estatísticas de IOCs"""

    total_iocs: int
    by_type: dict
    by_tlp: dict
    by_confidence: dict
    by_feed: dict
    feeds_count: int
    last_sync: Optional[datetime] = None
