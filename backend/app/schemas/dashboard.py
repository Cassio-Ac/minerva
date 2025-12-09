"""
Dashboard Schemas
Request/Response schemas para API
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from app.models.widget import Widget
from app.models.dashboard import DashboardLayout


class DashboardCreate(BaseModel):
    """Schema para criar dashboard"""
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    index: str = Field(..., description="Elasticsearch index name")
    server_id: Optional[str] = Field(None, description="Elasticsearch server ID")
    layout: Optional[DashboardLayout] = None
    widgets: List[Widget] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class DashboardUpdate(BaseModel):
    """Schema para atualizar dashboard (parcial)"""
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    index: Optional[str] = Field(None, description="Elasticsearch index name")
    server_id: Optional[str] = Field(None, description="Elasticsearch server ID")
    layout: Optional[DashboardLayout] = None
    widgets: Optional[List[Widget]] = None
    tags: Optional[List[str]] = None
