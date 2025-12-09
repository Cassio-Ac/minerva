"""
Dashboard Models
Define estruturas de dados para Dashboards
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import uuid4

from app.models.widget import Widget


class DashboardLayout(BaseModel):
    """Configuração de layout do dashboard"""
    cols: int = Field(default=12, description="Number of columns", ge=1, le=24)
    row_height: int = Field(default=30, description="Row height in pixels", ge=10)
    width: int = Field(default=1600, description="Total width in pixels", ge=800)


class DashboardMetadata(BaseModel):
    """Metadados do dashboard"""
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    created_by: Optional[str] = None
    is_public: bool = Field(default=False, description="Dashboard visibility")
    tags: List[str] = Field(default_factory=list, description="Dashboard tags")
    version: int = Field(default=1, description="Dashboard version")


class Dashboard(BaseModel):
    """Dashboard completo"""
    id: str = Field(default_factory=lambda: str(uuid4()), description="Dashboard UUID")
    title: str = Field(..., min_length=1, max_length=200, description="Dashboard title")
    description: Optional[str] = Field(None, max_length=1000, description="Dashboard description")
    layout: DashboardLayout = Field(default_factory=DashboardLayout)
    widgets: List[Widget] = Field(default_factory=list, description="List of widgets")
    index: str = Field(..., description="Elasticsearch index name")
    server_id: Optional[str] = Field(None, description="Elasticsearch server ID to use for queries")
    metadata: DashboardMetadata = Field(default_factory=DashboardMetadata)

    class Config:
        json_schema_extra = {
            "example": {
                "id": "dashboard-uuid-123",
                "title": "Análise de Vazamentos",
                "description": "Dashboard para análise de dados de vazamentos",
                "layout": {
                    "cols": 12,
                    "row_height": 30,
                    "width": 1600
                },
                "widgets": [
                    {
                        "id": "widget-uuid-1",
                        "title": "Top 10 Domínios",
                        "type": "pie",
                        "position": {"x": 0, "y": 0, "w": 6, "h": 4},
                        "data": {"query": {}, "config": {}}
                    }
                ],
                "index": "vazamentos",
                "server_id": "es-server-uuid-123",
                "metadata": {
                    "created_at": "2025-11-05T10:00:00Z",
                    "is_public": False,
                    "tags": ["vazamentos", "segurança"]
                }
            }
        }


class DashboardListItem(BaseModel):
    """Dashboard list item (resumo)"""
    id: str
    title: str
    description: Optional[str] = None
    index: str
    widget_count: int = 0
    created_at: datetime
    updated_at: datetime
    tags: List[str] = Field(default_factory=list)

    class Config:
        json_schema_extra = {
            "example": {
                "id": "dashboard-uuid-123",
                "title": "Análise de Vazamentos",
                "description": "Dashboard para análise...",
                "index": "vazamentos",
                "widget_count": 5,
                "created_at": "2025-11-05T10:00:00Z",
                "updated_at": "2025-11-05T12:00:00Z",
                "tags": ["vazamentos", "segurança"]
            }
        }
