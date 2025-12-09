"""
Widget Models
Define estruturas de dados para Widgets
"""

from pydantic import BaseModel, Field
from typing import Literal, Dict, Any, Optional
from datetime import datetime
from uuid import UUID, uuid4


class WidgetPosition(BaseModel):
    """Posição do widget no grid"""
    x: int = Field(..., description="Grid column position", ge=0)
    y: int = Field(..., description="Grid row position", ge=0)
    w: int = Field(..., description="Width in grid units", ge=1, le=12)
    h: int = Field(..., description="Height in grid units", ge=1)


class WidgetData(BaseModel):
    """Dados do widget"""
    query: Dict[str, Any] = Field(..., description="Elasticsearch query")
    results: Optional[Dict[str, Any]] = Field(None, description="Cached query results (runtime only, not persisted)")
    config: Dict[str, Any] = Field(default_factory=dict, description="Plotly configuration")


class WidgetMetadata(BaseModel):
    """Metadados do widget"""
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    created_by: Optional[str] = None
    version: int = Field(default=1, description="Widget version")


class Widget(BaseModel):
    """Widget completo"""
    id: str = Field(default_factory=lambda: str(uuid4()), description="Widget UUID")
    title: str = Field(..., min_length=1, max_length=200, description="Widget title")
    type: Literal['pie', 'bar', 'line', 'metric', 'table', 'area', 'scatter'] = Field(..., description="Visualization type")
    position: WidgetPosition
    data: WidgetData
    index: Optional[str] = Field(None, description="Elasticsearch index used by this widget")
    metadata: WidgetMetadata = Field(default_factory=WidgetMetadata)

    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "title": "Top 10 Domínios",
                "type": "pie",
                "position": {"x": 0, "y": 0, "w": 4, "h": 3},
                "data": {
                    "query": {
                        "size": 0,
                        "aggs": {
                            "domains": {
                                "terms": {"field": "domain.keyword", "size": 10}
                            }
                        }
                    },
                    "results": {},
                    "config": {"colors": ["#FF6384", "#36A2EB"]}
                },
                "metadata": {
                    "created_at": "2025-11-05T10:00:00Z",
                    "updated_at": "2025-11-05T10:00:00Z",
                    "version": 1
                }
            }
        }
