"""
Widget Schemas
Request/Response schemas para API
"""

from pydantic import BaseModel, Field
from typing import Literal, Optional, Dict, Any
from app.models.widget import WidgetPosition, WidgetData


class WidgetCreate(BaseModel):
    """Schema para criar widget"""
    title: str = Field(..., min_length=1, max_length=200)
    type: Literal['pie', 'bar', 'line', 'metric', 'table']
    position: WidgetPosition
    data: WidgetData


class WidgetUpdate(BaseModel):
    """Schema para atualizar widget (parcial)"""
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    type: Optional[Literal['pie', 'bar', 'line', 'metric', 'table']] = None
    position: Optional[WidgetPosition] = None
    data: Optional[WidgetData] = None
