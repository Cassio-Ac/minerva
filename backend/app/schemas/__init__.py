"""Schemas module"""
from app.schemas.dashboard import DashboardCreate, DashboardUpdate
from app.schemas.widget import WidgetCreate, WidgetUpdate

__all__ = [
    "DashboardCreate",
    "DashboardUpdate",
    "WidgetCreate",
    "WidgetUpdate",
]
