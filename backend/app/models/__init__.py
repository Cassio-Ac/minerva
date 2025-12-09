"""Models module"""
from app.models.widget import Widget, WidgetPosition, WidgetData, WidgetMetadata
from app.models.dashboard import Dashboard, DashboardLayout, DashboardMetadata, DashboardListItem
from app.models.conversation import (
    Conversation,
    ConversationMessage,
    ConversationListItem,
    ChatWidget,
)
# User models are imported directly in endpoints (not here to avoid circular imports)
# from app.models.user import User, UserRole
# from app.models.dashboard_permission import DashboardPermission, DashboardShare, DashboardVisibility

__all__ = [
    "Widget",
    "WidgetPosition",
    "WidgetData",
    "WidgetMetadata",
    "Dashboard",
    "DashboardLayout",
    "DashboardMetadata",
    "DashboardListItem",
    "Conversation",
    "ConversationMessage",
    "ConversationListItem",
    "ChatWidget",
]
