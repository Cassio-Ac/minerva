"""
Telegram Message Blacklist Model
"""
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.db.database import Base


class TelegramMessageBlacklist(Base):
    """Model for storing patterns to filter out from Telegram search results"""

    __tablename__ = "telegram_message_blacklist"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    pattern = Column(String(500), nullable=False, index=True)
    description = Column(String(1000), nullable=True)
    is_regex = Column(Boolean, default=False, nullable=False)
    case_sensitive = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    created_by = Column(UUID(as_uuid=True), nullable=True)

    def __repr__(self):
        return f"<TelegramMessageBlacklist {self.pattern}>"
