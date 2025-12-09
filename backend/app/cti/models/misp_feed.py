"""
MISP Feed Model

Representa feeds MISP configurados para importação de IOCs.
"""
from sqlalchemy import Column, String, Boolean, Integer, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid

from app.db.database import Base


class MISPFeed(Base):
    """Model para feeds MISP configurados"""

    __tablename__ = "misp_feeds"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False, index=True)
    url = Column(String, nullable=False)
    feed_type = Column(
        String, default="misp"
    )  # 'misp', 'csv', 'freetext'
    is_active = Column(Boolean, default=True, index=True)
    is_public = Column(Boolean, default=True)
    last_sync_at = Column(DateTime(timezone=True), nullable=True)
    total_iocs_imported = Column(Integer, default=0)
    sync_frequency = Column(
        String, default="daily"
    )  # 'hourly', 'daily', 'weekly'
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    def __repr__(self):
        return f"<MISPFeed(id={self.id}, name={self.name}, is_active={self.is_active})>"
