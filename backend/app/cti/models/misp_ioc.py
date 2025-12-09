"""
MISP IOC Model

Representa IOCs (Indicators of Compromise) importados do MISP.
"""
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text, ARRAY
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid

from app.db.database import Base


class MISPIoC(Base):
    """Model para IOCs importados do MISP"""

    __tablename__ = "misp_iocs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    feed_id = Column(
        UUID(as_uuid=True), ForeignKey("misp_feeds.id", ondelete="CASCADE"), nullable=False
    )
    ioc_type = Column(String, nullable=False, index=True)  # 'ip', 'domain', 'hash', 'url', 'email'
    ioc_subtype = Column(String, nullable=True)  # 'md5', 'sha256', 'ip-dst', 'ip-src', etc
    ioc_value = Column(Text, nullable=False, index=True)
    context = Column(Text, nullable=True)  # Ex: "WannaCry C2 server"
    malware_family = Column(String, nullable=True, index=True)
    threat_actor = Column(String, nullable=True, index=True)
    tags = Column(ARRAY(String), nullable=True)  # Array de tags
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    tlp = Column(String, default="white")  # 'white', 'green', 'amber', 'red'
    confidence = Column(String, default="medium")  # 'low', 'medium', 'high'
    to_ids = Column(Boolean, default=False)  # Flag de detecção
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationship
    # feed = relationship("MISPFeed", backref="iocs")

    def __repr__(self):
        return f"<MISPIoC(id={self.id}, type={self.ioc_type}, value={self.ioc_value[:50]})>"
