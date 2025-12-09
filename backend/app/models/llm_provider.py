"""
LLM Provider Model
Database model for LLM provider configurations
"""

from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.sql import func
from app.db.database import Base
import uuid


class LLMProvider(Base):
    """LLM Provider configuration"""

    __tablename__ = "llm_providers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)  # User-friendly name
    provider_type = Column(String, nullable=False)  # 'anthropic', 'openai', 'databricks', etc
    model_name = Column(String, nullable=False)  # e.g., 'claude-3-5-sonnet-20241022'
    api_key_encrypted = Column(String, nullable=False)  # Encrypted API key
    api_base_url = Column(String, nullable=True)  # Optional custom base URL
    temperature = Column(Float, nullable=False, default=0.1)
    max_tokens = Column(Integer, nullable=False, default=4000)
    is_active = Column(Boolean, nullable=False, default=True)
    is_default = Column(Boolean, nullable=False, default=False)
    extra_config = Column(JSONB, nullable=True)  # Provider-specific config
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    def __repr__(self):
        return f"<LLMProvider(id={self.id}, name={self.name}, type={self.provider_type}, model={self.model_name})>"
