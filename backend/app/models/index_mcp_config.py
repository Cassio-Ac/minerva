"""
Index MCP Configuration Model
Configuração de quais MCPs usar para cada índice do Elasticsearch
"""
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.db.database import Base


class IndexMCPConfig(Base):
    """
    Configuração de MCPs por índice do Elasticsearch

    Permite definir quais MCP servers devem ser usados para cada índice,
    com prioridade e configurações específicas.
    """
    __tablename__ = "index_mcp_config"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Referências
    es_server_id = Column(UUID(as_uuid=True), ForeignKey("es_servers.id", ondelete="CASCADE"), nullable=False, index=True)
    index_name = Column(String(255), nullable=False, index=True)
    mcp_server_id = Column(UUID(as_uuid=True), ForeignKey("mcp_servers.id", ondelete="CASCADE"), nullable=False, index=True)

    # Configuração
    priority = Column(Integer, nullable=False, default=10, index=True)  # Lower number = higher priority
    is_enabled = Column(Boolean, nullable=False, default=True)
    auto_inject_context = Column(Boolean, nullable=False, default=True)  # Auto-inject MCP tools into LLM context

    # Configurações adicionais específicas (JSON)
    config = Column(JSONB, nullable=True)  # e.g., {"max_results": 10, "filters": {...}}

    # Metadata
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Relationships
    es_server = relationship("ESServer", back_populates="index_mcp_configs")
    mcp_server = relationship("MCPServer", back_populates="index_configs")
    created_by = relationship("User", foreign_keys=[created_by_id])

    def __repr__(self):
        return f"<IndexMCPConfig(index={self.index_name}, mcp={self.mcp_server_id}, priority={self.priority})>"

    def to_dict(self):
        """Convert to dictionary"""
        return {
            "id": str(self.id),
            "es_server_id": str(self.es_server_id),
            "index_name": self.index_name,
            "mcp_server_id": str(self.mcp_server_id),
            "priority": self.priority,
            "is_enabled": self.is_enabled,
            "auto_inject_context": self.auto_inject_context,
            "config": self.config,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_by_id": str(self.created_by_id) if self.created_by_id else None,
        }
