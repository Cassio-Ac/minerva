"""
User Index Access Model
Gerencia o acesso de usuários OPERATOR a índices específicos do Elasticsearch
"""
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from app.db.database import Base


class UserIndexAccess(Base):
    """
    User Index Access Model
    Define quais índices um usuário OPERATOR pode acessar
    """
    __tablename__ = "user_index_accesses"
    __table_args__ = (
        UniqueConstraint('user_id', 'es_server_id', 'index_name', name='uix_user_server_index'),
        {'extend_existing': True}
    )

    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # User reference
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    # Elasticsearch Server reference
    es_server_id = Column(UUID(as_uuid=True), nullable=False, index=True)

    # Index name (pode usar wildcard: gvuln*, logs-2024-*)
    index_name = Column(String(255), nullable=False, index=True)

    # Permissions
    can_read = Column(Boolean, default=True, nullable=False)
    can_write = Column(Boolean, default=False, nullable=False)  # Para CSV upload
    can_create = Column(Boolean, default=False, nullable=False)  # Para criar novos índices

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    created_by = relationship("User", foreign_keys=[created_by_id])

    def __repr__(self):
        return f"<UserIndexAccess user={self.user_id} server={self.es_server_id} index={self.index_name}>"

    def to_dict(self):
        """Convert to dictionary"""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "es_server_id": str(self.es_server_id),
            "index_name": self.index_name,
            "can_read": self.can_read,
            "can_write": self.can_write,
            "can_create": self.can_create,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_by_id": str(self.created_by_id) if self.created_by_id else None,
        }

    def matches_index(self, index_name: str) -> bool:
        """
        Verifica se este acesso match com um índice específico
        Suporta wildcards: gvuln* match gvuln_2024, gvuln-test, etc.

        Args:
            index_name: Nome do índice a verificar

        Returns:
            True se o acesso match com o índice
        """
        import fnmatch
        return fnmatch.fnmatch(index_name, self.index_name)
