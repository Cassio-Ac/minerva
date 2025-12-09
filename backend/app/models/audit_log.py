"""
Audit Log Model
Sistema de auditoria para eventos SSO e ações administrativas
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, JSON, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.database import Base


class AuditLog(Base):
    """
    Modelo de log de auditoria para eventos do sistema

    Registra eventos importantes como:
    - Logins SSO (sucesso e falhas)
    - Mudanças de configuração SSO
    - Criação/edição/exclusão de usuários
    - Mudanças de permissões
    - Sincronizações com AD
    """
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Tipo de evento
    event_type = Column(
        String(50),
        nullable=False,
        comment="Tipo: sso_login, sso_login_failed, sso_provider_created, user_created, etc"
    )

    # Categoria do evento (para filtros)
    category = Column(
        String(20),
        nullable=False,
        comment="Categoria: authentication, configuration, user_management, sync"
    )

    # Severidade
    severity = Column(
        String(20),
        nullable=False,
        default="info",
        comment="Severidade: info, warning, error, critical"
    )

    # Usuário que realizou a ação (pode ser NULL para eventos automáticos)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="Usuário que realizou a ação (NULL para eventos automáticos)"
    )

    # Usuário afetado pela ação (para eventos de gerenciamento de usuários)
    target_user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="Usuário afetado pela ação"
    )

    # Provider SSO relacionado (para eventos SSO)
    sso_provider_id = Column(
        UUID(as_uuid=True),
        ForeignKey("sso_providers.id", ondelete="SET NULL"),
        nullable=True,
        comment="Provider SSO relacionado ao evento"
    )

    # Descrição do evento
    description = Column(
        Text,
        nullable=False,
        comment="Descrição legível do evento"
    )

    # Dados adicionais do evento (JSON)
    event_metadata = Column(
        JSON,
        nullable=True,
        comment="Dados adicionais: IP, user agent, detalhes do erro, etc"
    )

    # IP do cliente
    ip_address = Column(
        String(45),
        nullable=True,
        comment="IP do cliente (IPv4 ou IPv6)"
    )

    # User Agent
    user_agent = Column(
        String(500),
        nullable=True,
        comment="User Agent do browser"
    )

    # Timestamp
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        comment="Timestamp do evento"
    )

    # Relationships
    user = relationship("User", foreign_keys=[user_id], backref="audit_logs_created")
    target_user = relationship("User", foreign_keys=[target_user_id], backref="audit_logs_targeted")
    sso_provider = relationship("SSOProvider", backref="audit_logs")

    # Índices para performance
    __table_args__ = (
        Index("idx_audit_event_type", "event_type"),
        Index("idx_audit_category", "category"),
        Index("idx_audit_user_id", "user_id"),
        Index("idx_audit_target_user_id", "target_user_id"),
        Index("idx_audit_sso_provider_id", "sso_provider_id"),
        Index("idx_audit_created_at", "created_at"),
        Index("idx_audit_severity", "severity"),
    )

    def __repr__(self):
        return (
            f"<AuditLog(id={self.id}, event_type='{self.event_type}', "
            f"category='{self.category}', created_at={self.created_at})>"
        )

    def to_dict(self):
        """Converte o objeto para dicionário"""
        return {
            "id": str(self.id),
            "event_type": self.event_type,
            "category": self.category,
            "severity": self.severity,
            "user_id": str(self.user_id) if self.user_id else None,
            "target_user_id": str(self.target_user_id) if self.target_user_id else None,
            "sso_provider_id": str(self.sso_provider_id) if self.sso_provider_id else None,
            "description": self.description,
            "metadata": self.event_metadata,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# Constantes de tipos de eventos
class AuditEventType:
    """Tipos de eventos de auditoria"""

    # Authentication events
    SSO_LOGIN_SUCCESS = "sso_login_success"
    SSO_LOGIN_FAILED = "sso_login_failed"
    SSO_LOGOUT = "sso_logout"
    LOCAL_LOGIN_SUCCESS = "local_login_success"
    LOCAL_LOGIN_FAILED = "local_login_failed"

    # SSO Provider events
    SSO_PROVIDER_CREATED = "sso_provider_created"
    SSO_PROVIDER_UPDATED = "sso_provider_updated"
    SSO_PROVIDER_DELETED = "sso_provider_deleted"
    SSO_PROVIDER_ACTIVATED = "sso_provider_activated"
    SSO_PROVIDER_DEACTIVATED = "sso_provider_deactivated"

    # User management events
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_ROLE_CHANGED = "user_role_changed"
    USER_ACTIVATED = "user_activated"
    USER_DEACTIVATED = "user_deactivated"

    # AD Sync events
    AD_SYNC_STARTED = "ad_sync_started"
    AD_SYNC_COMPLETED = "ad_sync_completed"
    AD_SYNC_FAILED = "ad_sync_failed"
    AD_USER_DEACTIVATED = "ad_user_deactivated"
    AD_USER_ACTIVATED = "ad_user_activated"


class AuditCategory:
    """Categorias de eventos"""
    AUTHENTICATION = "authentication"
    CONFIGURATION = "configuration"
    USER_MANAGEMENT = "user_management"
    SYNC = "sync"


class AuditSeverity:
    """Níveis de severidade"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
