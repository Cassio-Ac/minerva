"""
SQL Database Models
Modelos SQLAlchemy para metadados do sistema
"""

from sqlalchemy import Column, String, Text, DateTime, Boolean, JSON, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.db.database import Base
from app.core.security import encrypt_password, decrypt_password


def generate_uuid():
    """Gera UUID para primary keys"""
    return str(uuid.uuid4())


class ESServer(Base):
    """
    Servidores Elasticsearch configurados
    Senhas criptografadas com Fernet
    """
    __tablename__ = "es_servers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False, unique=True, index=True)
    url = Column(String(500), nullable=False)
    username = Column(String(100), nullable=True)
    password_encrypted = Column(Text, nullable=True)  # Senha criptografada!
    description = Column(Text, nullable=True)
    use_ssl = Column(Boolean, default=False)
    verify_certs = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False, index=True)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    dashboards = relationship("Dashboard", back_populates="server", cascade="all, delete-orphan")
    conversations = relationship("Conversation", back_populates="server", cascade="all, delete-orphan")
    index_mcp_configs = relationship("IndexMCPConfig", back_populates="es_server", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index('idx_es_servers_active_name', 'is_active', 'name'),
    )

    @property
    def password(self):
        """Retorna senha descriptografada"""
        if self.password_encrypted:
            return decrypt_password(self.password_encrypted)
        return None

    @password.setter
    def password(self, plain_password: str):
        """Salva senha criptografada"""
        if plain_password:
            self.password_encrypted = encrypt_password(plain_password)
        else:
            self.password_encrypted = None


class Dashboard(Base):
    """
    Dashboards criados pelos usuários
    """
    __tablename__ = "dashboards"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    title = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    index = Column(String(255), nullable=False, index=True)  # Índice ES associado
    server_id = Column(UUID(as_uuid=False), ForeignKey("es_servers.id", ondelete="SET NULL"), nullable=True)

    # Layout e widgets em JSON
    layout = Column(JSON, nullable=False, default=dict)
    widgets = Column(JSON, nullable=False, default=list)

    # Metadata
    is_public = Column(Boolean, default=False, index=True)
    tags = Column(JSON, nullable=False, default=list)  # Array de strings
    version = Column(String(20), default="1.0.0")
    created_by = Column(String(100), nullable=True, index=True)  # User ID (futuro)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    server = relationship("ESServer", back_populates="dashboards")

    # Indexes
    __table_args__ = (
        Index('idx_dashboards_index_active', 'index', 'is_public'),
        Index('idx_dashboards_created_by', 'created_by'),
        Index('idx_dashboards_updated_at', 'updated_at'),
    )


class Conversation(Base):
    """
    Conversas com IA
    Mensagens com widgets completos (query + dados)
    """
    __tablename__ = "conversations"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    title = Column(String(200), nullable=False, index=True)
    index = Column(String(255), nullable=True, index=True)  # Primary índice ES (opcional)
    server_id = Column(UUID(as_uuid=False), ForeignKey("es_servers.id", ondelete="SET NULL"), nullable=True)

    # Mensagens em JSON (array de objetos)
    # Cada mensagem: {id, role, content, timestamp, widget: {title, type, query, data, config}}
    messages = Column(JSON, nullable=False, default=list)

    # Metadata
    created_by = Column(String(100), nullable=False, index=True)  # User ID (obrigatório)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    server = relationship("ESServer", back_populates="conversations")

    # Indexes
    __table_args__ = (
        Index('idx_conversations_index', 'index'),
        Index('idx_conversations_created_by', 'created_by'),
        Index('idx_conversations_updated_at', 'updated_at'),
    )


# TODO: User model removido - agora está em app/models/user.py
# User model foi movido para app/models/user.py com suporte completo a roles, grupos e permissões
# class User(Base):
#     """
#     Usuários do sistema (futuro)
#     """
#     __tablename__ = "users"
#
#     id = Column(String(36), primary_key=True, default=generate_uuid)
#     email = Column(String(255), nullable=False, unique=True, index=True)
#     username = Column(String(100), nullable=False, unique=True, index=True)
#     password_hash = Column(String(255), nullable=False)  # Bcrypt hash
#     full_name = Column(String(200), nullable=True)
#     is_active = Column(Boolean, default=True, index=True)
#     is_superuser = Column(Boolean, default=False)
#     created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
#     updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
#
#     __table_args__ = (
#         Index('idx_users_email_active', 'email', 'is_active'),
#     )
