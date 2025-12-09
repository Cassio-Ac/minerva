"""
User Model
SQLAlchemy model for user authentication and authorization
"""
from datetime import datetime
from enum import Enum
from sqlalchemy import Column, String, Boolean, DateTime, Enum as SQLEnum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from app.db.database import Base


class UserRole(str, Enum):
    """User roles with hierarchical permissions"""
    ADMIN = "admin"      # Can configure everything, manage users
    POWER = "power"      # Can use LLM, create dashboards, generate reports (no restrictions)
    OPERATOR = "operator"  # Can use LLM, dashboards, upload CSV (restricted to assigned indices)
    READER = "reader"    # Can only view dashboards shared with them


class User(Base):
    """User model with authentication and role-based permissions"""
    __tablename__ = "users"
    __table_args__ = {'extend_existing': True}

    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Authentication
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)

    # Profile
    full_name = Column(String(255))

    # Authorization
    role = Column(String(50), nullable=False, default="reader")
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    # Settings (JSON)
    preferences = Column(String, nullable=True)  # JSON string com preferências do usuário

    # Elasticsearch Server Assignment (for OPERATOR role)
    assigned_es_server_id = Column(UUID(as_uuid=True), nullable=True)  # NULL = no restriction (ADMIN/POWER)

    # SSO Fields
    sso_provider_id = Column(UUID(as_uuid=True), ForeignKey("sso_providers.id", ondelete="SET NULL"), nullable=True)
    external_id = Column(String(255), nullable=True)  # Object ID no provider externo (MS, Google, etc)
    sso_email = Column(String(255), nullable=True)  # Email retornado pelo SSO
    last_sso_login = Column(DateTime, nullable=True)  # Último login via SSO
    last_ad_sync = Column(DateTime, nullable=True)  # Última verificação no AD
    ad_account_enabled = Column(Boolean, nullable=True)  # Status da conta no AD (cache)
    sync_status = Column(String(50), nullable=True)  # 'synced', 'error', 'not_found'

    # Profile Photo
    profile_photo_url = Column(String(500), nullable=True)  # URL relativa: /static/profile-photos/{user_id}.jpg
    photo_source = Column(String(20), nullable=True, default='default')  # 'entra_id', 'upload', 'gravatar', 'default'
    photo_updated_at = Column(DateTime, nullable=True)  # Última atualização da foto

    # Relationships (declared but not used directly to avoid circular imports)
    # groups = relationship("Group", secondary="user_groups", back_populates="users")
    downloads = relationship("Download", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"

    def to_dict(self):
        """Convert user to dictionary (safe - without password)"""
        return {
            "id": str(self.id),
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "role": self.role.value if isinstance(self.role, UserRole) else self.role,
            "is_active": self.is_active,
            "is_superuser": self.is_superuser,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            # SSO fields
            "sso_provider_id": str(self.sso_provider_id) if self.sso_provider_id else None,
            "external_id": self.external_id,
            "sso_email": self.sso_email,
            "last_sso_login": self.last_sso_login.isoformat() if self.last_sso_login else None,
            "last_ad_sync": self.last_ad_sync.isoformat() if self.last_ad_sync else None,
            "ad_account_enabled": self.ad_account_enabled,
            "sync_status": self.sync_status,
            # Profile photo
            "profile_photo_url": self.profile_photo_url,
            "photo_source": self.photo_source,
            "photo_updated_at": self.photo_updated_at.isoformat() if self.photo_updated_at else None,
        }

    @property
    def can_manage_users(self) -> bool:
        """Check if user can manage other users"""
        return self.role == UserRole.ADMIN or self.is_superuser

    @property
    def can_use_llm(self) -> bool:
        """Check if user can use LLM features"""
        return self.role in [UserRole.ADMIN, UserRole.POWER, UserRole.OPERATOR]

    @property
    def can_create_dashboards(self) -> bool:
        """Check if user can create dashboards"""
        return self.role in [UserRole.ADMIN, UserRole.POWER, UserRole.OPERATOR]

    @property
    def can_upload_csv(self) -> bool:
        """Check if user can upload CSV files"""
        return self.role in [UserRole.ADMIN, UserRole.POWER, UserRole.OPERATOR]

    @property
    def has_index_restrictions(self) -> bool:
        """Check if user has index-level restrictions (OPERATOR role)"""
        return self.role == UserRole.OPERATOR

    @property
    def can_configure_system(self) -> bool:
        """Check if user can configure system settings"""
        return self.role == UserRole.ADMIN or self.is_superuser
