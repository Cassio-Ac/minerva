"""
Dashboard Permission Model
SQLAlchemy model for dashboard ownership and sharing
"""
from datetime import datetime
from enum import Enum
from sqlalchemy import Column, String, Boolean, DateTime, Enum as SQLEnum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from app.db.database import Base


class DashboardVisibility(str, Enum):
    """Dashboard visibility levels"""
    PRIVATE = "private"    # Only owner can see
    PUBLIC = "public"      # All authenticated users can see
    SHARED = "shared"      # Only specific users can see (via dashboard_shares table)


class DashboardPermission(Base):
    """
    Dashboard Permission Model
    Tracks ownership and visibility of dashboards
    """
    __tablename__ = "dashboard_permissions"
    __table_args__ = {'extend_existing': True}

    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Dashboard reference (from PostgreSQL dashboards table)
    dashboard_id = Column(String(255), unique=True, nullable=False, index=True)

    # Owner
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    # Visibility
    visibility = Column(SQLEnum(DashboardVisibility), nullable=False, default=DashboardVisibility.PRIVATE)

    # Permissions
    allow_edit_by_others = Column(Boolean, default=False, nullable=False)  # Se outros podem editar
    allow_copy = Column(Boolean, default=True, nullable=False)            # Se outros podem copiar

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<DashboardPermission dashboard={self.dashboard_id} owner={self.owner_id} visibility={self.visibility}>"

    def to_dict(self):
        """Convert to dictionary"""
        return {
            "id": str(self.id),
            "dashboard_id": self.dashboard_id,
            "owner_id": str(self.owner_id),
            "visibility": self.visibility.value if isinstance(self.visibility, DashboardVisibility) else self.visibility,
            "allow_edit_by_others": self.allow_edit_by_others,
            "allow_copy": self.allow_copy,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class DashboardShare(Base):
    """
    Dashboard Share Model
    Specific user shares (for SHARED visibility)
    """
    __tablename__ = "dashboard_shares"
    __table_args__ = {'extend_existing': True}

    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Dashboard permission reference
    permission_id = Column(UUID(as_uuid=True), ForeignKey("dashboard_permissions.id", ondelete="CASCADE"), nullable=False, index=True)

    # Shared with user
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    # Access level
    can_edit = Column(Boolean, default=False, nullable=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<DashboardShare permission={self.permission_id} user={self.user_id} can_edit={self.can_edit}>"

    def to_dict(self):
        """Convert to dictionary"""
        return {
            "id": str(self.id),
            "permission_id": str(self.permission_id),
            "user_id": str(self.user_id),
            "can_edit": self.can_edit,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
