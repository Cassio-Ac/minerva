"""
Group Model
SQLAlchemy model for user groups and group-based permissions
"""
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Text, Table, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from app.db.database import Base


# Many-to-Many: Users <-> Groups
user_groups = Table(
    'user_groups',
    Base.metadata,
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    Column('group_id', UUID(as_uuid=True), ForeignKey('groups.id', ondelete='CASCADE'), primary_key=True),
    Column('created_at', DateTime, default=datetime.utcnow, nullable=False),
    extend_existing=True
)


# Many-to-Many: Groups <-> Dashboards (via permissions)
group_dashboard_permissions = Table(
    'group_dashboard_permissions',
    Base.metadata,
    Column('group_id', UUID(as_uuid=True), ForeignKey('groups.id', ondelete='CASCADE'), primary_key=True),
    Column('dashboard_id', String(255), primary_key=True),  # Dashboard ID from PostgreSQL
    Column('can_view', Boolean, default=True, nullable=False),
    Column('can_edit', Boolean, default=False, nullable=False),
    Column('can_delete', Boolean, default=False, nullable=False),
    Column('created_at', DateTime, default=datetime.utcnow, nullable=False),
    extend_existing=True
)


class Group(Base):
    """
    Group Model
    Groups for organizing users and managing permissions
    """
    __tablename__ = "groups"
    __table_args__ = {'extend_existing': True}

    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Group info
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)

    # System flags
    is_system = Column(Boolean, default=False, nullable=False)  # System groups can't be deleted
    is_active = Column(Boolean, default=True, nullable=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Creator
    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    def __repr__(self):
        return f"<Group {self.name}>"

    def to_dict(self):
        """Convert group to dictionary"""
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "is_system": self.is_system,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_by_id": str(self.created_by_id) if self.created_by_id else None,
        }
