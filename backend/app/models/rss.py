"""
RSS Feed Models
Database models for RSS feed management and collection tracking
"""

from sqlalchemy import Column, String, Text, DateTime, Boolean, Integer, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
import uuid

from app.db.database import Base


class RSSCategory(Base):
    """
    RSS Feed Categories
    Organizes feeds into logical groups (AI, Cybersecurity, Threat Intel, etc)
    """
    __tablename__ = "rss_categories"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    color = Column(String(7), nullable=True)  # Hex color for UI (#FF5733)
    icon = Column(String(50), nullable=True)  # Icon name for UI
    sort_order = Column(Integer, default=0)  # Display order
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    sources = relationship("RSSSource", back_populates="category", cascade="all, delete-orphan")

    __table_args__ = (
        Index('idx_rss_categories_active', 'is_active', 'sort_order'),
    )

    def __repr__(self):
        return f"<RSSCategory(id={self.id}, name={self.name})>"


class RSSSource(Base):
    """
    RSS Feed Sources
    Individual RSS feeds configured by administrators
    """
    __tablename__ = "rss_sources"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(200), nullable=False, index=True)
    url = Column(String(1000), nullable=False)
    category_id = Column(UUID(as_uuid=True), ForeignKey("rss_categories.id", ondelete="CASCADE"), nullable=False)

    # Configuration
    refresh_interval_hours = Column(Integer, default=6, nullable=False)  # How often to collect
    is_active = Column(Boolean, default=True, nullable=False)

    # Metadata
    description = Column(Text, nullable=True)
    feed_title = Column(String(500), nullable=True)  # Title from RSS feed itself
    feed_link = Column(String(1000), nullable=True)  # Homepage link from feed

    # Collection stats
    last_collected_at = Column(DateTime(timezone=True), nullable=True)
    last_collection_status = Column(String(50), nullable=True)  # 'success', 'error', 'partial'
    last_error_message = Column(Text, nullable=True)
    total_articles_collected = Column(Integer, default=0, nullable=False)

    # Extra config (JSON)
    extra_config = Column(JSONB, nullable=True)  # Custom headers, auth, etc

    # Audit
    created_by = Column(String(100), nullable=True)  # User ID who created
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    category = relationship("RSSCategory", back_populates="sources")
    collection_runs = relationship("RSSCollectionRun", back_populates="source", cascade="all, delete-orphan")

    __table_args__ = (
        Index('idx_rss_sources_active_category', 'is_active', 'category_id'),
        Index('idx_rss_sources_last_collected', 'last_collected_at'),
    )

    def __repr__(self):
        return f"<RSSSource(id={self.id}, name={self.name}, url={self.url})>"


class RSSCollectionRun(Base):
    """
    RSS Collection Runs
    Audit trail of feed collection executions
    """
    __tablename__ = "rss_collection_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id = Column(UUID(as_uuid=True), ForeignKey("rss_sources.id", ondelete="CASCADE"), nullable=False)

    # Execution info
    started_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    finished_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, nullable=True)

    # Results
    status = Column(String(50), nullable=False)  # 'running', 'success', 'error', 'partial'
    articles_found = Column(Integer, default=0)
    articles_new = Column(Integer, default=0)  # New articles added to ES
    articles_duplicate = Column(Integer, default=0)  # Skipped (already exist)
    error_message = Column(Text, nullable=True)

    # Metadata
    triggered_by = Column(String(50), nullable=True)  # 'scheduler', 'manual', 'api'
    executed_by = Column(String(100), nullable=True)  # User ID if manual

    # Stats from feed
    feed_metadata = Column(JSONB, nullable=True)  # Feed title, description, etc

    # Relationships
    source = relationship("RSSSource", back_populates="collection_runs")

    __table_args__ = (
        Index('idx_rss_runs_source_started', 'source_id', 'started_at'),
        Index('idx_rss_runs_status', 'status'),
    )

    def __repr__(self):
        return f"<RSSCollectionRun(id={self.id}, source_id={self.source_id}, status={self.status})>"


class RSSSettings(Base):
    """
    Global RSS Settings
    System-wide configuration for RSS module
    """
    __tablename__ = "rss_settings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Scheduling
    scheduler_enabled = Column(Boolean, default=True, nullable=False)
    default_refresh_interval_hours = Column(Integer, default=6, nullable=False)
    scheduler_cron = Column(String(100), nullable=True)  # Custom cron expression

    # Collection
    max_articles_per_feed = Column(Integer, default=100, nullable=False)  # Limit per collection
    days_to_keep_articles = Column(Integer, default=180, nullable=False)  # ES retention

    # Processing
    enable_deduplication = Column(Boolean, default=True, nullable=False)
    enable_nlp_enrichment = Column(Boolean, default=False, nullable=False)  # Sentiment, entities

    # Elasticsearch
    es_index_alias = Column(String(100), default="rss-articles", nullable=False)
    es_shards = Column(Integer, default=1, nullable=False)
    es_replicas = Column(Integer, default=1, nullable=False)

    # Notifications
    notify_on_errors = Column(Boolean, default=True, nullable=False)
    notification_webhook = Column(String(1000), nullable=True)

    # Extra
    extra_config = Column(JSONB, nullable=True)

    # Audit
    updated_by = Column(String(100), nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    def __repr__(self):
        return f"<RSSSettings(scheduler_enabled={self.scheduler_enabled})>"
