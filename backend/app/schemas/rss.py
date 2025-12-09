"""
RSS Pydantic Schemas
Request/Response models for RSS API
"""

from pydantic import BaseModel, Field, HttpUrl, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# ==================== Enums ====================

class CollectionStatus(str, Enum):
    RUNNING = "running"
    SUCCESS = "success"
    ERROR = "error"
    PARTIAL = "partial"


class CollectionTrigger(str, Enum):
    SCHEDULER = "scheduler"
    MANUAL = "manual"
    API = "api"


# ==================== RSS Category ====================

class RSSCategoryBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    color: Optional[str] = Field(None, pattern=r'^#[0-9A-Fa-f]{6}$')  # Hex color
    icon: Optional[str] = Field(None, max_length=50)
    sort_order: int = 0
    is_active: bool = True


class RSSCategoryCreate(RSSCategoryBase):
    pass


class RSSCategoryUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    color: Optional[str] = Field(None, pattern=r'^#[0-9A-Fa-f]{6}$')
    icon: Optional[str] = None
    sort_order: Optional[int] = None
    is_active: Optional[bool] = None


class RSSCategoryResponse(RSSCategoryBase):
    id: str
    created_at: datetime
    updated_at: datetime
    sources_count: Optional[int] = 0  # Number of sources in this category

    class Config:
        from_attributes = True


# ==================== RSS Source ====================

class RSSSourceBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    url: str = Field(..., min_length=1, max_length=1000)
    category_id: str
    refresh_interval_hours: int = Field(6, ge=1, le=168)  # 1 hour to 1 week
    is_active: bool = True
    description: Optional[str] = None
    extra_config: Optional[Dict[str, Any]] = None

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError('URL must start with http:// or https://')
        return v


class RSSSourceCreate(RSSSourceBase):
    created_by: Optional[str] = None


class RSSSourceUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    url: Optional[str] = Field(None, min_length=1, max_length=1000)
    category_id: Optional[str] = None
    refresh_interval_hours: Optional[int] = Field(None, ge=1, le=168)
    is_active: Optional[bool] = None
    description: Optional[str] = None
    extra_config: Optional[Dict[str, Any]] = None


class RSSSourceResponse(RSSSourceBase):
    id: str
    feed_title: Optional[str] = None
    feed_link: Optional[str] = None
    last_collected_at: Optional[datetime] = None
    last_collection_status: Optional[str] = None
    last_error_message: Optional[str] = None
    total_articles_collected: int = 0
    created_at: datetime
    updated_at: datetime
    category_name: Optional[str] = None  # Joined from category

    class Config:
        from_attributes = True


class RSSSourceStats(BaseModel):
    """Statistics for RSS source"""
    id: str
    name: str
    total_articles: int
    articles_today: int
    articles_this_week: int
    last_article_date: Optional[datetime] = None
    avg_articles_per_day: float


# ==================== RSS Collection Run ====================

class RSSCollectionRunResponse(BaseModel):
    id: str
    source_id: str
    source_name: Optional[str] = None
    started_at: datetime
    finished_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    status: CollectionStatus
    articles_found: int = 0
    articles_new: int = 0
    articles_duplicate: int = 0
    error_message: Optional[str] = None
    triggered_by: Optional[CollectionTrigger] = None
    feed_metadata: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


# ==================== RSS Article (Elasticsearch) ====================

class RSSArticle(BaseModel):
    """RSS Article stored in Elasticsearch"""
    content_hash: str  # Changed from article_id to match ES
    title: str
    link: str
    published: datetime
    summary: Optional[str] = None  # Optional for BibTeX entries
    author: Optional[str] = None
    tags: List[str] = []

    # Feed info
    feed_name: str
    category: str
    feed_title: Optional[str] = None
    feed_description: Optional[str] = None
    feed_link: Optional[str] = None
    feed_updated: Optional[str] = None

    # Metadata
    collected_at: datetime  # Changed from created_at to match ES
    source_type: str = "rss_feed"

    # Optional timestamp field
    timestamp: Optional[datetime] = Field(None, alias="@timestamp")

    # Optional NLP enrichment
    sentiment: Optional[str] = None  # positive, negative, neutral
    entities: Optional[List[str]] = None  # Extracted entities
    keywords: Optional[List[str]] = None

    # Malpedia enrichment (LLM-generated)
    enriched_summary: Optional[str] = None
    actors_mentioned: Optional[List[str]] = None
    families_mentioned: Optional[List[str]] = None
    enriched_at: Optional[str] = None
    enrichment_version: Optional[str] = None

    class Config:
        populate_by_name = True


class RSSArticleSearchRequest(BaseModel):
    """Search/filter request for RSS articles"""
    query: Optional[str] = None  # Full-text search
    categories: Optional[List[str]] = None
    feed_names: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    sentiment: Optional[str] = None
    limit: int = Field(50, ge=1, le=10000)
    offset: int = Field(0, ge=0)
    sort_by: str = Field("published", pattern=r'^(published|collected_at|title)$')
    sort_order: str = Field("desc", pattern=r'^(asc|desc)$')


class RSSArticleSearchResponse(BaseModel):
    """Search response with articles and metadata"""
    total: int
    articles: List[RSSArticle]
    facets: Optional[Dict[str, Any]] = None  # Aggregations
    took_ms: int  # Query time


# ==================== RSS Chat ====================

class ChatMessage(BaseModel):
    """Single message in conversation history"""
    role: str  # "user" | "assistant"
    content: str


class RSSChatRequest(BaseModel):
    """Chat request with context filters and conversation history"""
    query: str = Field(..., min_length=1, max_length=2000)
    categories: Optional[List[str]] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    max_context_articles: int = Field(10, ge=1, le=50)
    context: Optional[List[ChatMessage]] = None  # Conversation history


class RSSChatResponse(BaseModel):
    """Chat response with LLM answer and sources"""
    answer: str
    sources: List[RSSArticle]
    query: str
    context_used: int  # Number of articles used in context
    model_used: str


# ==================== RSS Settings ====================

class RSSSettingsUpdate(BaseModel):
    scheduler_enabled: Optional[bool] = None
    default_refresh_interval_hours: Optional[int] = Field(None, ge=1, le=168)
    scheduler_cron: Optional[str] = None
    max_articles_per_feed: Optional[int] = Field(None, ge=10, le=1000)
    days_to_keep_articles: Optional[int] = Field(None, ge=7, le=3650)
    enable_deduplication: Optional[bool] = None
    enable_nlp_enrichment: Optional[bool] = None
    notify_on_errors: Optional[bool] = None
    notification_webhook: Optional[str] = None


class RSSSettingsResponse(BaseModel):
    id: str
    scheduler_enabled: bool
    default_refresh_interval_hours: int
    scheduler_cron: Optional[str] = None
    max_articles_per_feed: int
    days_to_keep_articles: int
    enable_deduplication: bool
    enable_nlp_enrichment: bool
    es_index_alias: str
    notify_on_errors: bool
    notification_webhook: Optional[str] = None
    updated_at: datetime

    class Config:
        from_attributes = True


# ==================== Bulk Import/Export ====================

class RSSFeedImport(BaseModel):
    """Single feed for bulk import"""
    name: str
    url: str
    category: str


class RSSBulkImportRequest(BaseModel):
    """Bulk import request (YAML/JSON format)"""
    feeds: Dict[str, Dict[str, str]]  # {category: {name: url}}
    overwrite_existing: bool = False


class RSSBulkImportResponse(BaseModel):
    """Bulk import result"""
    categories_created: int
    sources_created: int
    sources_updated: int
    sources_skipped: int
    errors: List[str] = []


# ==================== Dashboard Stats ====================

class RSSStatsResponse(BaseModel):
    """Global RSS statistics for dashboard"""
    total_sources: int
    active_sources: int
    total_categories: int
    total_articles: int
    articles_today: int
    articles_this_week: int
    articles_this_month: int
    last_collection_at: Optional[datetime] = None

    # Top sources
    top_sources: List[Dict[str, Any]]  # name, count

    # All sources (for filters)
    all_sources: List[Dict[str, Any]] = []  # name, count

    # Articles by category
    articles_by_category: Dict[str, int]

    # Timeline (articles per day, last 30 days)
    timeline: List[Dict[str, Any]]  # date, count

    # Collection health
    failed_collections_today: int
    avg_collection_duration_seconds: Optional[float] = None


# ==================== Manual Collection ====================

class RSSCollectRequest(BaseModel):
    """Trigger manual collection"""
    source_ids: Optional[List[str]] = None  # If None, collect all active
    category_ids: Optional[List[str]] = None  # If specified, collect all in these categories


class RSSCollectResponse(BaseModel):
    """Manual collection result"""
    task_id: str  # Celery task ID
    sources_queued: int
    message: str
