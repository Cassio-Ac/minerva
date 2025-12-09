"""
Breach (Data Leak) Schemas
Pydantic models for breach detection and data leak monitoring
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


# ==================== Breach Entry ====================

class BreachEntry(BaseModel):
    """Single breach/leak entry from Elasticsearch"""
    id: int
    date: datetime
    breach_source: str
    breach_content: str
    breach_author: str
    breach_type: str

    class Config:
        from_attributes = True


# ==================== Search ====================

class BreachSearchRequest(BaseModel):
    """Request for searching breaches with filters"""
    query: Optional[str] = Field(None, description="Full-text search query")
    sources: Optional[List[str]] = Field(None, description="Filter by breach sources")
    types: Optional[List[str]] = Field(None, description="Filter by breach types (Data leak, ransomware, etc)")
    authors: Optional[List[str]] = Field(None, description="Filter by authors/groups")
    date_from: Optional[datetime] = Field(None, description="Start date filter")
    date_to: Optional[datetime] = Field(None, description="End date filter")
    limit: int = Field(50, ge=1, le=200, description="Maximum results to return")
    offset: int = Field(0, ge=0, description="Pagination offset")
    sort_by: str = Field("date", description="Field to sort by")
    sort_order: str = Field("desc", description="Sort order (asc/desc)")


class BreachFacets(BaseModel):
    """Faceted search results for breach filters"""
    sources: List[dict] = Field(default_factory=list, description="Top breach sources")
    types: List[dict] = Field(default_factory=list, description="Breach types distribution")
    authors: List[dict] = Field(default_factory=list, description="Top authors/groups")
    timeline: List[dict] = Field(default_factory=list, description="Daily timeline")


class BreachSearchResponse(BaseModel):
    """Response from breach search with facets"""
    total: int = Field(..., description="Total breaches matching criteria")
    breaches: List[BreachEntry] = Field(default_factory=list)
    facets: Optional[BreachFacets] = None
    took_ms: int = Field(0, description="Search time in milliseconds")


# ==================== Stats ====================

class BreachStats(BaseModel):
    """Global breach statistics"""
    total_breaches: int = 0
    breaches_today: int = 0
    breaches_this_week: int = 0
    breaches_this_month: int = 0
    breaches_by_type: dict = Field(default_factory=dict)
    top_sources: List[dict] = Field(default_factory=list)
    top_authors: List[dict] = Field(default_factory=list)
    timeline: List[dict] = Field(default_factory=list)


# ==================== Chat ====================

class BreachChatRequest(BaseModel):
    """Request for chatting about breaches using RAG"""
    query: str = Field(..., min_length=1, max_length=1000, description="User question about breaches")
    breach_type: Optional[str] = Field(None, description="Filter by breach type")
    source: Optional[str] = Field(None, description="Filter by source")
    days: int = Field(30, ge=1, le=365, description="Number of days to search")
    max_context: int = Field(10, ge=1, le=50, description="Maximum breaches to include in context")


class BreachChatResponse(BaseModel):
    """Response from breach chat with RAG"""
    answer: str = Field(..., description="LLM-generated answer")
    context_used: int = Field(..., description="Number of breaches used in context")
    sources: List[BreachEntry] = Field(default_factory=list, description="Breach entries used for context")
    query: str = Field(..., description="Original user query")
