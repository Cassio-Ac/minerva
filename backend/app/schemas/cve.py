"""
CVE (Common Vulnerabilities and Exposures) Schemas
"""
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel


class CVEEntry(BaseModel):
    """Single CVE entry from Elasticsearch"""
    id: int
    date: datetime
    cve_id: str
    cve_title: str
    cve_content: str
    cve_source: str
    cve_type: str
    cve_severity_level: str
    cve_severity_score: str


class CVESearchRequest(BaseModel):
    """Request model for CVE search"""
    query: Optional[str] = None
    sources: Optional[List[str]] = None
    types: Optional[List[str]] = None
    severity_levels: Optional[List[str]] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    limit: int = 50
    offset: int = 0
    sort_by: str = "date"
    sort_order: str = "desc"


class CVESearchResponse(BaseModel):
    """Response model for CVE search"""
    total: int
    cves: List[CVEEntry]
    facets: Optional[dict] = None
    took_ms: int


class CVEStats(BaseModel):
    """CVE statistics"""
    total_cves: int
    cves_today: int
    cves_this_week: int
    cves_this_month: int
    cves_by_severity: dict
    cves_by_source: dict
    top_sources: List[dict]
    timeline: List[dict]


class CVEChatRequest(BaseModel):
    """Request model for CVE chat"""
    query: str
    severity_level: Optional[str] = None
    source: Optional[str] = None
    days: int = 30
    max_context: int = 10


class CVEChatResponse(BaseModel):
    """Response model for CVE chat"""
    answer: str
    context_used: int
