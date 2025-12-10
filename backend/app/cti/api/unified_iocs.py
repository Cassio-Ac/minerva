"""
Unified IOC API Endpoints

RESTful API for unified IOC correlation system.
Prefix: /api/v1/cti/iocs
"""

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

from app.db.database import get_db
from app.models.user import User
from app.core.dependencies import get_current_user, require_role
from app.cti.services.unified_ioc_service import UnifiedIOCService, UnifiedIOCMigration
from app.cti.services.unified_ioc_adapters import list_adapters

router = APIRouter(prefix="/iocs", tags=["CTI - Unified IOCs"])


# ============ SCHEMAS ============

class IOCSourceResponse(BaseModel):
    source_name: str
    source_confidence: Optional[float] = None
    source_reputation: Optional[float] = None
    first_seen_by_source: Optional[str] = None
    last_seen_by_source: Optional[str] = None
    context: Optional[str] = None


class ConfidenceBreakdownResponse(BaseModel):
    base_score: float
    multi_source_boost: float
    reputation_boost: float
    time_decay: float
    final_score: float


class UnifiedIOCResponse(BaseModel):
    id: str
    ioc_value: str
    ioc_type: str
    ioc_subtype: Optional[str] = None
    source_count: int
    source_names: List[str]
    confidence_score: float
    confidence_level: str
    malware_family: Optional[str] = None
    threat_actor: Optional[str] = None
    threat_type: Optional[str] = None
    tags: List[str] = []
    mitre_attack: List[str] = []
    tlp: str = "white"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    is_active: bool = True

    class Config:
        from_attributes = True


class UnifiedIOCDetailResponse(UnifiedIOCResponse):
    sources: List[IOCSourceResponse] = []
    confidence_breakdown: Optional[ConfidenceBreakdownResponse] = None
    targeted_countries: List[str] = []
    targeted_industries: List[str] = []
    references: List[str] = []
    campaigns: List[str] = []
    enrichment: Optional[Dict[str, Any]] = None
    geo: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None
    last_updated: Optional[str] = None


class IOCListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    iocs: List[UnifiedIOCResponse]


class IOCLookupResponse(BaseModel):
    found: bool
    ioc: Optional[UnifiedIOCDetailResponse] = None


class IOCStatsResponse(BaseModel):
    total_iocs: int
    active_iocs: int
    by_type: Dict[str, int]
    by_source: Dict[str, int]
    by_confidence_level: Dict[str, int]
    by_malware_family: Dict[str, int]
    by_threat_actor: Dict[str, int]
    by_tlp: Dict[str, int]
    avg_confidence: float
    avg_sources_per_ioc: float
    multi_source_iocs: int
    high_confidence_iocs: int
    critical_iocs: int
    recent_24h: int
    recent_7d: int


class IOCIngestRequest(BaseModel):
    iocs: List[Dict[str, Any]] = Field(..., description="List of IOCs to ingest")
    source_name: str = Field(..., description="Source name (misp, otx, etc.)")


class IOCIngestResponse(BaseModel):
    created: int
    updated: int
    errors: int
    total: int


class MigrationResponse(BaseModel):
    started_at: str
    completed_at: Optional[str] = None
    misp: Dict[str, Any]
    otx: Dict[str, Any]
    final_stats: Optional[Dict[str, Any]] = None


class SourceAdapterResponse(BaseModel):
    name: str
    source_name: str
    reputation: float


# ============ ENDPOINTS ============

@router.get("", response_model=IOCListResponse)
async def search_iocs(
    q: Optional[str] = Query(None, description="Full-text search query"),
    ioc_type: Optional[str] = Query(None, description="Filter by type (ip, domain, url, hash, email)"),
    source: Optional[str] = Query(None, description="Filter by source name"),
    min_confidence: Optional[float] = Query(None, ge=0, le=100, description="Minimum confidence score"),
    confidence_level: Optional[str] = Query(None, description="Filter by level (critical, high, medium, low)"),
    malware_family: Optional[str] = Query(None, description="Filter by malware family"),
    threat_actor: Optional[str] = Query(None, description="Filter by threat actor"),
    tags: Optional[str] = Query(None, description="Filter by tags (comma-separated)"),
    mitre: Optional[str] = Query(None, description="Filter by MITRE ATT&CK IDs (comma-separated)"),
    min_sources: Optional[int] = Query(None, ge=1, description="Minimum number of sources"),
    tlp: Optional[str] = Query(None, description="Filter by TLP level"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    sort_by: str = Query("confidence_score", description="Sort field"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    current_user: User = Depends(get_current_user)
):
    """
    Search unified IOCs with advanced filtering.

    Results are sorted by confidence score by default.
    Supports full-text search across IOC value, malware family, threat actor, and tags.
    """
    service = UnifiedIOCService()

    try:
        tags_list = [t.strip() for t in tags.split(",")] if tags else None
        mitre_list = [t.strip() for t in mitre.split(",")] if mitre else None

        result = await service.search_iocs(
            query=q,
            ioc_type=ioc_type,
            source_name=source,
            min_confidence=min_confidence,
            confidence_level=confidence_level,
            malware_family=malware_family,
            threat_actor=threat_actor,
            tags=tags_list,
            mitre_attack=mitre_list,
            min_source_count=min_sources,
            tlp=tlp,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order
        )

        return IOCListResponse(**result)
    finally:
        await service.close()


@router.get("/lookup", response_model=IOCLookupResponse)
async def lookup_ioc(
    value: str = Query(..., description="IOC value to lookup"),
    current_user: User = Depends(get_current_user)
):
    """
    Quick lookup for a specific IOC value.

    Returns full details including all sources and correlation data.
    The value is normalized before lookup (e.g., defanged URLs are refanged).
    """
    service = UnifiedIOCService()

    try:
        ioc = await service.lookup_ioc(value)

        if ioc:
            return IOCLookupResponse(
                found=True,
                ioc=UnifiedIOCDetailResponse(**ioc)
            )

        return IOCLookupResponse(found=False, ioc=None)
    finally:
        await service.close()


@router.get("/stats", response_model=IOCStatsResponse)
async def get_ioc_stats(
    current_user: User = Depends(get_current_user)
):
    """
    Get comprehensive statistics about unified IOCs.

    Includes counts by type, source, confidence level, and more.
    """
    service = UnifiedIOCService()

    try:
        stats = await service.get_stats()
        return IOCStatsResponse(**stats)
    finally:
        await service.close()


@router.get("/high-confidence")
async def get_high_confidence_iocs(
    min_score: float = Query(70, ge=50, le=100, description="Minimum confidence score"),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user)
):
    """
    Get IOCs with high confidence scores.

    Useful for priority alerting and immediate action items.
    """
    service = UnifiedIOCService()

    try:
        result = await service.search_iocs(
            min_confidence=min_score,
            page_size=limit,
            sort_by="confidence_score",
            sort_order="desc"
        )

        return {
            "min_score": min_score,
            "count": len(result["iocs"]),
            "iocs": result["iocs"]
        }
    finally:
        await service.close()


@router.get("/multi-source")
async def get_multi_source_iocs(
    min_sources: int = Query(2, ge=2, description="Minimum number of sources"),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user)
):
    """
    Get IOCs that appear in multiple sources.

    These are high-value correlations that increase confidence.
    """
    service = UnifiedIOCService()

    try:
        result = await service.search_iocs(
            min_source_count=min_sources,
            page_size=limit,
            sort_by="source_count",
            sort_order="desc"
        )

        return {
            "min_sources": min_sources,
            "count": len(result["iocs"]),
            "iocs": result["iocs"]
        }
    finally:
        await service.close()


@router.get("/recent")
async def get_recent_iocs(
    hours: int = Query(24, ge=1, le=168, description="Look back hours (max 7 days)"),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user)
):
    """
    Get recently seen IOCs.

    Returns IOCs updated within the specified time window.
    """
    service = UnifiedIOCService()

    try:
        # Use ES range query via search
        es = await service._get_client()

        body = {
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"last_seen": {"gte": f"now-{hours}h"}}},
                        {"term": {"is_active": True}}
                    ]
                }
            },
            "size": limit,
            "sort": [{"last_seen": "desc"}]
        }

        result = await es.search(index="unified_iocs", body=body)
        hits = result.get("hits", {})

        return {
            "hours": hours,
            "count": hits.get("total", {}).get("value", 0),
            "iocs": [
                {**hit["_source"], "id": hit["_id"]}
                for hit in hits.get("hits", [])
            ]
        }
    finally:
        await service.close()


@router.get("/sources")
async def list_sources(
    current_user: User = Depends(get_current_user)
):
    """
    List all IOC sources with counts and reputation.
    """
    service = UnifiedIOCService()

    try:
        stats = await service.get_stats()
        adapters = {a["source_name"]: a["reputation"] for a in list_adapters()}

        sources = []
        for source_name, count in stats.get("by_source", {}).items():
            sources.append({
                "name": source_name,
                "ioc_count": count,
                "reputation": adapters.get(source_name, 0.5)
            })

        return {
            "total_sources": len(sources),
            "sources": sorted(sources, key=lambda x: x["ioc_count"], reverse=True)
        }
    finally:
        await service.close()


@router.get("/adapters", response_model=List[SourceAdapterResponse])
async def list_available_adapters(
    current_user: User = Depends(get_current_user)
):
    """
    List all available source adapters.

    Shows which sources can be integrated.
    """
    return [SourceAdapterResponse(**a) for a in list_adapters()]


@router.get("/{ioc_id}", response_model=UnifiedIOCDetailResponse)
async def get_ioc_by_id(
    ioc_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get detailed information about a specific IOC.

    Includes all sources, confidence breakdown, and enrichment data.
    """
    service = UnifiedIOCService()

    try:
        ioc = await service.get_by_id(ioc_id)

        if not ioc:
            raise HTTPException(status_code=404, detail="IOC not found")

        return UnifiedIOCDetailResponse(**ioc)
    finally:
        await service.close()


# ============ ADMIN ENDPOINTS ============

@router.post("/ingest", response_model=IOCIngestResponse)
async def ingest_iocs(
    request: IOCIngestRequest,
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    Bulk ingest IOCs from a source.

    IOCs are automatically normalized, deduplicated, and correlated.
    Requires admin or power role.
    """
    service = UnifiedIOCService()

    try:
        result = await service.ingest_batch(
            iocs=request.iocs,
            source_name=request.source_name
        )

        return IOCIngestResponse(**result)
    finally:
        await service.close()


@router.post("/migrate")
async def run_migration(
    background_tasks: BackgroundTasks,
    dry_run: bool = Query(False, description="Simulate migration without writing"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"]))
):
    """
    Migrate existing IOCs from PostgreSQL to unified Elasticsearch index.

    This migrates data from misp_iocs and otx_pulse_indicators tables.
    Run with dry_run=true first to see counts.

    **Warning:** This is a resource-intensive operation. Run during low-traffic periods.
    Requires admin role.
    """
    from sqlalchemy import select, func
    from app.cti.models.misp_ioc import MISPIoC
    from app.cti.models.otx_pulse import OTXPulseIndicator

    if dry_run:
        # Count only
        misp_count = await db.scalar(select(func.count(MISPIoC.id)))
        otx_count = await db.scalar(select(func.count(OTXPulseIndicator.id)))

        return {
            "dry_run": True,
            "misp_iocs_to_migrate": misp_count,
            "otx_indicators_to_migrate": otx_count,
            "estimated_total": misp_count + otx_count,
            "note": "Set dry_run=false to execute migration"
        }

    # Run migration in background
    async def run_migration_task():
        migration = UnifiedIOCMigration(db)
        result = await migration.run_full_migration()
        return result

    background_tasks.add_task(run_migration_task)

    return {
        "status": "started",
        "message": "Migration started in background. Check /stats for progress."
    }


@router.post("/index/create")
async def create_index(
    current_user: User = Depends(require_role(["admin"]))
):
    """
    Create the unified_iocs index if it doesn't exist.

    Requires admin role.
    """
    service = UnifiedIOCService()

    try:
        created = await service.ensure_index()

        if created:
            return {"status": "created", "index": "unified_iocs"}
        return {"status": "exists", "index": "unified_iocs"}
    finally:
        await service.close()


@router.get("/index/stats")
async def get_index_stats(
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    Get Elasticsearch index statistics.

    Requires admin or power role.
    """
    service = UnifiedIOCService()

    try:
        return await service.get_index_stats()
    finally:
        await service.close()


@router.delete("/index/delete")
async def delete_index(
    confirm: bool = Query(False, description="Confirm deletion"),
    current_user: User = Depends(require_role(["admin"]))
):
    """
    Delete the unified_iocs index.

    **WARNING:** This will delete ALL unified IOC data.
    Requires admin role and confirm=true.
    """
    if not confirm:
        raise HTTPException(
            status_code=400,
            detail="Set confirm=true to delete the index. This action cannot be undone."
        )

    service = UnifiedIOCService()

    try:
        deleted = await service.delete_index()

        if deleted:
            return {"status": "deleted", "index": "unified_iocs"}
        return {"status": "not_found", "index": "unified_iocs"}
    finally:
        await service.close()
