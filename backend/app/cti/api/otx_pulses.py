"""
OTX Pulses API Endpoints

API para gerenciar sincronização, export MISP e enriquecimento bulk
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
from app.db.database import get_db
from app.cti.services.otx_pulse_sync_service import OTXPulseSyncService
from app.cti.services.otx_misp_exporter import OTXMISPExporter
from app.cti.services.otx_bulk_enrichment_service import OTXBulkEnrichmentService
from app.cti.models.otx_pulse import OTXPulse, OTXPulseIndicator
from app.models.user import User
from app.core.dependencies import get_current_user, require_role
from pydantic import BaseModel
from typing import List, Optional
from uuid import UUID
from datetime import datetime

router = APIRouter()


# Schemas
class PulseSyncRequest(BaseModel):
    limit: int = 50


class PulseSearchRequest(BaseModel):
    query: str
    limit: int = 20


class ExportPulseRequest(BaseModel):
    pulse_id: UUID


class BulkEnrichmentRequest(BaseModel):
    limit: int = 100
    ioc_types: Optional[List[str]] = None
    priority_only: bool = True


# ====== PULSE LIST/BROWSE ENDPOINTS ======

class PulseResponse(BaseModel):
    id: str
    pulse_id: str
    name: str
    description: Optional[str]
    author_name: Optional[str]
    created: Optional[datetime]
    modified: Optional[datetime]
    tlp: Optional[str]
    adversary: Optional[str]
    targeted_countries: List[str]
    industries: List[str]
    tags: List[str]
    indicator_count: int
    attack_ids: List[str]
    malware_families: List[str]
    exported_to_misp: bool
    synced_at: datetime

    class Config:
        from_attributes = True


class PulsesListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    pulses: List[PulseResponse]


@router.get("/pulses", response_model=PulsesListResponse)
async def list_pulses(
    search: Optional[str] = Query(None, description="Search in name, description, adversary"),
    adversary: Optional[str] = Query(None, description="Filter by adversary/threat actor"),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List OTX pulses with filtering and pagination
    """
    query = select(OTXPulse).where(OTXPulse.is_active == True)
    count_query = select(func.count(OTXPulse.id)).where(OTXPulse.is_active == True)

    # Apply filters
    if search:
        search_filter = or_(
            OTXPulse.name.ilike(f"%{search}%"),
            OTXPulse.description.ilike(f"%{search}%"),
            OTXPulse.adversary.ilike(f"%{search}%")
        )
        query = query.where(search_filter)
        count_query = count_query.where(search_filter)

    if adversary:
        query = query.where(OTXPulse.adversary.ilike(f"%{adversary}%"))
        count_query = count_query.where(OTXPulse.adversary.ilike(f"%{adversary}%"))

    if tag:
        query = query.where(OTXPulse.tags.contains([tag]))
        count_query = count_query.where(OTXPulse.tags.contains([tag]))

    # Get total count
    total_result = await session.execute(count_query)
    total = total_result.scalar()

    # Apply pagination and ordering
    offset = (page - 1) * page_size
    query = query.order_by(OTXPulse.created.desc()).offset(offset).limit(page_size)

    result = await session.execute(query)
    pulses = result.scalars().all()

    return PulsesListResponse(
        total=total,
        page=page,
        page_size=page_size,
        pulses=[PulseResponse(
            id=str(p.id),
            pulse_id=p.pulse_id,
            name=p.name,
            description=p.description,
            author_name=p.author_name,
            created=p.created,
            modified=p.modified,
            tlp=p.tlp,
            adversary=p.adversary,
            targeted_countries=p.targeted_countries or [],
            industries=p.industries or [],
            tags=p.tags or [],
            indicator_count=p.indicator_count or 0,
            attack_ids=p.attack_ids or [],
            malware_families=p.malware_families or [],
            exported_to_misp=p.exported_to_misp,
            synced_at=p.synced_at
        ) for p in pulses]
    )


@router.get("/pulses/{pulse_id}/detail")
async def get_pulse_detail(
    pulse_id: str,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get detailed information about a specific pulse including indicators
    """
    # Get pulse
    result = await session.execute(
        select(OTXPulse).where(OTXPulse.id == pulse_id)
    )
    pulse = result.scalar_one_or_none()

    if not pulse:
        raise HTTPException(status_code=404, detail="Pulse not found")

    # Get indicators (limit to first 100)
    indicators_result = await session.execute(
        select(OTXPulseIndicator)
        .where(OTXPulseIndicator.pulse_id == pulse.id)
        .limit(100)
    )
    indicators = indicators_result.scalars().all()

    return {
        "pulse": {
            "id": str(pulse.id),
            "pulse_id": pulse.pulse_id,
            "name": pulse.name,
            "description": pulse.description,
            "author_name": pulse.author_name,
            "created": pulse.created,
            "modified": pulse.modified,
            "tlp": pulse.tlp,
            "adversary": pulse.adversary,
            "targeted_countries": pulse.targeted_countries or [],
            "industries": pulse.industries or [],
            "tags": pulse.tags or [],
            "references": pulse.references or [],
            "indicator_count": pulse.indicator_count,
            "attack_ids": pulse.attack_ids or [],
            "malware_families": pulse.malware_families or [],
            "exported_to_misp": pulse.exported_to_misp,
            "synced_at": pulse.synced_at
        },
        "indicators": [
            {
                "id": str(i.id),
                "type": i.indicator_type,
                "value": i.indicator,
                "title": i.title,
                "description": i.description,
                "created": i.created
            } for i in indicators
        ],
        "indicators_shown": len(indicators),
        "indicators_total": pulse.indicator_count
    }


@router.get("/adversaries")
async def get_adversaries(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get list of unique adversaries with pulse counts
    """
    result = await session.execute(
        select(OTXPulse.adversary, func.count(OTXPulse.id))
        .where(OTXPulse.is_active == True)
        .where(OTXPulse.adversary.isnot(None))
        .where(OTXPulse.adversary != '')
        .group_by(OTXPulse.adversary)
        .order_by(func.count(OTXPulse.id).desc())
    )
    adversaries = [{"name": row[0], "count": row[1]} for row in result.fetchall()]

    return {"adversaries": adversaries}


@router.get("/tags")
async def get_tags(
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get most common tags across all pulses
    """
    # Get all tags from all pulses
    result = await session.execute(
        select(OTXPulse.tags)
        .where(OTXPulse.is_active == True)
        .where(OTXPulse.tags != None)
    )

    # Count tag occurrences
    tag_counts = {}
    for row in result.fetchall():
        if row[0]:
            for tag in row[0]:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

    # Sort by count and limit
    sorted_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

    return {"tags": [{"name": t[0], "count": t[1]} for t in sorted_tags]}


# ====== PULSE SYNC ENDPOINTS ======

@router.post("/pulses/sync")
async def sync_otx_pulses(
    request: PulseSyncRequest,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    Sincroniza pulses subscritos do OTX

    Requer: role admin ou power
    """
    service = OTXPulseSyncService(session)

    # Executar sync em background
    background_tasks.add_task(service.sync_subscribed_pulses, request.limit)

    return {
        "status": "started",
        "message": f"Pulse sync started (limit={request.limit})",
        "info": "Sync running in background. Check /pulses/sync-history for progress"
    }


@router.post("/pulses/sync/search")
async def search_and_sync_pulses(
    request: PulseSearchRequest,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    Busca e sincroniza pulses por query (tags, adversary, etc)

    Requer: role admin ou power
    """
    service = OTXPulseSyncService(session)

    # Executar em background
    background_tasks.add_task(service.sync_pulses_by_search, request.query, request.limit)

    return {
        "status": "started",
        "message": f"Pulse search sync started: '{request.query}' (limit={request.limit})",
        "info": "Sync running in background"
    }


@router.get("/pulses/sync-history")
async def get_sync_history(
    limit: int = 10,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    Histórico de sincronizações

    Requer: role admin ou power
    """
    service = OTXPulseSyncService(session)
    history = await service.get_sync_history(limit)

    return {
        "count": len(history),
        "history": history
    }


@router.get("/pulses/stats")
async def get_pulse_stats(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    Estatísticas de pulses sincronizados

    Requer: role admin ou power
    """
    service = OTXPulseSyncService(session)
    stats = await service.get_pulse_stats()

    return stats


# ====== MISP EXPORT ENDPOINTS ======

@router.post("/pulses/export/misp")
async def export_pulse_to_misp(
    request: ExportPulseRequest,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"]))
):
    """
    Exporta um pulse específico para MISP

    Requer: role admin
    """
    exporter = OTXMISPExporter(session)
    result = await exporter.export_pulse_to_misp(str(request.pulse_id))

    if not result['success']:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result['message']
        )

    return result


@router.post("/pulses/export/misp/batch")
async def export_pending_pulses_to_misp(
    background_tasks: BackgroundTasks,
    limit: int = 10,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"]))
):
    """
    Exporta pulses pendentes para MISP em batch

    Requer: role admin
    """
    exporter = OTXMISPExporter(session)

    # Executar em background
    background_tasks.add_task(exporter.export_pending_pulses, limit)

    return {
        "status": "started",
        "message": f"Batch export to MISP started (limit={limit})",
        "info": "Export running in background"
    }


@router.get("/pulses/export/stats")
async def get_export_stats(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    Estatísticas de export para MISP

    Requer: role admin ou power
    """
    exporter = OTXMISPExporter(session)
    stats = await exporter.get_export_stats()

    return stats


# ====== BULK ENRICHMENT ENDPOINTS ======

@router.post("/iocs/enrich/bulk")
async def bulk_enrich_iocs(
    request: BulkEnrichmentRequest,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    Enriquece IOCs do MISP em massa com dados OTX

    Requer: role admin ou power
    """
    service = OTXBulkEnrichmentService(session)

    # Executar em background
    background_tasks.add_task(
        service.enrich_misp_iocs,
        request.limit,
        request.ioc_types,
        request.priority_only
    )

    return {
        "status": "started",
        "message": f"Bulk enrichment started (limit={request.limit}, priority_only={request.priority_only})",
        "info": "Enrichment running in background. Check /iocs/enrich/stats for progress"
    }


@router.post("/pulses/{pulse_id}/enrich-indicators")
async def enrich_pulse_indicators(
    pulse_id: UUID,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    Enriquece todos os indicators de um pulse específico

    Requer: role admin ou power
    """
    service = OTXBulkEnrichmentService(session)

    # Executar em background
    background_tasks.add_task(service.enrich_pulse_indicators, str(pulse_id))

    return {
        "status": "started",
        "message": f"Pulse indicators enrichment started for pulse {pulse_id}",
        "info": "Enrichment running in background"
    }


@router.get("/iocs/enrich/stats")
async def get_enrichment_stats(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    Estatísticas de enriquecimento de IOCs

    Requer: role admin ou power
    """
    service = OTXBulkEnrichmentService(session)
    stats = await service.get_enrichment_stats()

    return stats


# ====== COMBINED STATS ENDPOINT ======

@router.get("/otx/overview")
async def get_otx_overview(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    Overview completo do sistema OTX

    Retorna estatísticas de:
    - Pulses sincronizados
    - Export para MISP
    - Enriquecimento de IOCs
    - Chaves OTX

    Requer: role admin ou power
    """
    pulse_service = OTXPulseSyncService(session)
    exporter = OTXMISPExporter(session)
    enrichment_service = OTXBulkEnrichmentService(session)

    from app.cti.services.otx_key_manager import OTXKeyManager
    key_manager = OTXKeyManager(session)

    pulse_stats = await pulse_service.get_pulse_stats()
    export_stats = await exporter.get_export_stats()
    enrichment_stats = await enrichment_service.get_enrichment_stats()
    key_stats = await key_manager.get_key_stats()

    return {
        "pulses": pulse_stats,
        "misp_export": export_stats,
        "enrichment": enrichment_stats,
        "api_keys": key_stats
    }
