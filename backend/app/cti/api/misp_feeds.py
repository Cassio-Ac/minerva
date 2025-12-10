"""
MISP Feeds API

Endpoints para gerenciar feeds MISP e buscar IOCs.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import logging
from uuid import UUID

from app.db.database import get_db
from app.cti.services.misp_feed_service import MISPFeedService
from app.cti.services.otx_service import OTXService
from app.cti.services.ioc_enrichment_service import IOCEnrichmentService
from app.cti.schemas.misp_ioc import (
    MISPFeed,
    MISPFeedCreate,
    MISPFeedUpdate,
    MISPIoC,
    MISPIoCSearch,
    MISPIoCStats,
)
from app.core.dependencies import get_current_user

router = APIRouter(prefix="/misp", tags=["CTI - MISP Feeds"])
logger = logging.getLogger(__name__)


@router.post("/feeds/test", summary="Test CIRCL feed")
async def test_circl_feed(
    limit: int = Query(default=5, ge=1, le=50, description="Number of events to process"),
    current_user: dict = Depends(get_current_user),
):
    """
    Testar import do feed CIRCL OSINT (primeiros N eventos)

    **Teste sem persistência no banco**
    """
    logger.info(f"🧪 Testing CIRCL feed (limit={limit})...")

    service = MISPFeedService(db=None)  # Não precisa de DB para teste
    iocs = service.fetch_circl_feed(limit=limit)

    return {
        "status": "success",
        "feed": "CIRCL OSINT",
        "feed_url": service.CIRCL_FEED,
        "events_processed": limit,
        "iocs_found": len(iocs),
        "sample": iocs[:5],  # Mostrar primeiros 5 IOCs
    }


@router.post("/feeds/sync", summary="Sync CIRCL feed to database")
async def sync_circl_feed(
    limit: int = Query(default=10, ge=1, le=100, description="Number of events to sync"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Sincronizar feed CIRCL OSINT para o banco de dados

    **Requer autenticação admin**
    """
    logger.info(f"🔄 Syncing CIRCL feed to database (limit={limit})...")

    service = MISPFeedService(db)

    # 1. Buscar ou criar feed CIRCL
    circl_feed = await service.get_feed_by_name("CIRCL OSINT")

    if not circl_feed:
        logger.info("📝 Creating CIRCL OSINT feed...")
        circl_feed = await service.create_feed(
            {
                "name": "CIRCL OSINT",
                "url": service.CIRCL_FEED,
                "feed_type": "misp",
                "is_public": True,
                "is_active": True,
                "sync_frequency": "daily",
            }
        )

    # 2. Fetch IOCs
    iocs = service.fetch_circl_feed(limit=limit)

    if not iocs:
        raise HTTPException(status_code=500, detail="Failed to fetch IOCs from CIRCL feed")

    # 3. Import IOCs
    imported_count = await service.import_iocs(iocs, str(circl_feed.id))

    return {
        "status": "success",
        "feed_id": str(circl_feed.id),
        "feed_name": circl_feed.name,
        "events_processed": limit,
        "iocs_found": len(iocs),
        "iocs_imported": imported_count,
    }


@router.get("/feeds", response_model=List[MISPFeed], summary="List all feeds")
async def list_feeds(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Listar todos os feeds MISP configurados
    """
    service = MISPFeedService(db)
    feeds = await service.list_feeds()
    return feeds


@router.get("/feeds/available", summary="List available public feeds")
async def list_available_feeds(
    current_user: dict = Depends(get_current_user),
):
    """
    Listar todos os feeds públicos disponíveis

    Retorna lista de feeds que podem ser configurados
    """
    service = MISPFeedService()
    return {
        "feeds": [
            {
                "id": feed_id,
                **feed_info
            }
            for feed_id, feed_info in service.FEEDS.items()
        ]
    }


@router.get("/feeds/{feed_id}", response_model=MISPFeed, summary="Get feed by ID")
async def get_feed(
    feed_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Obter feed por ID
    """
    service = MISPFeedService(db)
    feed = await service.get_feed(str(feed_id))

    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    return feed


@router.post("/feeds", response_model=MISPFeed, summary="Create new feed")
async def create_feed(
    feed_data: MISPFeedCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Criar novo feed MISP
    """
    service = MISPFeedService(db)
    feed = await service.create_feed(feed_data.dict())
    return feed


@router.get("/iocs/search", summary="Search IOC by value")
async def search_ioc(
    value: str = Query(..., description="IOC value (IP, domain, hash, etc)"),
    search_live_feeds: bool = Query(default=True, description="Search in live feeds if not found in database"),
    enrich_with_llm: bool = Query(default=True, description="Automatically enrich IOC with LLM analysis"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Buscar IOC por valor (MISP database + live feeds + OTX + LLM enrichment)

    **Exemplo:**
    - `value=185.176.43.94` → busca IP
    - `value=evil.com` → busca domain
    - `value=db349b97c37d22f5ea1d1841e3c89eb4` → busca hash MD5

    **Search sources:**
    1. MISP Database (fast)
    2. MISP Live feeds (slower, only if search_live_feeds=true)
    3. AlienVault OTX (always searched)
    4. LLM Enrichment (if enrich_with_llm=true and IOC found)
    """
    service = MISPFeedService(db)
    otx_service = OTXService()
    enrichment_service = IOCEnrichmentService()

    # Initialize results
    misp_result = None
    otx_result = None
    enrichment_result = None

    # Search in MISP database first
    ioc = await service.search_ioc(value)
    if ioc:
        misp_result = {"found": True, "ioc": ioc, "source": "database"}
        logger.info(f"✅ Found in MISP database")

    # Search in live feeds if not found in database and enabled
    elif search_live_feeds:
        logger.info(f"🔍 Searching '{value}' in MISP live feeds...")
        ioc = service.search_ioc_in_live_feeds(value)
        if ioc:
            misp_result = {"found": True, "ioc": ioc, "source": "live_feeds"}
            logger.info(f"✅ Found in MISP live feeds")

    # If not found in MISP
    if not misp_result:
        misp_result = {"found": False, "ioc": None, "source": None, "message": "Not found in MISP database or live feeds"}

    # Always search in OTX
    logger.info(f"🔍 Searching '{value}' in AlienVault OTX...")
    otx_result = otx_service.search_indicator(value)

    # LLM Enrichment if IOC was found and enrichment enabled
    if enrich_with_llm and misp_result.get("found"):
        logger.info(f"🧠 Enriching IOC with LLM analysis...")
        try:
            ioc_data = misp_result["ioc"]
            enrichment_result = await enrichment_service.enrich_ioc_with_llm(ioc_data)
            logger.info(f"✅ LLM enrichment completed")
        except Exception as e:
            logger.error(f"❌ LLM enrichment failed: {e}")
            enrichment_result = {"error": str(e)}

    return {
        "misp": misp_result,
        "otx": otx_result,
        "enrichment": enrichment_result
    }


@router.get("/iocs/stats", response_model=MISPIoCStats, summary="Get IOC statistics")
async def get_ioc_stats(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Obter estatísticas de IOCs do Elasticsearch (unified_iocs index)

    Returns stats from the unified IOC index which contains both MISP and OTX data.
    """
    from app.cti.services.unified_ioc_service import UnifiedIOCService

    service = UnifiedIOCService()
    try:
        es_stats = await service.get_stats()

        # Map ES stats to MISPIoCStats format for backward compatibility
        return {
            "total_iocs": es_stats.get("total_iocs", 0),
            "by_type": es_stats.get("by_type", {}),
            "by_tlp": es_stats.get("by_tlp", {}),
            "by_confidence": es_stats.get("by_confidence_level", {}),
            "by_feed": es_stats.get("by_source", {}),  # source = feed in new architecture
            "feeds_count": len(es_stats.get("by_source", {})),
            "last_sync": None  # ES doesn't track global last_sync
        }
    finally:
        await service.close()


@router.get("/iocs", summary="List IOCs with filtering")
async def list_iocs(
    search: Optional[str] = Query(None, description="Search in value, threat_actor, malware_family, comment"),
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type (ip, domain, url, hash, email)"),
    threat_actor: Optional[str] = Query(None, description="Filter by threat actor"),
    malware_family: Optional[str] = Query(None, description="Filter by malware family"),
    feed_id: Optional[str] = Query(None, description="Filter by feed ID"),
    limit: int = Query(default=100, ge=1, le=1000, description="Number of IOCs to return"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Listar IOCs salvos no banco com filtros opcionais

    **Filtros:**
    - `search`: Busca em value, threat_actor, malware_family, comment
    - `ioc_type`: ip, domain, url, hash, email
    - `threat_actor`: Nome do threat actor
    - `malware_family`: Nome da família de malware
    - `feed_id`: UUID do feed
    - `limit`: Quantidade máxima de resultados
    - `offset`: Paginação
    """
    service = MISPFeedService(db)
    iocs = await service.list_iocs(
        search=search,
        ioc_type=ioc_type,
        threat_actor=threat_actor,
        malware_family=malware_family,
        feed_id=feed_id,
        limit=limit,
        offset=offset
    )
    return iocs


@router.post("/feeds/test/{feed_type}", summary="Test specific feed type")
async def test_specific_feed(
    feed_type: str,
    limit: int = Query(default=5, ge=1, le=5000, description="Number of events/items to process"),
    otx_api_key: Optional[str] = Query(None, description="OTX API key (required for OTX feed)"),
    use_pagination: bool = Query(default=False, description="Use pagination for OTX (slower but more complete)"),
    current_user: dict = Depends(get_current_user),
):
    """
    Testar feed específico por tipo

    **Tipos disponíveis:**
    - `circl_osint` - CIRCL OSINT Feed
    - `urlhaus` - URLhaus malicious URLs
    - `threatfox` - ThreatFox IOCs
    - `otx` - AlienVault OTX (requer API key)

    **Teste sem persistência no banco**
    """
    service = MISPFeedService(db=None)

    if feed_type not in service.FEEDS:
        raise HTTPException(status_code=404, detail=f"Feed type '{feed_type}' not found")

    feed_info = service.FEEDS[feed_type]

    # Validar autenticação se necessário
    if feed_info["requires_auth"] and not otx_api_key:
        raise HTTPException(status_code=400, detail=f"Feed '{feed_type}' requires authentication (otx_api_key)")

    logger.info(f"🧪 Testing {feed_type} feed (limit={limit})...")

    # Buscar IOCs baseado no tipo
    iocs = []
    if feed_type == "circl_osint":
        iocs = service.fetch_circl_feed(limit=limit)
    elif feed_type == "urlhaus":
        iocs = service.fetch_urlhaus_feed(limit=limit)
    elif feed_type == "threatfox":
        iocs = service.fetch_threatfox_feed(limit=limit)
    elif feed_type == "otx":
        iocs = service.fetch_otx_feed(api_key=otx_api_key, limit=limit, use_pagination=use_pagination)
    elif feed_type == "openphish":
        iocs = service.fetch_openphish_feed(limit=limit)
    elif feed_type == "serpro":
        iocs = service.fetch_serpro_feed(limit=limit)
    elif feed_type == "bambenek_dga":
        iocs = service.fetch_bambenek_dga_feed(limit=limit)
    elif feed_type == "emerging_threats":
        iocs = service.fetch_emerging_threats_feed(limit=limit)
    elif feed_type == "alienvault_reputation":
        iocs = service.fetch_alienvault_reputation_feed(limit=limit)
    elif feed_type == "sslbl":
        iocs = service.fetch_sslbl_feed(limit=limit)
    elif feed_type == "digitalside":
        iocs = service.fetch_digitalside_feed(limit=limit)
    elif feed_type == "blocklist_de":
        iocs = service.fetch_blocklist_de_feed(limit=limit)
    elif feed_type == "greensnow":
        iocs = service.fetch_greensnow_feed(limit=limit)
    elif feed_type == "diamondfox_c2":
        iocs = service.fetch_diamondfox_c2_feed(limit=limit)
    elif feed_type == "cins_badguys":
        iocs = service.fetch_cins_badguys_feed(limit=limit)
    else:
        raise HTTPException(status_code=400, detail=f"Feed type '{feed_type}' not implemented yet")

    return {
        "status": "success",
        "feed_type": feed_type,
        "feed_name": feed_info["name"],
        "feed_url": feed_info["url"],
        "items_processed": limit,
        "iocs_found": len(iocs),
        "sample": iocs[:5],  # Mostrar primeiros 5 IOCs
    }


@router.post("/feeds/sync/{feed_type}", summary="Sync specific feed to database")
async def sync_specific_feed(
    feed_type: str,
    limit: int = Query(default=100, ge=1, le=10000, description="Number of items to sync"),
    otx_api_key: Optional[str] = Query(None, description="OTX API key (required for OTX)"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Sincronizar feed específico para o banco de dados

    **Tipos disponíveis:**
    - `circl_osint` - CIRCL OSINT Feed (~500 IOCs)
    - `urlhaus` - URLhaus (~1000 IOCs)
    - `threatfox` - ThreatFox IOCs
    - `otx` - AlienVault OTX (requer API key, ~2000 IOCs)

    **Requer autenticação admin**
    """
    service = MISPFeedService(db)

    if feed_type not in service.FEEDS:
        raise HTTPException(status_code=404, detail=f"Feed type '{feed_type}' not found")

    feed_info = service.FEEDS[feed_type]

    # Validar autenticação se necessário
    if feed_info["requires_auth"] and not otx_api_key:
        raise HTTPException(status_code=400, detail=f"Feed '{feed_type}' requires otx_api_key")

    logger.info(f"🔄 Syncing {feed_type} to database (limit={limit})...")

    # 1. Buscar ou criar feed
    feed = await service.get_feed_by_name(feed_info["name"])

    if not feed:
        logger.info(f"📝 Creating {feed_info['name']} feed...")
        feed = await service.create_feed(
            {
                "name": feed_info["name"],
                "url": feed_info["url"],
                "feed_type": feed_info["type"],
                "is_public": True,
                "is_active": True,
                "sync_frequency": "daily",
            }
        )

    # 2. Fetch IOCs baseado no tipo
    iocs = []
    if feed_type == "circl_osint":
        iocs = service.fetch_circl_feed(limit=limit)
    elif feed_type == "urlhaus":
        iocs = service.fetch_urlhaus_feed(limit=limit)
    elif feed_type == "threatfox":
        iocs = service.fetch_threatfox_feed(limit=limit)
    elif feed_type == "otx":
        iocs = service.fetch_otx_feed(api_key=otx_api_key, limit=limit, use_pagination=use_pagination)
    elif feed_type == "openphish":
        iocs = service.fetch_openphish_feed(limit=limit)
    elif feed_type == "serpro":
        iocs = service.fetch_serpro_feed(limit=limit)
    elif feed_type == "bambenek_dga":
        iocs = service.fetch_bambenek_dga_feed(limit=limit)
    elif feed_type == "emerging_threats":
        iocs = service.fetch_emerging_threats_feed(limit=limit)
    elif feed_type == "alienvault_reputation":
        iocs = service.fetch_alienvault_reputation_feed(limit=limit)
    elif feed_type == "sslbl":
        iocs = service.fetch_sslbl_feed(limit=limit)
    elif feed_type == "digitalside":
        iocs = service.fetch_digitalside_feed(limit=limit)
    elif feed_type == "blocklist_de":
        iocs = service.fetch_blocklist_de_feed(limit=limit)
    elif feed_type == "greensnow":
        iocs = service.fetch_greensnow_feed(limit=limit)
    elif feed_type == "diamondfox_c2":
        iocs = service.fetch_diamondfox_c2_feed(limit=limit)
    elif feed_type == "cins_badguys":
        iocs = service.fetch_cins_badguys_feed(limit=limit)
    else:
        raise HTTPException(status_code=400, detail=f"Feed type '{feed_type}' not implemented yet")

    if not iocs:
        raise HTTPException(status_code=500, detail=f"Failed to fetch IOCs from {feed_type}")

    # 3. Import IOCs
    imported_count = await service.import_iocs(iocs, str(feed.id))

    return {
        "status": "success",
        "feed_id": str(feed.id),
        "feed_name": feed.name,
        "feed_type": feed_type,
        "items_processed": limit,
        "iocs_found": len(iocs),
        "iocs_imported": imported_count,
    }


@router.post("/feeds/sync-all", summary="Sync all MISP feeds (async task)")
async def sync_all_feeds(
    quick: bool = Query(default=True, description="Quick sync with lower limits (faster)"),
    current_user: dict = Depends(get_current_user),
):
    """
    Trigger async sync of ALL available MISP feeds

    **Modes:**
    - `quick=true` (default): Quick sync with ~500-1000 IOCs per feed (faster)
    - `quick=false`: Full sync with up to 5000 IOCs per feed (slower but more complete)

    **Note:** This triggers a Celery background task. Check logs for progress.
    """
    from app.tasks.misp_tasks import sync_all_misp_feeds, quick_sync_all_feeds

    if quick:
        task = quick_sync_all_feeds.delay()
        return {
            "status": "queued",
            "task_id": task.id,
            "mode": "quick",
            "message": "Quick MISP sync task queued. Check Celery logs for progress."
        }
    else:
        task = sync_all_misp_feeds.delay()
        return {
            "status": "queued",
            "task_id": task.id,
            "mode": "full",
            "message": "Full MISP sync task queued. Check Celery logs for progress."
        }


@router.get("/feeds/sync-status", summary="Get sync schedule info")
async def get_sync_status(
    current_user: dict = Depends(get_current_user),
):
    """
    Get information about the automatic sync schedule

    MISP feeds are automatically synced every 2 hours.
    """
    from app.cti.services.misp_feed_service import MISPFeedService

    service = MISPFeedService()
    available_feeds = [
        {"id": feed_id, "name": feed_info["name"], "requires_auth": feed_info.get("requires_auth", False)}
        for feed_id, feed_info in service.FEEDS.items()
    ]

    return {
        "schedule": "Every 2 hours (at minute 0)",
        "cron": "0 */2 * * *",
        "timezone": "America/Sao_Paulo",
        "feeds_count": len(available_feeds),
        "feeds": available_feeds,
        "note": "Feeds requiring authentication (OTX) are handled separately"
    }
