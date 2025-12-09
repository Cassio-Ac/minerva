"""
IOC Enrichment API

Endpoints para enriquecer IOCs usando LLM e threat intelligence.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional, List
import logging

from app.core.dependencies import get_current_user
from app.cti.services.ioc_enrichment_service import get_ioc_enrichment_service
from app.cti.services.misp_feed_service import MISPFeedService

router = APIRouter(prefix="/ioc-enrichment", tags=["CTI - IOC Enrichment"])
logger = logging.getLogger(__name__)


@router.post("/enrich-single", summary="Enrich single IOC")
async def enrich_single_ioc(
    ioc_type: str = Query(..., description="IOC type (ip, url, domain, hash, etc)"),
    ioc_value: str = Query(..., description="IOC value"),
    context: Optional[str] = Query(None, description="Additional context"),
    malware_family: Optional[str] = Query(None, description="Known malware family"),
    threat_actor: Optional[str] = Query(None, description="Known threat actor"),
    tags: Optional[str] = Query(None, description="Comma-separated tags"),
    llm_provider: Optional[str] = Query(None, description="LLM provider ID (optional)"),
    current_user: dict = Depends(get_current_user),
):
    """
    Enriquece um único IOC usando LLM

    **Example:**
    - `ioc_type=ip&ioc_value=192.168.1.1&context=C2 server`
    - `ioc_type=url&ioc_value=http://evil.com/panel&malware_family=DiamondFox`
    """
    logger.info(f"🔍 Enriching IOC: {ioc_type}/{ioc_value}")

    # Build IOC data
    ioc_data = {
        "type": ioc_type,
        "value": ioc_value,
        "context": context if context else f"Manual enrichment request for {ioc_type}",
        "malware_family": malware_family,
        "threat_actor": threat_actor,
        "tags": tags.split(',') if tags else [],
        "feed_source": "Manual Request"
    }

    # Enrich
    service = get_ioc_enrichment_service()
    enrichment = await service.enrich_ioc_with_llm(ioc_data, llm_provider)

    return {
        "status": "success",
        "ioc": ioc_data,
        "enrichment": enrichment
    }


@router.post("/enrich-from-feed", summary="Enrich IOCs from a specific feed")
async def enrich_from_feed(
    feed_type: str = Query(..., description="Feed type (e.g., diamondfox_c2, sslbl)"),
    limit: int = Query(default=5, ge=1, le=20, description="Number of IOCs to enrich"),
    llm_provider: Optional[str] = Query(None, description="LLM provider ID (optional)"),
    current_user: dict = Depends(get_current_user),
):
    """
    Busca IOCs de um feed e enriquece usando LLM

    **Feeds suportados:**
    - diamondfox_c2 - DiamondFox C2 Panels
    - sslbl - abuse.ch SSL Blacklist
    - openphish - Phishing URLs
    - serpro - Brazilian Government IPs
    - urlhaus - Malicious URLs
    - threatfox - Threat IOCs
    - emerging_threats - Compromised IPs
    - alienvault_reputation - IP Reputation
    - blocklist_de - Aggregated IPs
    - greensnow - Malicious IPs
    - cins_badguys - CINS Score IPs

    **Example:**
    - `feed_type=diamondfox_c2&limit=3`
    """
    logger.info(f"📡 Fetching {limit} IOCs from {feed_type} for enrichment...")

    # Fetch IOCs from feed
    feed_service = MISPFeedService(db=None)

    if feed_type not in feed_service.FEEDS:
        raise HTTPException(status_code=404, detail=f"Feed type '{feed_type}' not found")

    # Fetch IOCs based on feed type
    iocs = []
    try:
        if feed_type == "diamondfox_c2":
            iocs = feed_service.fetch_diamondfox_c2_feed(limit=limit)
        elif feed_type == "sslbl":
            iocs = feed_service.fetch_sslbl_feed(limit=limit)
        elif feed_type == "openphish":
            iocs = feed_service.fetch_openphish_feed(limit=limit)
        elif feed_type == "serpro":
            iocs = feed_service.fetch_serpro_feed(limit=limit)
        elif feed_type == "urlhaus":
            iocs = feed_service.fetch_urlhaus_feed(limit=limit)
        elif feed_type == "threatfox":
            iocs = feed_service.fetch_threatfox_feed(limit=limit)
        elif feed_type == "emerging_threats":
            iocs = feed_service.fetch_emerging_threats_feed(limit=limit)
        elif feed_type == "alienvault_reputation":
            iocs = feed_service.fetch_alienvault_reputation_feed(limit=limit)
        elif feed_type == "blocklist_de":
            iocs = feed_service.fetch_blocklist_de_feed(limit=limit)
        elif feed_type == "greensnow":
            iocs = feed_service.fetch_greensnow_feed(limit=limit)
        elif feed_type == "cins_badguys":
            iocs = feed_service.fetch_cins_badguys_feed(limit=limit)
        else:
            raise HTTPException(status_code=400, detail=f"Feed type '{feed_type}' not supported yet")

    except Exception as e:
        logger.error(f"❌ Error fetching from feed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch IOCs: {str(e)}")

    if not iocs:
        raise HTTPException(status_code=404, detail=f"No IOCs found in feed '{feed_type}'")

    # Add feed_source to IOCs
    for ioc in iocs:
        ioc["feed_source"] = feed_service.FEEDS[feed_type]["name"]

    # Enrich IOCs
    enrichment_service = get_ioc_enrichment_service()
    enriched_iocs = await enrichment_service.enrich_iocs_batch(iocs, llm_provider, max_iocs=limit)

    return {
        "status": "success",
        "feed_type": feed_type,
        "feed_name": feed_service.FEEDS[feed_type]["name"],
        "iocs_fetched": len(iocs),
        "iocs_enriched": len(enriched_iocs),
        "enriched_iocs": enriched_iocs
    }


@router.get("/stats", summary="Get enrichment statistics")
async def get_enrichment_stats(
    current_user: dict = Depends(get_current_user),
):
    """
    Retorna estatísticas sobre enrichment de IOCs

    (Placeholder para futuras métricas)
    """
    return {
        "status": "success",
        "message": "Statistics endpoint - to be implemented with database tracking"
    }
