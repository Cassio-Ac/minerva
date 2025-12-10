"""
OTX Pulses API Endpoints

API para gerenciar sincronização e visualização de pulses OTX.
Dados agora vêm do Elasticsearch (unified_iocs index).
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.database import get_db
from app.cti.services.otx_pulse_sync_service import OTXPulseSyncService
from app.models.user import User
from app.core.dependencies import get_current_user, require_role
from pydantic import BaseModel
from typing import List, Optional
from uuid import UUID
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

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
    search: Optional[str] = Query(None, description="Search in tags, threat_actor, malware_family"),
    adversary: Optional[str] = Query(None, description="Filter by adversary/threat actor"),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List OTX IOCs from Elasticsearch unified_iocs index.

    In Architecture v2.0, OTX data is stored as unified IOCs.
    This endpoint returns IOC groups aggregated by threat_actor/malware_family.
    """
    from app.db.elasticsearch import get_es_client

    es = await get_es_client()

    try:
        # Build query for OTX source
        must_clauses = [{"term": {"source_names": "otx"}}]

        if search:
            must_clauses.append({
                "multi_match": {
                    "query": search,
                    "fields": ["ioc_value", "tags", "threat_actor", "malware_family"],
                    "type": "best_fields"
                }
            })

        if adversary:
            must_clauses.append({"match": {"threat_actor": adversary}})

        if tag:
            must_clauses.append({"term": {"tags": tag}})

        # Get aggregations by threat_actor and malware_family
        body = {
            "size": 0,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "must": must_clauses
                }
            },
            "aggs": {
                "by_threat_actor": {
                    "terms": {
                        "field": "threat_actor.keyword",
                        "size": 500
                    },
                    "aggs": {
                        "sample": {"top_hits": {"size": 1}},
                        "tags": {"terms": {"field": "tags", "size": 5}},
                        "types": {"terms": {"field": "ioc_type", "size": 5}}
                    }
                },
                "by_malware": {
                    "terms": {
                        "field": "malware_family.keyword",
                        "size": 500
                    },
                    "aggs": {
                        "sample": {"top_hits": {"size": 1}},
                        "tags": {"terms": {"field": "tags", "size": 5}}
                    }
                }
            }
        }

        result = await es.search(index="unified_iocs", body=body)
        total_iocs = result.get("hits", {}).get("total", {}).get("value", 0)
        aggs = result.get("aggregations", {})

        # Convert aggregations to PulseResponse format
        pulses = []

        # Add threat actor groups
        for bucket in aggs.get("by_threat_actor", {}).get("buckets", []):
            actor_name = bucket["key"]
            if not actor_name:
                continue
            sample = bucket.get("sample", {}).get("hits", {}).get("hits", [{}])[0].get("_source", {})
            tags = [t["key"] for t in bucket.get("tags", {}).get("buckets", [])]

            pulses.append(PulseResponse(
                id=f"actor-{actor_name}",
                pulse_id=f"actor-{actor_name}",
                name=f"Threat Actor: {actor_name}",
                description=f"IOCs associated with {actor_name}",
                author_name="OTX",
                created=sample.get("first_seen"),
                modified=sample.get("last_seen"),
                tlp=sample.get("tlp", "white"),
                adversary=actor_name,
                targeted_countries=sample.get("targeted_countries", []),
                industries=[],
                tags=tags,
                indicator_count=bucket["doc_count"],
                attack_ids=sample.get("mitre_attack", []),
                malware_families=[],
                exported_to_misp=False,
                synced_at=datetime.now()
            ))

        # Add malware family groups
        for bucket in aggs.get("by_malware", {}).get("buckets", []):
            malware_name = bucket["key"]
            if not malware_name:
                continue
            sample = bucket.get("sample", {}).get("hits", {}).get("hits", [{}])[0].get("_source", {})
            tags = [t["key"] for t in bucket.get("tags", {}).get("buckets", [])]

            pulses.append(PulseResponse(
                id=f"malware-{malware_name}",
                pulse_id=f"malware-{malware_name}",
                name=f"Malware: {malware_name}",
                description=f"IOCs associated with {malware_name}",
                author_name="OTX",
                created=sample.get("first_seen"),
                modified=sample.get("last_seen"),
                tlp=sample.get("tlp", "white"),
                adversary=sample.get("threat_actor"),
                targeted_countries=sample.get("targeted_countries", []),
                industries=[],
                tags=tags,
                indicator_count=bucket["doc_count"],
                attack_ids=sample.get("mitre_attack", []),
                malware_families=[malware_name],
                exported_to_misp=False,
                synced_at=datetime.now()
            ))

        # Sort by indicator count
        pulses.sort(key=lambda x: x.indicator_count, reverse=True)

        # Apply pagination
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_pulses = pulses[start_idx:end_idx]

        return PulsesListResponse(
            total=len(pulses),
            page=page,
            page_size=page_size,
            pulses=paginated_pulses
        )

    except Exception as e:
        logger.error(f"Error fetching OTX pulses from ES: {e}")
        return PulsesListResponse(
            total=0,
            page=page,
            page_size=page_size,
            pulses=[]
        )
    finally:
        await es.close()


@router.get("/pulses/{pulse_id}/detail")
async def get_pulse_detail(
    pulse_id: str,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get detailed information about a specific pulse including indicators from Elasticsearch.
    """
    from app.db.elasticsearch import get_es_client

    es = await get_es_client()

    try:
        # Search for IOCs from this pulse (by source_ref)
        body = {
            "size": 100,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"source_names": "otx"}},
                        {"nested": {
                            "path": "sources",
                            "query": {
                                "term": {"sources.source_ref": pulse_id}
                            }
                        }}
                    ]
                }
            },
            "sort": [{"last_seen": "desc"}]
        }

        result = await es.search(index="unified_iocs", body=body)
        hits = result.get("hits", {}).get("hits", [])

        if not hits:
            raise HTTPException(status_code=404, detail="Pulse not found")

        # Aggregate info from first IOC
        first_ioc = hits[0]["_source"]

        # Find OTX source info
        otx_source = None
        for src in first_ioc.get("sources", []):
            if src.get("source_name") == "otx":
                otx_source = src
                break

        # Build indicators list
        indicators = []
        unique_tags = set()
        for hit in hits:
            src = hit["_source"]
            indicators.append({
                "id": hit["_id"],
                "type": src.get("ioc_type"),
                "value": src.get("ioc_value"),
                "title": None,
                "description": otx_source.get("context") if otx_source else None,
                "created": src.get("first_seen")
            })
            for tag in src.get("tags", []):
                unique_tags.add(tag)

        return {
            "pulse": {
                "id": pulse_id,
                "pulse_id": pulse_id,
                "name": f"OTX Pulse: {pulse_id}",
                "description": otx_source.get("context") if otx_source else None,
                "author_name": "OTX",
                "created": first_ioc.get("first_seen"),
                "modified": first_ioc.get("last_seen"),
                "tlp": first_ioc.get("tlp", "white"),
                "adversary": first_ioc.get("threat_actor"),
                "targeted_countries": first_ioc.get("targeted_countries", []),
                "industries": [],
                "tags": list(unique_tags),
                "references": first_ioc.get("references", []),
                "indicator_count": result.get("hits", {}).get("total", {}).get("value", 0),
                "attack_ids": first_ioc.get("mitre_attack", []),
                "malware_families": [first_ioc.get("malware_family")] if first_ioc.get("malware_family") else [],
                "exported_to_misp": False,
                "synced_at": datetime.now()
            },
            "indicators": indicators,
            "indicators_shown": len(indicators),
            "indicators_total": result.get("hits", {}).get("total", {}).get("value", 0)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting pulse detail: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await es.close()


@router.get("/adversaries")
async def get_adversaries(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get list of unique adversaries (threat actors) with IOC counts from Elasticsearch.
    """
    from app.db.elasticsearch import get_es_client

    es = await get_es_client()

    try:
        body = {
            "size": 0,
            "query": {"term": {"source_names": "otx"}},
            "aggs": {
                "adversaries": {
                    "terms": {
                        "field": "threat_actor.keyword",
                        "size": 100
                    }
                }
            }
        }

        result = await es.search(index="unified_iocs", body=body)
        buckets = result.get("aggregations", {}).get("adversaries", {}).get("buckets", [])

        adversaries = [{"name": b["key"], "count": b["doc_count"]} for b in buckets if b["key"]]

        return {"adversaries": adversaries}

    except Exception as e:
        logger.error(f"Error getting adversaries: {e}")
        return {"adversaries": []}
    finally:
        await es.close()


@router.get("/tags")
async def get_tags(
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get most common tags across OTX IOCs from Elasticsearch.
    """
    from app.db.elasticsearch import get_es_client

    es = await get_es_client()

    try:
        body = {
            "size": 0,
            "query": {"term": {"source_names": "otx"}},
            "aggs": {
                "tags": {
                    "terms": {
                        "field": "tags",
                        "size": limit
                    }
                }
            }
        }

        result = await es.search(index="unified_iocs", body=body)
        buckets = result.get("aggregations", {}).get("tags", {}).get("buckets", [])

        tags = [{"name": b["key"], "count": b["doc_count"]} for b in buckets]

        return {"tags": tags}

    except Exception as e:
        logger.error(f"Error getting tags: {e}")
        return {"tags": []}
    finally:
        await es.close()


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
    Estatísticas de IOCs OTX do Elasticsearch.

    Requer: role admin ou power
    """
    from app.db.elasticsearch import get_es_client

    es = await get_es_client()

    try:
        body = {
            "size": 0,
            "query": {"term": {"source_names": "otx"}},
            "aggs": {
                "total_iocs": {"value_count": {"field": "ioc_id"}},
                "by_type": {"terms": {"field": "ioc_type", "size": 20}},
                "by_confidence": {"terms": {"field": "confidence_level", "size": 10}},
                "unique_threat_actors": {"cardinality": {"field": "threat_actor.keyword"}},
                "unique_malware_families": {"cardinality": {"field": "malware_family.keyword"}},
                "recent_24h": {"filter": {"range": {"last_seen": {"gte": "now-24h"}}}},
                "recent_7d": {"filter": {"range": {"last_seen": {"gte": "now-7d"}}}}
            }
        }

        result = await es.search(index="unified_iocs", body=body)
        aggs = result.get("aggregations", {})

        return {
            "total_iocs": aggs.get("total_iocs", {}).get("value", 0),
            "by_type": {b["key"]: b["doc_count"] for b in aggs.get("by_type", {}).get("buckets", [])},
            "by_confidence": {b["key"]: b["doc_count"] for b in aggs.get("by_confidence", {}).get("buckets", [])},
            "unique_threat_actors": aggs.get("unique_threat_actors", {}).get("value", 0),
            "unique_malware_families": aggs.get("unique_malware_families", {}).get("value", 0),
            "recent_24h": aggs.get("recent_24h", {}).get("doc_count", 0),
            "recent_7d": aggs.get("recent_7d", {}).get("doc_count", 0),
            "source": "elasticsearch"
        }

    except Exception as e:
        logger.error(f"Error getting pulse stats: {e}")
        return {"error": str(e), "total_iocs": 0}
    finally:
        await es.close()


# ====== DEPRECATED MISP EXPORT ENDPOINTS ======
# These endpoints are deprecated in Architecture v2.0
# OTX data now goes directly to Elasticsearch, no intermediate MISP export

@router.post("/pulses/export/misp")
async def export_pulse_to_misp(
    request: ExportPulseRequest,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"]))
):
    """
    DEPRECATED: OTX data now syncs directly to Elasticsearch.
    """
    return {
        "status": "deprecated",
        "message": "MISP export is deprecated in Architecture v2.0. OTX data syncs directly to Elasticsearch."
    }


@router.post("/pulses/export/misp/batch")
async def export_pending_pulses_to_misp(
    background_tasks: BackgroundTasks,
    limit: int = 10,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"]))
):
    """
    DEPRECATED: OTX data now syncs directly to Elasticsearch.
    """
    return {
        "status": "deprecated",
        "message": "Batch MISP export is deprecated in Architecture v2.0. OTX data syncs directly to Elasticsearch."
    }


@router.get("/pulses/export/stats")
async def get_export_stats(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    DEPRECATED: Export stats are no longer available.
    """
    return {
        "status": "deprecated",
        "message": "Export stats deprecated. Use /pulses/stats for Elasticsearch stats."
    }


# ====== DEPRECATED BULK ENRICHMENT ENDPOINTS ======
# IOCs are now enriched during sync to Elasticsearch

@router.post("/iocs/enrich/bulk")
async def bulk_enrich_iocs(
    request: BulkEnrichmentRequest,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    DEPRECATED: IOCs are now enriched during sync to Elasticsearch.
    """
    return {
        "status": "deprecated",
        "message": "Bulk enrichment deprecated. IOCs are enriched during sync to Elasticsearch."
    }


@router.post("/pulses/{pulse_id}/enrich-indicators")
async def enrich_pulse_indicators(
    pulse_id: UUID,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    DEPRECATED: IOCs are now enriched during sync to Elasticsearch.
    """
    return {
        "status": "deprecated",
        "message": "Pulse enrichment deprecated. IOCs are enriched during sync."
    }


@router.get("/iocs/enrich/stats")
async def get_enrichment_stats(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    DEPRECATED: Use /pulses/stats instead.
    """
    return {
        "status": "deprecated",
        "message": "Use /pulses/stats for IOC statistics from Elasticsearch."
    }


# ====== COMBINED STATS ENDPOINT ======

@router.get("/otx/overview")
async def get_otx_overview(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "power"]))
):
    """
    Overview completo do sistema OTX from Elasticsearch.

    Retorna estatísticas de:
    - IOCs OTX no Elasticsearch
    - Chaves OTX configuradas

    Requer: role admin ou power
    """
    from app.db.elasticsearch import get_es_client
    from app.cti.services.otx_key_manager import OTXKeyManager

    es = await get_es_client()
    key_manager = OTXKeyManager(session)

    try:
        # Get OTX IOC stats from Elasticsearch
        body = {
            "size": 0,
            "query": {"term": {"source_names": "otx"}},
            "aggs": {
                "total_iocs": {"value_count": {"field": "ioc_id"}},
                "by_type": {"terms": {"field": "ioc_type", "size": 20}},
                "by_confidence": {"terms": {"field": "confidence_level", "size": 10}},
                "unique_threat_actors": {"cardinality": {"field": "threat_actor.keyword"}},
                "unique_malware_families": {"cardinality": {"field": "malware_family.keyword"}},
                "recent_24h": {"filter": {"range": {"last_seen": {"gte": "now-24h"}}}},
                "recent_7d": {"filter": {"range": {"last_seen": {"gte": "now-7d"}}}}
            }
        }

        result = await es.search(index="unified_iocs", body=body)
        aggs = result.get("aggregations", {})

        ioc_stats = {
            "total_iocs": aggs.get("total_iocs", {}).get("value", 0),
            "by_type": {b["key"]: b["doc_count"] for b in aggs.get("by_type", {}).get("buckets", [])},
            "by_confidence": {b["key"]: b["doc_count"] for b in aggs.get("by_confidence", {}).get("buckets", [])},
            "unique_threat_actors": aggs.get("unique_threat_actors", {}).get("value", 0),
            "unique_malware_families": aggs.get("unique_malware_families", {}).get("value", 0),
            "recent_24h": aggs.get("recent_24h", {}).get("doc_count", 0),
            "recent_7d": aggs.get("recent_7d", {}).get("doc_count", 0)
        }

        # Get API key stats
        key_stats = await key_manager.get_key_stats()

        return {
            "iocs": ioc_stats,
            "api_keys": key_stats,
            "misp_export": {"status": "deprecated", "message": "Use Elasticsearch directly"},
            "enrichment": {"status": "deprecated", "message": "IOCs enriched during sync"},
            "source": "elasticsearch"
        }

    except Exception as e:
        logger.error(f"Error getting OTX overview: {e}")
        return {"error": str(e)}
    finally:
        await es.close()
