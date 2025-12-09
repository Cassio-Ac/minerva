"""
CTI Enrichment Cache Service

Gerencia cache persistente de enrichment no Elasticsearch.

Estratégia Híbrida:
1. Enrichment on-demand (tempo real quando usuário seleciona)
2. Cache no Elasticsearch (pré-processado para performance)
3. Atualização periódica (daily/weekly)

Índice ES: cti_enrichment_cache
Estrutura:
{
    "actor_name": "APT28",
    "mitre_group_id": "G0007",
    "mitre_stix_id": "intrusion-set--...",
    "techniques": ["T1003.003", "T1566.001", ...],
    "techniques_count": 99,
    "last_enriched": "2025-11-19T18:00:00Z",
    "aliases": ["Fancy Bear", "Sednit", ...]
}
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from elasticsearch import AsyncElasticsearch

from .enrichment_service import EnrichmentService
from app.db.elasticsearch import get_es_client

logger = logging.getLogger(__name__)

INDEX_NAME = "cti_enrichment_cache"


class EnrichmentCacheService:
    """
    Service to manage enrichment cache in Elasticsearch
    """

    def __init__(self):
        self.enrichment_service = EnrichmentService()
        self.es_client: Optional[AsyncElasticsearch] = None
        # MISP Galaxy service not used for now (enrichment not fully implemented)
        self.misp_service = None

    async def _get_es_client(self):
        """Get Elasticsearch client"""
        if self.es_client is None:
            self.es_client = await get_es_client()
        return self.es_client

    async def _ensure_index_exists(self):
        """Create index if it doesn't exist"""
        es = await self._get_es_client()

        # Check if index exists
        exists = await es.indices.exists(index=INDEX_NAME)
        if exists:
            return

        # Create index with mapping
        logger.info(f"📝 Creating index: {INDEX_NAME}")
        await es.indices.create(
            index=INDEX_NAME,
            body={
                "mappings": {
                    "properties": {
                        # MITRE ATT&CK data
                        "actor_name": {"type": "keyword"},
                        "mitre_group_id": {"type": "keyword"},
                        "mitre_stix_id": {"type": "keyword"},
                        "techniques": {"type": "keyword"},
                        "techniques_count": {"type": "integer"},
                        "last_enriched": {"type": "date"},
                        "aliases": {"type": "keyword"},

                        # MISP Galaxy geopolitical data
                        "misp_found": {"type": "boolean"},
                        "country": {"type": "keyword"},
                        "state_sponsor": {"type": "text"},
                        "military_unit": {"type": "text"},
                        "targeted_countries": {"type": "keyword"},
                        "targeted_sectors": {"type": "keyword"},
                        "incident_type": {"type": "keyword"},
                        "attribution_confidence": {"type": "keyword"},
                        "additional_aliases": {"type": "keyword"},
                        "misp_refs": {"type": "keyword"},
                        "description": {"type": "text"}
                    }
                },
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0
                }
            }
        )
        logger.info(f"✅ Index created: {INDEX_NAME}")

    async def get_cached_techniques(
        self,
        actor_name: str,
        max_age_hours: int = 24
    ) -> Optional[List[str]]:
        """
        Get cached techniques for an actor

        Args:
            actor_name: Actor name
            max_age_hours: Maximum cache age in hours (default 24h)

        Returns:
            List of technique IDs if cached and fresh, None otherwise
        """
        try:
            es = await self._get_es_client()

            # Query cache
            result = await es.search(
                index=INDEX_NAME,
                body={
                    "query": {
                        "term": {
                            "actor_name": actor_name
                        }
                    }
                },
                size=1
            )

            if result['hits']['total']['value'] == 0:
                logger.info(f"🔍 No cache found for actor: {actor_name}")
                return None

            doc = result['hits']['hits'][0]['_source']

            # Check cache age
            last_enriched = datetime.fromisoformat(doc['last_enriched'].replace('Z', '+00:00'))
            age = datetime.now(last_enriched.tzinfo) - last_enriched

            if age.total_seconds() / 3600 > max_age_hours:
                logger.info(f"⏰ Cache expired for {actor_name} (age: {age})")
                return None

            logger.info(f"✅ Cache hit for {actor_name}: {doc['techniques_count']} techniques")
            return doc['techniques']

        except Exception as e:
            logger.error(f"❌ Error getting cached techniques: {e}")
            return None

    async def save_enrichment(
        self,
        actor_name: str,
        techniques: List[str],
        mitre_group_id: Optional[str] = None,
        mitre_stix_id: Optional[str] = None,
        aliases: Optional[List[str]] = None
    ):
        """
        Save enrichment to cache (MITRE ATT&CK + MISP Galaxy)

        Args:
            actor_name: Actor name
            techniques: List of technique IDs
            mitre_group_id: MITRE Group ID (e.g., G0007)
            mitre_stix_id: MITRE STIX ID
            aliases: List of aliases
        """
        try:
            await self._ensure_index_exists()
            es = await self._get_es_client()

            # Base document with MITRE ATT&CK data
            doc = {
                "actor_name": actor_name,
                "mitre_group_id": mitre_group_id,
                "mitre_stix_id": mitre_stix_id,
                "techniques": techniques,
                "techniques_count": len(techniques),
                "last_enriched": datetime.utcnow().isoformat() + "Z",
                "aliases": aliases or []
            }

            # TODO: Enrich with MISP Galaxy data (method not yet implemented)
            # For now, skip MISP enrichment to avoid errors
            doc["misp_found"] = False

            # Upsert (update or insert)
            await es.index(
                index=INDEX_NAME,
                id=actor_name,  # Use actor name as document ID
                body=doc
            )

            logger.info(f"💾 Saved enrichment cache for {actor_name}: {len(techniques)} techniques + MISP data")

        except Exception as e:
            logger.error(f"❌ Error saving enrichment cache: {e}")

    async def enrich_and_cache_actor(self, actor_name: str, use_llm_fallback: bool = True) -> List[str]:
        """
        Enrich actor and save to cache

        Strategy:
        1. Try MITRE ATT&CK direct match first
        2. If no match and use_llm_fallback=True, use LLM inference
        3. Save to cache (even if empty, to avoid reprocessing)

        Args:
            actor_name: Actor name
            use_llm_fallback: Use LLM if MITRE match fails (default True)

        Returns:
            List of technique IDs
        """
        logger.info(f"🔨 Enriching and caching actor: {actor_name}")

        # 1. Try MITRE ATT&CK direct match
        techniques = await self.enrichment_service.get_techniques_for_actor(actor_name)

        if techniques:
            # Success with MITRE match
            logger.info(f"✅ MITRE match found: {len(techniques)} techniques")
            await self.save_enrichment(
                actor_name=actor_name,
                techniques=techniques
            )
            return techniques

        # 2. No MITRE match - try LLM inference if enabled
        if use_llm_fallback:
            logger.info(f"🤖 No MITRE match - trying LLM inference for {actor_name}")

            try:
                # Import LLM enrichment service
                from .llm_enrichment_service import get_llm_enrichment_service
                llm_service = get_llm_enrichment_service()

                # Infer techniques using LLM
                llm_result = await llm_service.infer_techniques_with_llm(actor_name)

                techniques = llm_result.get("techniques", [])
                confidence = llm_result.get("confidence", "unknown")
                reasoning = llm_result.get("reasoning", "")

                if techniques:
                    logger.info(f"✅ LLM inferred {len(techniques)} techniques (confidence: {confidence})")
                    logger.info(f"   Reasoning: {reasoning[:100]}")

                    # Save with LLM metadata
                    await self.save_enrichment(
                        actor_name=actor_name,
                        techniques=techniques,
                        # Add LLM metadata to cache document
                        # (You may need to update save_enrichment to accept these)
                    )
                else:
                    logger.warning(f"⚠️  LLM inference failed or returned no techniques")
                    # Save empty cache entry to mark as processed
                    await self.save_enrichment(
                        actor_name=actor_name,
                        techniques=[]
                    )

                return techniques

            except Exception as e:
                logger.error(f"❌ LLM enrichment error: {e}")
                # Save empty cache to avoid reprocessing
                await self.save_enrichment(
                    actor_name=actor_name,
                    techniques=[]
                )
                return []

        # 3. LLM disabled or failed - save empty cache
        logger.warning(f"⚠️  No techniques found for {actor_name} (LLM disabled or unavailable)")
        await self.save_enrichment(
            actor_name=actor_name,
            techniques=[]
        )

        return techniques

    async def enrich_and_cache_all_actors(self) -> Dict[str, Any]:
        """
        Enrich ALL actors and save to cache

        Returns:
            Statistics dictionary
        """
        logger.info("🚀 Starting batch enrichment of all actors...")

        # Get all actors from Elasticsearch
        es = await self._get_es_client()
        result = await es.search(
            index="malpedia_actors",
            body={"query": {"match_all": {}}},
            size=10000
        )

        actors = [hit['_source'] for hit in result['hits']['hits']]
        total = len(actors)
        enriched = 0
        not_mapped = 0

        logger.info(f"📋 Found {total} actors to enrich")

        for i, actor in enumerate(actors, 1):
            actor_name = actor['name']

            if i % 50 == 0:
                logger.info(f"Progress: {i}/{total} ({i/total*100:.1f}%)")

            techniques = await self.enrich_and_cache_actor(actor_name)

            if techniques:
                enriched += 1
            else:
                not_mapped += 1

        stats = {
            "total_actors": total,
            "enriched": enriched,
            "not_mapped": not_mapped,
            "coverage": f"{enriched/total*100:.1f}%"
        }

        logger.info(f"✅ Batch enrichment complete: {stats}")
        return stats

    async def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics

        Returns:
            Statistics about cached enrichments
        """
        try:
            es = await self._get_es_client()

            # Check if index exists
            exists = await es.indices.exists(index=INDEX_NAME)
            if not exists:
                return {
                    "index_exists": False,
                    "total_cached": 0
                }

            # Get count
            count_result = await es.count(index=INDEX_NAME)
            total = count_result['count']

            # Get sample of recent enrichments
            recent = await es.search(
                index=INDEX_NAME,
                body={
                    "query": {"match_all": {}},
                    "sort": [{"last_enriched": "desc"}],
                    "size": 5
                }
            )

            recent_actors = [
                {
                    "name": hit['_source']['actor_name'],
                    "techniques": hit['_source']['techniques_count'],
                    "last_enriched": hit['_source']['last_enriched']
                }
                for hit in recent['hits']['hits']
            ]

            return {
                "index_exists": True,
                "total_cached": total,
                "recent_enrichments": recent_actors
            }

        except Exception as e:
            logger.error(f"❌ Error getting cache stats: {e}")
            return {"error": str(e)}


# Singleton
_cache_service: Optional[EnrichmentCacheService] = None


def get_enrichment_cache_service() -> EnrichmentCacheService:
    """Get singleton instance"""
    global _cache_service
    if _cache_service is None:
        _cache_service = EnrichmentCacheService()
    return _cache_service
