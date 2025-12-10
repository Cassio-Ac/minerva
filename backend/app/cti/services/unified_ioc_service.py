"""
Unified IOC Elasticsearch Service

Centralized IOC storage with multi-source correlation and confidence scoring.
Follows pattern from yara_elasticsearch_service.py

Memory-optimized for large migrations (100k+ IOCs).
"""

import logging
import gc
import asyncio
from typing import List, Dict, Any, Optional, AsyncGenerator
from datetime import datetime, timezone

from elasticsearch import AsyncElasticsearch

from app.db.elasticsearch import get_es_client
from .unified_ioc_normalizer import IOCNormalizer
from .unified_ioc_confidence import IOCConfidenceScorer
from .unified_ioc_correlation import IOCCorrelationEngine
from .unified_ioc_adapters import get_adapter, BaseIOCAdapter

logger = logging.getLogger(__name__)

UNIFIED_IOC_INDEX = "unified_iocs"

# Elasticsearch mapping for unified IOCs
UNIFIED_IOC_MAPPING = {
    "settings": {
        "number_of_shards": 3,
        "number_of_replicas": 1,
        "refresh_interval": "5s",
        "analysis": {
            "analyzer": {
                "ioc_analyzer": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "filter": ["lowercase", "asciifolding"]
                }
            },
            "normalizer": {
                "lowercase_normalizer": {
                    "type": "custom",
                    "filter": ["lowercase"]
                }
            }
        }
    },
    "mappings": {
        "properties": {
            # Identification
            "ioc_id": {"type": "keyword"},
            "ioc_value": {
                "type": "text",
                "analyzer": "ioc_analyzer",
                "fields": {
                    "keyword": {
                        "type": "keyword",
                        "normalizer": "lowercase_normalizer"
                    },
                    "raw": {"type": "keyword"}
                }
            },
            "ioc_value_hash": {"type": "keyword"},
            "ioc_type": {"type": "keyword"},
            "ioc_subtype": {"type": "keyword"},

            # Sources (nested for independent querying)
            "sources": {
                "type": "nested",
                "properties": {
                    "source_name": {"type": "keyword"},
                    "source_id": {"type": "keyword"},
                    "source_ref": {"type": "keyword"},
                    "source_confidence": {"type": "float"},
                    "source_reputation": {"type": "float"},
                    "first_seen_by_source": {"type": "date"},
                    "last_seen_by_source": {"type": "date"},
                    "context": {"type": "text"},
                    "raw_data": {"type": "object", "enabled": False}
                }
            },
            "source_count": {"type": "integer"},
            "source_names": {"type": "keyword"},

            # Confidence
            "confidence_score": {"type": "float"},
            "confidence_level": {"type": "keyword"},
            "confidence_breakdown": {
                "type": "object",
                "properties": {
                    "base_score": {"type": "float"},
                    "multi_source_boost": {"type": "float"},
                    "reputation_boost": {"type": "float"},
                    "time_decay": {"type": "float"},
                    "final_score": {"type": "float"}
                }
            },

            # Attribution
            "threat_type": {"type": "keyword"},
            "malware_family": {
                "type": "text",
                "analyzer": "ioc_analyzer",
                "fields": {"keyword": {"type": "keyword"}}
            },
            "threat_actor": {
                "type": "text",
                "analyzer": "ioc_analyzer",
                "fields": {"keyword": {"type": "keyword"}}
            },
            "campaigns": {"type": "keyword"},

            # Classification
            "tags": {"type": "keyword"},
            "mitre_attack": {"type": "keyword"},
            "tlp": {"type": "keyword"},

            # Targeting
            "targeted_countries": {"type": "keyword"},
            "targeted_industries": {"type": "keyword"},
            "references": {"type": "keyword"},

            # Timestamps
            "first_seen": {"type": "date"},
            "last_seen": {"type": "date"},
            "last_updated": {"type": "date"},
            "created_at": {"type": "date"},

            # Status
            "is_active": {"type": "boolean"},
            "is_false_positive": {"type": "boolean"},
            "to_ids": {"type": "boolean"},

            # Enrichment
            "enrichment": {
                "type": "object",
                "properties": {
                    "enriched_at": {"type": "date"},
                    "llm_analysis": {"type": "text"},
                    "detection_methods": {"type": "keyword"},
                    "severity": {"type": "keyword"}
                }
            },

            # Geo (for IP IOCs)
            "geo": {
                "type": "object",
                "properties": {
                    "country_code": {"type": "keyword"},
                    "country_name": {"type": "keyword"},
                    "city": {"type": "keyword"},
                    "asn": {"type": "keyword"},
                    "org": {"type": "keyword"}
                }
            }
        }
    }
}


class UnifiedIOCService:
    """Service for unified IOC management in Elasticsearch"""

    def __init__(self, es_client: Optional[AsyncElasticsearch] = None):
        self.es = es_client
        self._owns_client = False
        self.normalizer = IOCNormalizer()
        self.scorer = IOCConfidenceScorer()
        self.correlation_engine = IOCCorrelationEngine()

    async def _get_client(self) -> AsyncElasticsearch:
        """Get or create ES client"""
        if self.es is None:
            self.es = await get_es_client()
            self._owns_client = True
        return self.es

    async def close(self):
        """Close ES client if owned"""
        if self._owns_client and self.es:
            await self.es.close()
            self.es = None

    # ============ INDEX MANAGEMENT ============

    async def ensure_index(self) -> bool:
        """Create unified_iocs index if not exists"""
        es = await self._get_client()

        try:
            exists = await es.indices.exists(index=UNIFIED_IOC_INDEX)

            if not exists:
                await es.indices.create(index=UNIFIED_IOC_INDEX, body=UNIFIED_IOC_MAPPING)
                logger.info(f"Created index: {UNIFIED_IOC_INDEX}")
                return True

            return False
        except Exception as e:
            # Index already exists or other error
            if "resource_already_exists_exception" in str(e):
                logger.debug(f"Index {UNIFIED_IOC_INDEX} already exists")
                return False
            raise

    async def delete_index(self) -> bool:
        """Delete unified_iocs index (use with caution)"""
        es = await self._get_client()
        exists = await es.indices.exists(index=UNIFIED_IOC_INDEX)

        if exists:
            await es.indices.delete(index=UNIFIED_IOC_INDEX)
            logger.warning(f"Deleted index: {UNIFIED_IOC_INDEX}")
            return True

        return False

    async def get_index_stats(self) -> Dict[str, Any]:
        """Get index statistics"""
        es = await self._get_client()

        try:
            stats = await es.indices.stats(index=UNIFIED_IOC_INDEX)
            index_stats = stats.get("indices", {}).get(UNIFIED_IOC_INDEX, {})
            primaries = index_stats.get("primaries", {})

            return {
                "index": UNIFIED_IOC_INDEX,
                "docs_count": primaries.get("docs", {}).get("count", 0),
                "docs_deleted": primaries.get("docs", {}).get("deleted", 0),
                "store_size_bytes": primaries.get("store", {}).get("size_in_bytes", 0),
                "store_size_human": self._format_bytes(
                    primaries.get("store", {}).get("size_in_bytes", 0)
                )
            }
        except Exception as e:
            logger.error(f"Error getting index stats: {e}")
            return {"error": str(e)}

    # ============ INGESTION ============

    async def ingest_ioc(
        self,
        ioc_value: str,
        ioc_type: str,
        source_name: str,
        source_data: Dict[str, Any],
        update_if_exists: bool = True
    ) -> Dict[str, Any]:
        """
        Ingest a single IOC with real-time correlation.

        If IOC exists: Updates sources list and recalculates confidence.
        If IOC new: Creates document with initial confidence.

        Args:
            ioc_value: Raw IOC value
            ioc_type: IOC type (ip, domain, url, hash, email)
            source_name: Source name (misp, otx, etc.)
            source_data: Source data in unified format
            update_if_exists: Whether to update existing IOC

        Returns:
            Result with action taken and document ID
        """
        es = await self._get_client()

        # 1. Normalize IOC value
        normalized, value_hash = self.normalizer.normalize_and_hash(ioc_value, ioc_type)

        # 2. Check if IOC already exists
        existing = await self._get_by_hash(value_hash)

        if existing and update_if_exists:
            # 3a. Correlate with existing data
            updated_doc = self.correlation_engine.correlate(
                existing_doc=existing,
                new_source=source_data,
                source_name=source_name
            )

            # 4. Recalculate confidence
            confidence = self.scorer.calculate(
                sources=updated_doc["sources"],
                last_seen=updated_doc.get("last_seen")
            )
            updated_doc.update(confidence)

            # 5. Update document (refresh=False for performance)
            await es.update(
                index=UNIFIED_IOC_INDEX,
                id=value_hash,
                body={"doc": updated_doc},
                refresh=False
            )

            return {
                "action": "updated",
                "id": value_hash,
                "source_count": updated_doc["source_count"],
                "confidence_score": confidence["confidence_score"],
                "confidence_level": confidence["confidence_level"]
            }

        else:
            # 3b. Create new IOC document
            new_doc = self.correlation_engine.create_new_document(
                normalized_value=normalized,
                value_hash=value_hash,
                ioc_type=ioc_type,
                source_name=source_name,
                source_data=source_data
            )

            # 4. Calculate initial confidence
            confidence = self.scorer.calculate(
                sources=new_doc["sources"],
                last_seen=new_doc.get("last_seen")
            )
            new_doc.update(confidence)

            # 5. Index new document (refresh=False for performance)
            await es.index(
                index=UNIFIED_IOC_INDEX,
                id=value_hash,
                body=new_doc,
                refresh=False
            )

            return {
                "action": "created",
                "id": value_hash,
                "source_count": 1,
                "confidence_score": confidence["confidence_score"],
                "confidence_level": confidence["confidence_level"]
            }

    async def ingest_batch(
        self,
        iocs: List[Dict[str, Any]],
        source_name: str,
        batch_size: int = 250,
        refresh_every: int = 10
    ) -> Dict[str, int]:
        """
        Bulk ingest IOCs from a source (memory-optimized).

        Strategy:
        1. Normalize all IOCs
        2. Query existing by hash (mget)
        3. Separate into updates vs creates
        4. Bulk update/create
        5. Periodic refresh and GC

        Args:
            iocs: List of IOCs in unified format (with 'value' and 'type' keys)
            source_name: Source name
            batch_size: Documents per bulk request (default 250 for memory safety)
            refresh_every: Refresh index every N batches (default 10)

        Returns:
            Stats with created, updated, errors counts
        """
        es = await self._get_client()

        # Get adapter for this source
        adapter = get_adapter(source_name)

        stats = {"created": 0, "updated": 0, "errors": 0, "total": len(iocs)}
        batch_count = 0

        for i in range(0, len(iocs), batch_size):
            batch = iocs[i:i + batch_size]
            batch_count += 1

            # Normalize and compute hashes
            normalized_batch = []
            for ioc in batch:
                try:
                    # Transform through adapter if not already transformed
                    if "value" not in ioc and "ioc_value" in ioc:
                        source_data = adapter.transform(ioc)
                    else:
                        source_data = ioc

                    value = source_data.get("value")
                    ioc_type = source_data.get("type", "other")

                    if not value:
                        stats["errors"] += 1
                        continue

                    normalized, hash_val = self.normalizer.normalize_and_hash(value, ioc_type)

                    normalized_batch.append({
                        "hash": hash_val,
                        "normalized": normalized,
                        "type": ioc_type,
                        "source_data": source_data
                    })
                except Exception as e:
                    logger.warning(f"Normalization failed: {e}")
                    stats["errors"] += 1

            if not normalized_batch:
                continue

            # Fetch existing documents
            hashes = [nb["hash"] for nb in normalized_batch]
            existing_docs = await self._mget_by_hashes(hashes)

            # Build bulk operations
            bulk_ops = []

            for nb in normalized_batch:
                existing = existing_docs.get(nb["hash"])

                try:
                    if existing:
                        # Update existing
                        updated = self.correlation_engine.correlate(
                            existing_doc=existing,
                            new_source=nb["source_data"],
                            source_name=source_name
                        )
                        confidence = self.scorer.calculate(
                            sources=updated["sources"],
                            last_seen=updated.get("last_seen")
                        )
                        updated.update(confidence)

                        bulk_ops.append({"update": {"_index": UNIFIED_IOC_INDEX, "_id": nb["hash"]}})
                        bulk_ops.append({"doc": updated})
                        stats["updated"] += 1
                    else:
                        # Create new
                        new_doc = self.correlation_engine.create_new_document(
                            normalized_value=nb["normalized"],
                            value_hash=nb["hash"],
                            ioc_type=nb["type"],
                            source_name=source_name,
                            source_data=nb["source_data"]
                        )
                        confidence = self.scorer.calculate(
                            sources=new_doc["sources"],
                            last_seen=new_doc.get("last_seen")
                        )
                        new_doc.update(confidence)

                        bulk_ops.append({"index": {"_index": UNIFIED_IOC_INDEX, "_id": nb["hash"]}})
                        bulk_ops.append(new_doc)
                        stats["created"] += 1
                except Exception as e:
                    logger.warning(f"Error processing IOC: {e}")
                    stats["errors"] += 1

            # Execute bulk
            if bulk_ops:
                try:
                    response = await es.bulk(body=bulk_ops, refresh=False)
                    if response.get("errors"):
                        for item in response.get("items", []):
                            op = item.get("index") or item.get("update", {})
                            if "error" in op:
                                stats["errors"] += 1
                                logger.warning(f"Bulk error: {op.get('error')}")
                except Exception as e:
                    logger.error(f"Bulk operation failed: {e}")
                    stats["errors"] += len(bulk_ops) // 2

            logger.info(f"Batch {batch_count}: processed {len(normalized_batch)} IOCs")

            # Periodic refresh and memory cleanup
            if batch_count % refresh_every == 0:
                await es.indices.refresh(index=UNIFIED_IOC_INDEX)
                gc.collect()
                # Small delay to let ES process segment merges
                await asyncio.sleep(0.1)

            # Clear references
            del normalized_batch, bulk_ops, existing_docs, hashes
            batch = None

        # Final refresh
        await es.indices.refresh(index=UNIFIED_IOC_INDEX)
        gc.collect()

        return stats

    # ============ SEARCH ============

    async def search_iocs(
        self,
        query: Optional[str] = None,
        ioc_type: Optional[str] = None,
        source_name: Optional[str] = None,
        min_confidence: Optional[float] = None,
        confidence_level: Optional[str] = None,
        malware_family: Optional[str] = None,
        threat_actor: Optional[str] = None,
        tags: Optional[List[str]] = None,
        mitre_attack: Optional[List[str]] = None,
        min_source_count: Optional[int] = None,
        tlp: Optional[str] = None,
        is_active: bool = True,
        page: int = 1,
        page_size: int = 50,
        sort_by: str = "confidence_score",
        sort_order: str = "desc"
    ) -> Dict[str, Any]:
        """
        Search unified IOCs with filters.

        Args:
            query: Full-text search query
            ioc_type: Filter by type (ip, domain, url, hash, email)
            source_name: Filter by source
            min_confidence: Minimum confidence score
            confidence_level: Filter by level (critical, high, medium, low)
            malware_family: Filter by malware family
            threat_actor: Filter by threat actor
            tags: Filter by tags (any match)
            mitre_attack: Filter by MITRE ATT&CK techniques
            min_source_count: Minimum number of sources
            tlp: Filter by TLP level
            is_active: Filter active/inactive
            page: Page number
            page_size: Results per page
            sort_by: Sort field
            sort_order: asc or desc

        Returns:
            Search results with pagination
        """
        es = await self._get_client()

        must_clauses = []
        filter_clauses = []

        # Full-text search
        if query:
            must_clauses.append({
                "multi_match": {
                    "query": query,
                    "fields": [
                        "ioc_value^3",
                        "ioc_value.keyword^4",
                        "malware_family^2",
                        "threat_actor^2",
                        "tags",
                        "mitre_attack"
                    ],
                    "type": "best_fields",
                    "fuzziness": "AUTO"
                }
            })

        # Filters
        if is_active is not None:
            filter_clauses.append({"term": {"is_active": is_active}})
        if ioc_type:
            filter_clauses.append({"term": {"ioc_type": ioc_type}})
        if source_name:
            filter_clauses.append({"term": {"source_names": source_name}})
        if min_confidence is not None:
            filter_clauses.append({"range": {"confidence_score": {"gte": min_confidence}}})
        if confidence_level:
            filter_clauses.append({"term": {"confidence_level": confidence_level}})
        if malware_family:
            filter_clauses.append({"match": {"malware_family": malware_family}})
        if threat_actor:
            filter_clauses.append({"match": {"threat_actor": threat_actor}})
        if tags:
            filter_clauses.append({"terms": {"tags": tags}})
        if mitre_attack:
            filter_clauses.append({"terms": {"mitre_attack": mitre_attack}})
        if min_source_count:
            filter_clauses.append({"range": {"source_count": {"gte": min_source_count}}})
        if tlp:
            filter_clauses.append({"term": {"tlp": tlp}})

        # Build query
        if must_clauses or filter_clauses:
            query_body = {
                "bool": {
                    "must": must_clauses if must_clauses else [{"match_all": {}}],
                    "filter": filter_clauses
                }
            }
        else:
            query_body = {"match_all": {}}

        # Build sort
        sort = [{sort_by: sort_order}]
        if sort_by != "last_seen":
            sort.append({"last_seen": "desc"})

        body = {
            "query": query_body,
            "from": (page - 1) * page_size,
            "size": page_size,
            "sort": sort
        }

        result = await es.search(index=UNIFIED_IOC_INDEX, body=body)

        hits = result.get("hits", {})
        return {
            "total": hits.get("total", {}).get("value", 0),
            "page": page,
            "page_size": page_size,
            "iocs": [
                {**hit["_source"], "id": hit["_id"]}
                for hit in hits.get("hits", [])
            ]
        }

    async def lookup_ioc(self, ioc_value: str) -> Optional[Dict[str, Any]]:
        """
        Quick lookup by exact IOC value.

        Args:
            ioc_value: IOC value to lookup

        Returns:
            Full IOC document or None if not found
        """
        normalized, value_hash = self.normalizer.normalize_and_hash(ioc_value)
        return await self._get_by_hash(value_hash)

    async def get_by_id(self, ioc_id: str) -> Optional[Dict[str, Any]]:
        """Get IOC by document ID (hash)"""
        return await self._get_by_hash(ioc_id)

    # ============ STATISTICS ============

    async def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive IOC statistics"""
        es = await self._get_client()

        body = {
            "size": 0,
            "track_total_hits": True,  # Get exact count, not limited to 10000
            "aggs": {
                "total_active": {"filter": {"term": {"is_active": True}}},
                "by_type": {"terms": {"field": "ioc_type", "size": 20}},
                "by_source": {"terms": {"field": "source_names", "size": 50}},
                "by_confidence_level": {"terms": {"field": "confidence_level", "size": 10}},
                "by_malware_family": {"terms": {"field": "malware_family.keyword", "size": 50}},
                "by_threat_actor": {"terms": {"field": "threat_actor.keyword", "size": 50}},
                "by_tlp": {"terms": {"field": "tlp", "size": 10}},
                "avg_confidence": {"avg": {"field": "confidence_score"}},
                "avg_sources": {"avg": {"field": "source_count"}},
                "multi_source_iocs": {"filter": {"range": {"source_count": {"gte": 2}}}},
                "high_confidence_iocs": {"filter": {"range": {"confidence_score": {"gte": 70}}}},
                "critical_iocs": {"filter": {"term": {"confidence_level": "critical"}}},
                "recent_24h": {
                    "filter": {"range": {"last_seen": {"gte": "now-24h"}}}
                },
                "recent_7d": {
                    "filter": {"range": {"last_seen": {"gte": "now-7d"}}}
                }
            }
        }

        result = await es.search(index=UNIFIED_IOC_INDEX, body=body)
        aggs = result.get("aggregations", {})
        total = result.get("hits", {}).get("total", {}).get("value", 0)

        return {
            "total_iocs": total,
            "active_iocs": aggs.get("total_active", {}).get("doc_count", 0),
            "by_type": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_type", {}).get("buckets", [])
            },
            "by_source": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_source", {}).get("buckets", [])
            },
            "by_confidence_level": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_confidence_level", {}).get("buckets", [])
            },
            "by_malware_family": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_malware_family", {}).get("buckets", [])
            },
            "by_threat_actor": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_threat_actor", {}).get("buckets", [])
            },
            "by_tlp": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_tlp", {}).get("buckets", [])
            },
            "avg_confidence": round(aggs.get("avg_confidence", {}).get("value", 0) or 0, 2),
            "avg_sources_per_ioc": round(aggs.get("avg_sources", {}).get("value", 0) or 0, 2),
            "multi_source_iocs": aggs.get("multi_source_iocs", {}).get("doc_count", 0),
            "high_confidence_iocs": aggs.get("high_confidence_iocs", {}).get("doc_count", 0),
            "critical_iocs": aggs.get("critical_iocs", {}).get("doc_count", 0),
            "recent_24h": aggs.get("recent_24h", {}).get("doc_count", 0),
            "recent_7d": aggs.get("recent_7d", {}).get("doc_count", 0)
        }

    # ============ HELPERS ============

    async def _get_by_hash(self, value_hash: str) -> Optional[Dict[str, Any]]:
        """Get document by hash ID"""
        es = await self._get_client()
        try:
            result = await es.get(index=UNIFIED_IOC_INDEX, id=value_hash)
            if result.get("found"):
                return {"id": result["_id"], **result["_source"]}
        except Exception:
            pass
        return None

    async def _mget_by_hashes(self, hashes: List[str]) -> Dict[str, Dict]:
        """Bulk get documents by hashes"""
        es = await self._get_client()

        if not hashes:
            return {}

        try:
            result = await es.mget(index=UNIFIED_IOC_INDEX, body={"ids": hashes})

            found = {}
            for doc in result.get("docs", []):
                if doc.get("found"):
                    found[doc["_id"]] = {"id": doc["_id"], **doc["_source"]}
            return found
        except Exception as e:
            logger.error(f"mget failed: {e}")
            return {}

    def _format_bytes(self, size_bytes: int) -> str:
        """Format bytes to human readable"""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} PB"


# ============ MIGRATION SERVICE ============

class UnifiedIOCMigration:
    """Migration service for existing IOC data (memory-optimized)"""

    # Default settings for memory-safe migration
    DEFAULT_BATCH_SIZE = 250
    DEFAULT_REFRESH_EVERY = 10
    DEFAULT_SLEEP_BETWEEN_BATCHES = 0.05  # 50ms

    def __init__(self, db_session):
        self.db = db_session
        self.service = UnifiedIOCService()

    async def migrate_misp_iocs(
        self,
        batch_size: Optional[int] = None,
        start_offset: int = 0,
        max_records: Optional[int] = None
    ) -> Dict[str, int]:
        """
        Migrate MISP IOCs from PostgreSQL to Elasticsearch (memory-optimized).

        Args:
            batch_size: Records per batch (default 250 for memory safety)
            start_offset: Resume from this offset (for checkpoint recovery)
            max_records: Stop after this many records (None = all)

        Returns:
            Stats with created, updated, errors, last_offset
        """
        from sqlalchemy import select, func
        from app.cti.models.misp_ioc import MISPIoC
        from .unified_ioc_adapters import MISPIOCAdapter

        # Use default if not specified
        if batch_size is None:
            batch_size = self.DEFAULT_BATCH_SIZE

        adapter = MISPIOCAdapter()

        # Get total count
        count_stmt = select(func.count(MISPIoC.id))
        total = await self.db.scalar(count_stmt)

        if max_records:
            total = min(total, start_offset + max_records)

        logger.info(f"Migrating MISP IOCs: {start_offset} to {total} ({total - start_offset:,} records)")

        stats = {
            "total": total - start_offset,
            "created": 0,
            "updated": 0,
            "errors": 0,
            "last_offset": start_offset
        }
        offset = start_offset
        batch_num = 0

        while offset < total:
            batch_num += 1

            # Query with streaming-friendly approach
            stmt = select(MISPIoC).offset(offset).limit(batch_size)
            result = await self.db.execute(stmt)
            iocs = result.scalars().all()

            if not iocs:
                break

            # Transform to unified format
            transformed = []
            for ioc in iocs:
                try:
                    data = {
                        "id": str(ioc.id),
                        "feed_id": str(ioc.feed_id),
                        "ioc_value": ioc.ioc_value,
                        "ioc_type": ioc.ioc_type,
                        "ioc_subtype": ioc.ioc_subtype,
                        "context": ioc.context,
                        "malware_family": ioc.malware_family,
                        "threat_actor": ioc.threat_actor,
                        "tags": ioc.tags or [],
                        "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                        "tlp": ioc.tlp,
                        "confidence": ioc.confidence,
                        "to_ids": ioc.to_ids
                    }
                    unified = adapter.transform(data)
                    transformed.append(unified)
                except Exception as e:
                    logger.warning(f"Failed to transform MISP IOC {ioc.id}: {e}")
                    stats["errors"] += 1

            # Clear SQLAlchemy objects from memory
            del iocs

            # Ingest batch
            if transformed:
                batch_result = await self.service.ingest_batch(
                    iocs=transformed,
                    source_name="misp",
                    batch_size=batch_size,
                    refresh_every=self.DEFAULT_REFRESH_EVERY
                )
                stats["created"] += batch_result["created"]
                stats["updated"] += batch_result["updated"]
                stats["errors"] += batch_result["errors"]

            # Clear transformed from memory
            del transformed

            offset += batch_size
            stats["last_offset"] = offset

            # Progress logging
            progress_pct = ((offset - start_offset) / (total - start_offset)) * 100
            logger.info(f"MISP progress: {offset:,}/{total:,} ({progress_pct:.1f}%)")

            # Memory cleanup every 10 batches
            if batch_num % 10 == 0:
                gc.collect()
                await asyncio.sleep(self.DEFAULT_SLEEP_BETWEEN_BATCHES)

        gc.collect()
        return stats

    async def migrate_otx_indicators(
        self,
        batch_size: Optional[int] = None,
        start_offset: int = 0,
        max_records: Optional[int] = None
    ) -> Dict[str, int]:
        """
        Migrate OTX Pulse Indicators from PostgreSQL to Elasticsearch (memory-optimized).

        Note: OTX requires JOIN with pulses table, so uses smaller batches.

        Args:
            batch_size: Records per batch (default 250, smaller due to JOIN)
            start_offset: Resume from this offset (for checkpoint recovery)
            max_records: Stop after this many records (None = all)

        Returns:
            Stats with created, updated, errors, last_offset
        """
        from sqlalchemy import select, func
        from app.cti.models.otx_pulse import OTXPulseIndicator, OTXPulse
        from .unified_ioc_adapters import OTXIOCAdapter

        # Use default if not specified
        if batch_size is None:
            batch_size = self.DEFAULT_BATCH_SIZE

        adapter = OTXIOCAdapter()

        # Get total count
        count_stmt = select(func.count(OTXPulseIndicator.id))
        total = await self.db.scalar(count_stmt)

        if max_records:
            total = min(total, start_offset + max_records)

        logger.info(f"Migrating OTX indicators: {start_offset} to {total} ({total - start_offset:,} records)")

        stats = {
            "total": total - start_offset,
            "created": 0,
            "updated": 0,
            "errors": 0,
            "last_offset": start_offset
        }
        offset = start_offset
        batch_num = 0

        # Use smaller batch for JOIN queries (more memory intensive)
        effective_batch_size = min(batch_size, 200)

        while offset < total:
            batch_num += 1

            stmt = (
                select(OTXPulseIndicator, OTXPulse)
                .join(OTXPulse, OTXPulseIndicator.pulse_id == OTXPulse.id)
                .offset(offset)
                .limit(effective_batch_size)
            )
            result = await self.db.execute(stmt)
            rows = result.all()

            if not rows:
                break

            # Transform to unified format
            transformed = []
            for indicator, pulse in rows:
                try:
                    data = {
                        "id": str(indicator.id),
                        "pulse_id": pulse.pulse_id,
                        "indicator": indicator.indicator,
                        "type": indicator.type,
                        "title": indicator.title,
                        "description": indicator.description,
                        "adversary": pulse.adversary,
                        "tags": pulse.tags or [],
                        "attack_ids": pulse.attack_ids or [],
                        "references": pulse.references or [],
                        "targeted_countries": pulse.targeted_countries or [],
                        "industries": pulse.industries or [],
                        "tlp": pulse.tlp or "white",
                        "created": pulse.created.isoformat() if pulse.created else None,
                        "otx_enrichment": indicator.otx_enrichment
                    }
                    unified = adapter.transform(data)
                    transformed.append(unified)
                except Exception as e:
                    logger.warning(f"Failed to transform OTX indicator {indicator.id}: {e}")
                    stats["errors"] += 1

            # Clear SQLAlchemy objects from memory
            del rows

            # Ingest batch
            if transformed:
                batch_result = await self.service.ingest_batch(
                    iocs=transformed,
                    source_name="otx",
                    batch_size=effective_batch_size,
                    refresh_every=self.DEFAULT_REFRESH_EVERY
                )
                stats["created"] += batch_result["created"]
                stats["updated"] += batch_result["updated"]
                stats["errors"] += batch_result["errors"]

            # Clear transformed from memory
            del transformed

            offset += effective_batch_size
            stats["last_offset"] = offset

            # Progress logging
            progress_pct = ((offset - start_offset) / max(1, total - start_offset)) * 100
            logger.info(f"OTX progress: {offset:,}/{total:,} ({progress_pct:.1f}%)")

            # Memory cleanup every 5 batches (more aggressive due to JOINs)
            if batch_num % 5 == 0:
                gc.collect()
                await asyncio.sleep(self.DEFAULT_SLEEP_BETWEEN_BATCHES)

        gc.collect()
        return stats

    async def run_full_migration(
        self,
        misp_offset: int = 0,
        otx_offset: int = 0,
        skip_misp: bool = False,
        skip_otx: bool = False
    ) -> Dict[str, Any]:
        """
        Run complete migration from all sources (memory-optimized).

        Args:
            misp_offset: Resume MISP migration from this offset
            otx_offset: Resume OTX migration from this offset
            skip_misp: Skip MISP migration entirely
            skip_otx: Skip OTX migration entirely

        Returns:
            Results with stats and checkpoints for resuming
        """
        logger.info("Starting unified IOC migration (memory-optimized)...")
        logger.info(f"  MISP offset: {misp_offset}, skip: {skip_misp}")
        logger.info(f"  OTX offset: {otx_offset}, skip: {skip_otx}")

        # Ensure index exists
        await self.service.ensure_index()

        results = {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "misp": {"status": "skipped" if skip_misp else "pending"},
            "otx": {"status": "skipped" if skip_otx else "pending"}
        }

        # Migrate MISP (if not skipped)
        if not skip_misp:
            try:
                logger.info("=" * 50)
                logger.info("Starting MISP migration...")
                gc.collect()

                misp_stats = await self.migrate_misp_iocs(start_offset=misp_offset)
                results["misp"] = {"status": "completed", **misp_stats}

                logger.info(f"MISP completed: {misp_stats['created']} created, {misp_stats['updated']} updated")
                gc.collect()

                # Pause between sources to let ES recover
                await asyncio.sleep(1)

            except Exception as e:
                logger.error(f"MISP migration failed: {e}")
                results["misp"] = {
                    "status": "failed",
                    "error": str(e),
                    "last_offset": misp_offset  # For resuming
                }

        # Migrate OTX (if not skipped)
        if not skip_otx:
            try:
                logger.info("=" * 50)
                logger.info("Starting OTX migration...")
                gc.collect()

                otx_stats = await self.migrate_otx_indicators(start_offset=otx_offset)
                results["otx"] = {"status": "completed", **otx_stats}

                logger.info(f"OTX completed: {otx_stats['created']} created, {otx_stats['updated']} updated")
                gc.collect()

            except Exception as e:
                logger.error(f"OTX migration failed: {e}")
                results["otx"] = {
                    "status": "failed",
                    "error": str(e),
                    "last_offset": otx_offset  # For resuming
                }

        # Get final stats
        try:
            final_stats = await self.service.get_stats()
            results["final_stats"] = final_stats
        except Exception as e:
            logger.warning(f"Could not get final stats: {e}")
            results["final_stats"] = {"error": str(e)}

        results["completed_at"] = datetime.now(timezone.utc).isoformat()

        await self.service.close()

        # Log summary
        logger.info("=" * 50)
        logger.info("Migration Summary:")
        logger.info(f"  MISP: {results['misp'].get('status')}")
        logger.info(f"  OTX: {results['otx'].get('status')}")
        if "total_iocs" in results.get("final_stats", {}):
            logger.info(f"  Total IOCs: {results['final_stats']['total_iocs']:,}")

        return results

    async def get_migration_status(self) -> Dict[str, Any]:
        """Get current migration status for monitoring."""
        from sqlalchemy import select, func
        from app.cti.models.misp_ioc import MISPIoC
        from app.cti.models.otx_pulse import OTXPulseIndicator

        # Count sources
        misp_count = await self.db.scalar(select(func.count(MISPIoC.id)))
        otx_count = await self.db.scalar(select(func.count(OTXPulseIndicator.id)))

        # Get ES stats
        try:
            es_stats = await self.service.get_stats()
        except Exception:
            es_stats = {"total_iocs": 0, "by_source": {}}

        misp_migrated = es_stats.get("by_source", {}).get("misp", 0)
        otx_migrated = es_stats.get("by_source", {}).get("otx", 0)

        return {
            "sources": {
                "misp": {"total": misp_count, "migrated": misp_migrated, "remaining": misp_count - misp_migrated},
                "otx": {"total": otx_count, "migrated": otx_migrated, "remaining": otx_count - otx_migrated}
            },
            "unified_index": {
                "total": es_stats.get("total_iocs", 0),
                "by_source": es_stats.get("by_source", {}),
                "by_type": es_stats.get("by_type", {})
            },
            "progress": {
                "misp_pct": round((misp_migrated / max(1, misp_count)) * 100, 1),
                "otx_pct": round((otx_migrated / max(1, otx_count)) * 100, 1),
                "total_pct": round(((misp_migrated + otx_migrated) / max(1, misp_count + otx_count)) * 100, 1)
            }
        }
