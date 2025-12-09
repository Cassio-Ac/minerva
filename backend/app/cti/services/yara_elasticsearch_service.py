"""
YARA Elasticsearch Service

Unified YARA rules storage in Elasticsearch.
Combines rules from:
- Signature Base (Neo23x0)
- Malpedia (Fraunhofer)

All rules normalized to a common schema for unified search.
"""

import logging
import hashlib
from typing import List, Dict, Optional, Any
from datetime import datetime
from elasticsearch import AsyncElasticsearch
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.elasticsearch import get_es_client
from app.cti.models.yara_rule import YaraRule as YARARule

logger = logging.getLogger(__name__)

# Unified index name
YARA_INDEX = "yara_rules_unified"

# Index mapping for unified YARA rules
YARA_INDEX_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "analysis": {
            "analyzer": {
                "yara_analyzer": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "filter": ["lowercase", "asciifolding"]
                }
            }
        }
    },
    "mappings": {
        "properties": {
            "rule_id": {"type": "keyword"},
            "rule_name": {
                "type": "text",
                "analyzer": "yara_analyzer",
                "fields": {"keyword": {"type": "keyword"}}
            },
            "rule_hash": {"type": "keyword"},
            "source": {"type": "keyword"},  # signature_base, malpedia
            "source_file": {"type": "keyword"},
            "source_url": {"type": "keyword"},
            "category": {"type": "keyword"},
            "threat_name": {
                "type": "text",
                "analyzer": "yara_analyzer",
                "fields": {"keyword": {"type": "keyword"}}
            },
            "threat_actor": {
                "type": "text",
                "analyzer": "yara_analyzer",
                "fields": {"keyword": {"type": "keyword"}}
            },
            "malware_family": {
                "type": "text",
                "analyzer": "yara_analyzer",
                "fields": {"keyword": {"type": "keyword"}}
            },
            "malware_aliases": {"type": "keyword"},
            "rule_content": {"type": "text", "index": False},  # Store but don't index
            "description": {
                "type": "text",
                "analyzer": "yara_analyzer"
            },
            "author": {
                "type": "text",
                "fields": {"keyword": {"type": "keyword"}}
            },
            "references": {"type": "keyword"},
            "date": {"type": "keyword"},
            "version": {"type": "keyword"},
            "tags": {"type": "keyword"},
            "mitre_attack": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "strings_count": {"type": "integer"},
            "is_active": {"type": "boolean"},
            "synced_at": {"type": "date"},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"}
        }
    }
}


class YARAElasticsearchService:
    """Service for unified YARA rules in Elasticsearch"""

    def __init__(self, es_client: Optional[AsyncElasticsearch] = None):
        self.es = es_client
        self._owns_client = False

    async def _get_client(self) -> AsyncElasticsearch:
        if self.es is None:
            self.es = await get_es_client()
            self._owns_client = True
        return self.es

    async def close(self):
        if self._owns_client and self.es:
            await self.es.close()
            self.es = None

    async def ensure_index(self) -> bool:
        """Create the unified YARA index if it doesn't exist"""
        es = await self._get_client()

        try:
            exists = await es.indices.exists(index=YARA_INDEX)
            if not exists:
                await es.indices.create(index=YARA_INDEX, body=YARA_INDEX_MAPPING)
                logger.info(f"Created index: {YARA_INDEX}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error creating index: {e}")
            raise

    async def get_stats(self) -> Dict[str, Any]:
        """Get statistics about YARA rules"""
        es = await self._get_client()

        try:
            # Total count
            count_resp = await es.count(index=YARA_INDEX)
            total = count_resp.get("count", 0)

            # Aggregations
            aggs_query = {
                "size": 0,
                "aggs": {
                    "by_source": {
                        "terms": {"field": "source", "size": 10}
                    },
                    "by_category": {
                        "terms": {"field": "category", "size": 50}
                    },
                    "by_threat_actor": {
                        "terms": {"field": "threat_actor.keyword", "size": 50}
                    },
                    "by_malware_family": {
                        "terms": {"field": "malware_family.keyword", "size": 500}
                    },
                    "family_count": {
                        "cardinality": {"field": "malware_family.keyword"}
                    },
                    "active_count": {
                        "filter": {"term": {"is_active": True}}
                    }
                }
            }

            result = await es.search(index=YARA_INDEX, body=aggs_query)
            aggs = result.get("aggregations", {})

            return {
                "total_rules": total,
                "active_rules": aggs.get("active_count", {}).get("doc_count", 0),
                "by_source": {
                    b["key"]: b["doc_count"]
                    for b in aggs.get("by_source", {}).get("buckets", [])
                },
                "by_category": {
                    b["key"]: b["doc_count"]
                    for b in aggs.get("by_category", {}).get("buckets", [])
                },
                "by_threat_actor": {
                    b["key"]: b["doc_count"]
                    for b in aggs.get("by_threat_actor", {}).get("buckets", [])
                },
                "by_malware_family": {
                    b["key"]: b["doc_count"]
                    for b in aggs.get("by_malware_family", {}).get("buckets", [])
                },
                "total_families": aggs.get("family_count", {}).get("value", 0)
            }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {"total_rules": 0, "error": str(e)}

    async def search_rules(
        self,
        search: Optional[str] = None,
        source: Optional[str] = None,
        category: Optional[str] = None,
        threat_actor: Optional[str] = None,
        malware_family: Optional[str] = None,
        mitre_attack: Optional[str] = None,
        tags: Optional[List[str]] = None,
        page: int = 1,
        page_size: int = 20
    ) -> Dict[str, Any]:
        """Search YARA rules with filters"""
        es = await self._get_client()

        must_clauses = []
        filter_clauses = [{"term": {"is_active": True}}]

        # Full-text search
        if search:
            must_clauses.append({
                "multi_match": {
                    "query": search,
                    "fields": [
                        "rule_name^3",
                        "threat_name^2",
                        "threat_actor^2",
                        "malware_family^2",
                        "description",
                        "tags",
                        "author"
                    ],
                    "type": "best_fields",
                    "fuzziness": "AUTO"
                }
            })

        # Filters
        if source:
            filter_clauses.append({"term": {"source": source}})
        if category:
            filter_clauses.append({"term": {"category": category}})
        if threat_actor:
            filter_clauses.append({
                "bool": {
                    "should": [
                        {"match": {"threat_actor": threat_actor}},
                        {"match": {"malware_aliases": threat_actor}}
                    ]
                }
            })
        if malware_family:
            filter_clauses.append({
                "bool": {
                    "should": [
                        {"match": {"malware_family": malware_family}},
                        {"match": {"malware_aliases": malware_family}}
                    ]
                }
            })
        if mitre_attack:
            filter_clauses.append({"term": {"mitre_attack": mitre_attack}})
        if tags:
            filter_clauses.append({"terms": {"tags": tags}})

        query = {
            "bool": {
                "must": must_clauses if must_clauses else [{"match_all": {}}],
                "filter": filter_clauses
            }
        }

        # Calculate pagination
        from_offset = (page - 1) * page_size

        body = {
            "query": query,
            "from": from_offset,
            "size": page_size,
            "sort": [
                {"_score": "desc"},
                {"synced_at": "desc"}
            ],
            "_source": {
                "excludes": ["rule_content"]  # Exclude large content by default
            }
        }

        try:
            result = await es.search(index=YARA_INDEX, body=body)

            hits = result.get("hits", {})
            total = hits.get("total", {}).get("value", 0)

            rules = []
            for hit in hits.get("hits", []):
                rule = hit["_source"]
                rule["id"] = hit["_id"]
                rule["score"] = hit.get("_score")
                rules.append(rule)

            return {
                "total": total,
                "page": page,
                "page_size": page_size,
                "rules": rules
            }
        except Exception as e:
            logger.error(f"Error searching rules: {e}")
            return {"total": 0, "page": page, "page_size": page_size, "rules": [], "error": str(e)}

    async def get_rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific rule by ID including content"""
        es = await self._get_client()

        try:
            result = await es.get(index=YARA_INDEX, id=rule_id)
            if result.get("found"):
                rule = result["_source"]
                rule["id"] = result["_id"]
                return rule
            return None
        except Exception as e:
            logger.error(f"Error getting rule {rule_id}: {e}")
            return None

    async def get_categories(self) -> List[Dict[str, Any]]:
        """Get all categories with counts"""
        es = await self._get_client()

        try:
            result = await es.search(index=YARA_INDEX, body={
                "size": 0,
                "aggs": {
                    "categories": {
                        "terms": {"field": "category", "size": 100}
                    }
                }
            })

            return [
                {"category": b["key"], "count": b["doc_count"]}
                for b in result.get("aggregations", {}).get("categories", {}).get("buckets", [])
            ]
        except Exception as e:
            logger.error(f"Error getting categories: {e}")
            return []

    async def get_threat_actors(self) -> List[Dict[str, Any]]:
        """Get all threat actors with counts"""
        es = await self._get_client()

        try:
            result = await es.search(index=YARA_INDEX, body={
                "size": 0,
                "aggs": {
                    "actors": {
                        "terms": {"field": "threat_actor.keyword", "size": 200}
                    }
                }
            })

            return [
                {"threat_actor": b["key"], "count": b["doc_count"]}
                for b in result.get("aggregations", {}).get("actors", {}).get("buckets", [])
            ]
        except Exception as e:
            logger.error(f"Error getting threat actors: {e}")
            return []

    async def get_malware_families(self) -> List[Dict[str, Any]]:
        """Get all malware families with counts"""
        es = await self._get_client()

        try:
            result = await es.search(index=YARA_INDEX, body={
                "size": 0,
                "aggs": {
                    "families": {
                        "terms": {"field": "malware_family.keyword", "size": 500}
                    }
                }
            })

            return [
                {"malware_family": b["key"], "count": b["doc_count"]}
                for b in result.get("aggregations", {}).get("families", {}).get("buckets", [])
            ]
        except Exception as e:
            logger.error(f"Error getting malware families: {e}")
            return []

    # ============================================================
    # MIGRATION METHODS
    # ============================================================

    async def migrate_from_postgresql(self, db: AsyncSession, batch_size: int = 500) -> Dict[str, int]:
        """Migrate YARA rules from PostgreSQL (Signature Base) to Elasticsearch"""
        es = await self._get_client()
        await self.ensure_index()

        logger.info("Starting migration from PostgreSQL...")

        # Get all rules from PostgreSQL
        stmt = select(YARARule).where(YARARule.is_active == True)
        result = await db.execute(stmt)
        rules = result.scalars().all()

        total = len(rules)
        migrated = 0
        errors = 0

        # Process in batches
        for i in range(0, total, batch_size):
            batch = rules[i:i + batch_size]
            actions = []

            for rule in batch:
                doc_id = f"sigbase_{rule.id}"
                doc = {
                    "rule_id": str(rule.id),
                    "rule_name": rule.rule_name,
                    "rule_hash": rule.rule_hash,
                    "source": "signature_base",
                    "source_file": rule.source_file,
                    "source_url": rule.source_url,
                    "category": rule.category or "other",
                    "threat_name": rule.threat_name,
                    "threat_actor": rule.threat_actor,
                    "malware_family": None,  # Signature Base doesn't have this directly
                    "malware_aliases": [],
                    "rule_content": rule.rule_content,
                    "description": rule.description,
                    "author": rule.author,
                    "references": rule.reference or [],
                    "date": rule.date,
                    "version": rule.version,
                    "tags": rule.tags or [],
                    "mitre_attack": rule.mitre_attack or [],
                    "severity": rule.severity,
                    "strings_count": rule.strings_count or 0,
                    "is_active": rule.is_active,
                    "synced_at": rule.synced_at.isoformat() if rule.synced_at else None,
                    "created_at": rule.created_at.isoformat() if rule.created_at else None,
                    "updated_at": rule.updated_at.isoformat() if rule.updated_at else None
                }

                actions.append({"index": {"_index": YARA_INDEX, "_id": doc_id}})
                actions.append(doc)

            # Bulk index
            if actions:
                try:
                    response = await es.bulk(body=actions, refresh=False)
                    if response.get("errors"):
                        for item in response.get("items", []):
                            if "error" in item.get("index", {}):
                                errors += 1
                                logger.error(f"Bulk error: {item['index']['error']}")
                            else:
                                migrated += 1
                    else:
                        migrated += len(batch)
                except Exception as e:
                    logger.error(f"Batch error: {e}")
                    errors += len(batch)

            logger.info(f"Progress: {min(i + batch_size, total)}/{total}")

        # Refresh index
        await es.indices.refresh(index=YARA_INDEX)

        logger.info(f"PostgreSQL migration complete: {migrated} migrated, {errors} errors")
        return {"source": "signature_base", "total": total, "migrated": migrated, "errors": errors}

    async def migrate_from_malpedia(self, batch_size: int = 100) -> Dict[str, int]:
        """Extract and migrate YARA rules from Malpedia families in Elasticsearch"""
        es = await self._get_client()
        await self.ensure_index()

        logger.info("Starting migration from Malpedia...")

        # Scroll through all Malpedia families with YARA rules
        query = {
            "query": {
                "exists": {"field": "yara_rules.nome"}
            },
            "_source": ["name", "aka", "actors", "yara_rules", "os", "descricao"]
        }

        total_rules = 0
        migrated = 0
        errors = 0

        # Use scroll API for large result sets
        try:
            response = await es.search(
                index="malpedia_families",
                body=query,
                scroll="5m",
                size=batch_size
            )
        except Exception as e:
            logger.error(f"Error querying Malpedia: {e}")
            return {"source": "malpedia", "total": 0, "migrated": 0, "errors": 1}

        scroll_id = response.get("_scroll_id")
        hits = response.get("hits", {}).get("hits", [])

        while hits:
            actions = []

            for hit in hits:
                family = hit["_source"]
                family_name = family.get("name", "unknown")
                family_aka = family.get("aka", [])
                family_actors = family.get("actors", [])
                family_os = family.get("os", "")
                family_desc = family.get("descricao", "")

                yara_rules = family.get("yara_rules", [])

                for rule in yara_rules:
                    total_rules += 1
                    rule_name = rule.get("nome", "")
                    rule_content = rule.get("conteudo", "")
                    rule_url = rule.get("url", "")

                    if not rule_name or not rule_content:
                        errors += 1
                        continue

                    # Generate unique ID
                    rule_hash = hashlib.md5(rule_content.encode()).hexdigest()
                    doc_id = f"malpedia_{rule_hash[:16]}"

                    # Extract metadata from rule content
                    author = ""
                    description = family_desc[:500] if family_desc else f"YARA rule for {family_name}"
                    date = ""
                    tags = []

                    # Parse metadata from rule
                    if "author" in rule_content.lower():
                        for line in rule_content.split("\n"):
                            if "author" in line.lower() and "=" in line:
                                author = line.split("=")[-1].strip().strip('"').strip("'")
                                break

                    if "date" in rule_content.lower():
                        for line in rule_content.split("\n"):
                            if "date" in line.lower() and "=" in line:
                                date = line.split("=")[-1].strip().strip('"').strip("'")
                                break

                    # Determine category from OS
                    category = "malware"
                    if family_os:
                        category = f"malware_{family_os.lower()}"

                    doc = {
                        "rule_id": doc_id,
                        "rule_name": rule_name.replace(".yar", ""),
                        "rule_hash": rule_hash,
                        "source": "malpedia",
                        "source_file": rule_name,
                        "source_url": rule_url,
                        "category": category,
                        "threat_name": family_name,
                        "threat_actor": family_actors[0] if family_actors else None,
                        "malware_family": family_name,
                        "malware_aliases": family_aka,
                        "rule_content": rule_content,
                        "description": description,
                        "author": author,
                        "references": [rule_url] if rule_url else [],
                        "date": date,
                        "version": None,
                        "tags": tags,
                        "mitre_attack": [],
                        "severity": "medium",
                        "strings_count": rule_content.count("$"),
                        "is_active": True,
                        "synced_at": datetime.utcnow().isoformat(),
                        "created_at": datetime.utcnow().isoformat(),
                        "updated_at": datetime.utcnow().isoformat()
                    }

                    actions.append({"index": {"_index": YARA_INDEX, "_id": doc_id}})
                    actions.append(doc)

            # Bulk index
            if actions:
                try:
                    response = await es.bulk(body=actions, refresh=False)
                    if response.get("errors"):
                        for item in response.get("items", []):
                            if "error" in item.get("index", {}):
                                errors += 1
                            else:
                                migrated += 1
                    else:
                        migrated += len(actions) // 2
                except Exception as e:
                    logger.error(f"Batch error: {e}")
                    errors += len(actions) // 2

            logger.info(f"Malpedia progress: {migrated}/{total_rules} rules")

            # Get next batch
            try:
                response = await es.scroll(scroll_id=scroll_id, scroll="5m")
                hits = response.get("hits", {}).get("hits", [])
            except Exception as e:
                logger.error(f"Scroll error: {e}")
                break

        # Clear scroll
        try:
            await es.clear_scroll(scroll_id=scroll_id)
        except:
            pass

        # Refresh index
        await es.indices.refresh(index=YARA_INDEX)

        logger.info(f"Malpedia migration complete: {migrated} migrated, {errors} errors")
        return {"source": "malpedia", "total": total_rules, "migrated": migrated, "errors": errors}


# ============================================================
# STANDALONE MIGRATION FUNCTIONS
# ============================================================

async def run_full_yara_migration():
    """Run full migration from both sources"""
    from app.db.database import AsyncSessionLocal

    service = YARAElasticsearchService()

    try:
        # Ensure index exists
        await service.ensure_index()

        results = []

        # Migrate from PostgreSQL (Signature Base)
        async with AsyncSessionLocal() as db:
            pg_result = await service.migrate_from_postgresql(db)
            results.append(pg_result)

        # Migrate from Malpedia
        mp_result = await service.migrate_from_malpedia()
        results.append(mp_result)

        # Get final stats
        stats = await service.get_stats()

        return {
            "status": "success",
            "migrations": results,
            "final_stats": stats
        }

    finally:
        await service.close()
