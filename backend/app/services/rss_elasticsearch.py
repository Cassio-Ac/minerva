"""
RSS Elasticsearch Service
Manages Elasticsearch index for RSS articles with ILM
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import NotFoundError

logger = logging.getLogger(__name__)


class RSSElasticsearchService:
    """Service for RSS articles in Elasticsearch"""

    def __init__(self, es_client: Elasticsearch, index_alias: str = "rss-articles"):
        self.es = es_client
        self.index_alias = index_alias
        self.ilm_policy_name = f"{index_alias}-ilm"
        self.template_name = f"{index_alias}-template"

    def ensure_ilm_policy(self, rollover_days: int = 30, delete_days: int = 180) -> None:
        """
        Create or update ILM policy for RSS articles

        Args:
            rollover_days: Days before rollover (default: 30)
            delete_days: Days before deletion (default: 180)
        """
        try:
            policy = {
                "policy": {
                    "phases": {
                        "hot": {
                            "actions": {
                                "rollover": {
                                    "max_age": f"{rollover_days}d",
                                    "max_size": "20gb"
                                }
                            }
                        },
                        "delete": {
                            "min_age": f"{delete_days}d",
                            "actions": {
                                "delete": {}
                            }
                        }
                    }
                }
            }

            self.es.ilm.put_lifecycle(
                name=self.ilm_policy_name,
                body=policy
            )
            logger.info(f"✅ ILM policy '{self.ilm_policy_name}' created/updated")

        except Exception as e:
            logger.error(f"❌ Error creating ILM policy: {e}")
            raise

    def ensure_index_template(self, shards: int = 1, replicas: int = 1) -> None:
        """
        Create or update index template for RSS articles

        Args:
            shards: Number of primary shards (default: 1)
            replicas: Number of replicas (default: 1)
        """
        try:
            template = {
                "index_patterns": [f"{self.index_alias}-*"],
                "template": {
                    "settings": {
                        "number_of_shards": shards,
                        "number_of_replicas": replicas,
                        "index.refresh_interval": "5s",
                        "index.lifecycle.name": self.ilm_policy_name,
                        "index.lifecycle.rollover_alias": self.index_alias,
                        "analysis": {
                            "analyzer": {
                                "default": {
                                    "type": "standard",
                                    "stopwords": "_english_"
                                }
                            }
                        }
                    },
                    "mappings": {
                        "properties": {
                            # Timestamps
                            "@timestamp": {"type": "date"},
                            "published": {"type": "date"},
                            "collected_at": {"type": "date"},

                            # Article content
                            "title": {
                                "type": "text",
                                "fields": {
                                    "keyword": {"type": "keyword", "ignore_above": 256}
                                }
                            },
                            "link": {"type": "keyword"},
                            "summary": {"type": "text"},
                            "author": {"type": "keyword"},
                            "tags": {"type": "keyword"},
                            "content_hash": {"type": "keyword"},

                            # Feed metadata
                            "feed_name": {"type": "keyword"},
                            "feed_title": {
                                "type": "text",
                                "fields": {
                                    "keyword": {"type": "keyword", "ignore_above": 256}
                                }
                            },
                            "feed_link": {"type": "keyword"},
                            "feed_description": {"type": "text"},
                            "feed_updated": {"type": "date"},

                            # Categorization
                            "category": {"type": "keyword"},
                            "source_type": {"type": "keyword"},

                            # NLP enrichment (optional)
                            "sentiment": {"type": "keyword"},
                            "entities": {"type": "keyword"},
                            "keywords": {"type": "keyword"},

                            # Vector search (optional - for future)
                            # "embedding": {"type": "dense_vector", "dims": 768}
                        }
                    }
                }
            }

            self.es.indices.put_index_template(
                name=self.template_name,
                body=template
            )
            logger.info(f"✅ Index template '{self.template_name}' created/updated")

        except Exception as e:
            logger.error(f"❌ Error creating index template: {e}")
            raise

    def ensure_initial_index(self) -> None:
        """Create initial index with write alias if doesn't exist"""
        try:
            # Check if alias exists
            if not self.es.indices.exists_alias(name=self.index_alias):
                # Create first index
                index_name = f"{self.index_alias}-000001"

                self.es.indices.create(
                    index=index_name,
                    body={
                        "aliases": {
                            self.index_alias: {
                                "is_write_index": True
                            }
                        }
                    }
                )
                logger.info(f"✅ Initial index '{index_name}' created with alias '{self.index_alias}'")
            else:
                logger.info(f"✅ Alias '{self.index_alias}' already exists")

        except Exception as e:
            logger.error(f"❌ Error creating initial index: {e}")
            raise

    def setup(self, rollover_days: int = 30, delete_days: int = 180,
              shards: int = 1, replicas: int = 1) -> Dict[str, Any]:
        """
        Complete setup: ILM + Template + Initial Index

        Returns:
            Status dict with results
        """
        result = {
            "ilm_created": False,
            "template_created": False,
            "index_created": False,
            "errors": []
        }

        try:
            # 1. ILM Policy
            self.ensure_ilm_policy(rollover_days, delete_days)
            result["ilm_created"] = True

            # 2. Index Template
            self.ensure_index_template(shards, replicas)
            result["template_created"] = True

            # 3. Initial Index
            self.ensure_initial_index()
            result["index_created"] = True

            logger.info("✅ RSS Elasticsearch setup completed successfully")

        except Exception as e:
            error_msg = f"Setup error: {str(e)}"
            result["errors"].append(error_msg)
            logger.error(f"❌ {error_msg}")

        return result

    def bulk_index_articles(self, articles: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Bulk index articles to Elasticsearch

        Args:
            articles: List of article dicts

        Returns:
            Stats: created, updated, failed
        """
        if not articles:
            return {"created": 0, "updated": 0, "failed": 0}

        actions = []
        for article in articles:
            # Use content_hash as document ID for deduplication
            doc_id = article.get("content_hash")

            # Add @timestamp if not present
            if "@timestamp" not in article:
                article["@timestamp"] = article.get("published") or datetime.now(timezone.utc).isoformat()

            # Allow upsert via op_type param (default: create for deduplication)
            op_type = article.pop("_es_op_type", "create")

            actions.append({
                "_index": self.index_alias,
                "_id": doc_id,
                "_op_type": op_type,  # "create" (fail if exists) or "index" (upsert)
                "_source": article
            })

        # Bulk insert
        try:
            success_count, failed_items = helpers.bulk(
                self.es,
                actions,
                raise_on_error=False,
                stats_only=False  # Get detailed error info
            )

            # Process failed items to understand why they failed
            failed_count = len(failed_items)

            # Log first few failures for debugging
            if failed_items:
                for i, failed_item in enumerate(failed_items[:3]):  # Show first 3 errors
                    error_info = failed_item.get('create', {}).get('error', {})
                    error_type = error_info.get('type', 'unknown')
                    error_reason = error_info.get('reason', 'no reason provided')
                    doc_id = failed_item.get('create', {}).get('_id', 'unknown')
                    logger.warning(f"⚠️ Failed to index [{i+1}]: ID={doc_id[:16]}... | Type={error_type} | Reason={error_reason}")

            created = success_count

            logger.info(f"📤 Bulk index: {created} created, 0 updated, {failed_count} failed")

            return {
                "created": created,
                "updated": 0,
                "failed": failed_count
            }

        except Exception as e:
            logger.error(f"❌ Bulk index error: {e}")
            return {"created": 0, "updated": 0, "failed": len(articles)}

    def search_articles(
        self,
        query: Optional[str] = None,
        categories: Optional[List[str]] = None,
        feed_names: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        sentiment: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: str = "published",
        sort_order: str = "desc"
    ) -> Dict[str, Any]:
        """
        Search RSS articles with filters and aggregations

        Returns:
            Dict with: total, articles, facets, took_ms
        """
        # Build query
        must_clauses = []
        filter_clauses = []

        # Full-text search
        if query:
            # Use simple_query_string for better compatibility with Portuguese text
            # and user-friendly query parsing (no need to escape special chars)
            must_clauses.append({
                "simple_query_string": {
                    "query": query,
                    "fields": ["title^3", "summary^2", "feed_description"],
                    "default_operator": "OR",
                    "analyze_wildcard": True,
                    "fuzzy_max_expansions": 50,
                    "fuzzy_prefix_length": 2
                }
            })

        # Category filter
        if categories:
            filter_clauses.append({"terms": {"category": categories}})

        # Feed names filter
        if feed_names:
            filter_clauses.append({"terms": {"feed_name": feed_names}})

        # Tags filter
        if tags:
            filter_clauses.append({"terms": {"tags": tags}})

        # Date range
        if date_from or date_to:
            range_query = {}
            if date_from:
                range_query["gte"] = date_from.isoformat()
            if date_to:
                range_query["lte"] = date_to.isoformat()
            filter_clauses.append({"range": {"published": range_query}})

        # Sentiment filter
        if sentiment:
            filter_clauses.append({"term": {"sentiment": sentiment}})

        # Construct bool query
        es_query = {
            "bool": {
                "must": must_clauses if must_clauses else [{"match_all": {}}],
                "filter": filter_clauses
            }
        }

        # Build search body
        search_body = {
            "query": es_query,
            "from": offset,
            "size": limit,
            "sort": [{sort_by: {"order": sort_order}}],
            "_source": {
                "excludes": ["embedding"]  # Exclude vectors if present
            },
            # Aggregations for facets
            "aggs": {
                "by_category": {
                    "terms": {"field": "category.keyword", "size": 20}
                },
                "by_feed": {
                    "terms": {"field": "feed_name.keyword", "size": 50}
                },
                "by_tag": {
                    "terms": {"field": "tags.keyword", "size": 30}
                },
                "by_date": {
                    "date_histogram": {
                        "field": "published",
                        "calendar_interval": "day",
                        "min_doc_count": 1
                    }
                }
            }
        }

        try:
            response = self.es.search(
                index=self.index_alias,
                body=search_body
            )

            # Parse results
            hits = response["hits"]
            total = hits["total"]["value"]
            articles = [hit["_source"] for hit in hits["hits"]]

            # Parse aggregations
            aggs = response.get("aggregations", {})
            facets = {
                "categories": [
                    {"key": b["key"], "count": b["doc_count"]}
                    for b in aggs.get("by_category", {}).get("buckets", [])
                ],
                "feeds": [
                    {"key": b["key"], "count": b["doc_count"]}
                    for b in aggs.get("by_feed", {}).get("buckets", [])
                ],
                "tags": [
                    {"key": b["key"], "count": b["doc_count"]}
                    for b in aggs.get("by_tag", {}).get("buckets", [])
                ],
                "timeline": [
                    {"date": b["key_as_string"], "count": b["doc_count"]}
                    for b in aggs.get("by_date", {}).get("buckets", [])
                ]
            }

            return {
                "total": total,
                "articles": articles,
                "facets": facets,
                "took_ms": response["took"]
            }

        except Exception as e:
            logger.error(f"❌ Search error: {e}")
            return {
                "total": 0,
                "articles": [],
                "facets": {},
                "took_ms": 0
            }

    def get_stats(self) -> Dict[str, Any]:
        """Get global statistics for dashboard widgets"""
        try:
            # Total count
            count_result = self.es.count(index=self.index_alias)
            total = count_result["count"]

            # Today, this week, this month
            now = datetime.now(timezone.utc)
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            from datetime import timedelta
            week_start = today_start - timedelta(days=7)
            month_start = today_start.replace(day=1)
            days_30_ago = today_start - timedelta(days=30)

            stats_query = {
                "size": 0,
                "aggs": {
                    "today": {
                        "filter": {
                            "range": {"published": {"gte": today_start.isoformat()}}
                        }
                    },
                    "this_week": {
                        "filter": {
                            "range": {"published": {"gte": week_start.isoformat()}}
                        }
                    },
                    "this_month": {
                        "filter": {
                            "range": {"published": {"gte": month_start.isoformat()}}
                        }
                    },
                    "by_category": {
                        "terms": {"field": "category.keyword", "size": 20}
                    },
                    "top_feeds": {
                        "terms": {"field": "feed_name.keyword", "size": 10, "order": {"_count": "desc"}}
                    },
                    "all_feeds": {
                        "terms": {"field": "feed_name.keyword", "size": 100, "order": {"_key": "asc"}}
                    },
                    "timeline_30d": {
                        "filter": {
                            "range": {
                                "published": {
                                    "gte": days_30_ago.isoformat(),
                                    "lte": now.isoformat()  # Exclude future dates
                                }
                            }
                        },
                        "aggs": {
                            "daily_counts": {
                                "date_histogram": {
                                    "field": "published",
                                    "calendar_interval": "day",
                                    "format": "yyyy-MM-dd",
                                    "min_doc_count": 0,
                                    "extended_bounds": {
                                        "min": days_30_ago.strftime("%Y-%m-%d"),
                                        "max": now.strftime("%Y-%m-%d")
                                    }
                                }
                            }
                        }
                    }
                }
            }

            response = self.es.search(index=self.index_alias, body=stats_query)
            aggs = response["aggregations"]

            return {
                "total_articles": total,
                "articles_today": aggs["today"]["doc_count"],
                "articles_this_week": aggs["this_week"]["doc_count"],
                "articles_this_month": aggs["this_month"]["doc_count"],
                "articles_by_category": {
                    b["key"]: b["doc_count"]
                    for b in aggs["by_category"]["buckets"]
                },
                "top_sources": [
                    {"name": b["key"], "count": b["doc_count"]}
                    for b in aggs["top_feeds"]["buckets"]
                ],
                "all_sources": [
                    {"name": b["key"], "count": b["doc_count"]}
                    for b in aggs["all_feeds"]["buckets"]
                ],
                "timeline": [
                    {"date": b["key_as_string"], "count": b["doc_count"]}
                    for b in aggs["timeline_30d"]["daily_counts"]["buckets"]
                ]
            }

        except Exception as e:
            logger.error(f"❌ Stats error: {e}")
            return {}

    async def check_duplicate(self, content_hash: str) -> bool:
        """Check if article with content_hash already exists"""
        try:
            response = self.es.exists(index=self.index_alias, id=content_hash)
            return response
        except NotFoundError:
            return False
        except Exception as e:
            logger.error(f"❌ Duplicate check error: {e}")
            return False
