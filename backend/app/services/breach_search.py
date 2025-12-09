"""
Breach Search Service
Searches breachdetect_v3 index for data leaks and breaches
"""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch

logger = logging.getLogger(__name__)


class BreachSearchService:
    """Service for searching breach/data leak entries"""

    def __init__(self, es_client: Elasticsearch, index_name: str = "breachdetect_v3"):
        self.es = es_client
        self.index_name = index_name

    def search_breaches(
        self,
        query: Optional[str] = None,
        sources: Optional[List[str]] = None,
        types: Optional[List[str]] = None,
        authors: Optional[List[str]] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: str = "date",
        sort_order: str = "desc"
    ) -> Dict[str, Any]:
        """
        Search breaches with filters and facets

        Returns:
            Dict with: total, breaches, facets, took_ms
        """
        # Build query
        must_clauses = []
        filter_clauses = []

        # Full-text search
        if query:
            must_clauses.append({
                "multi_match": {
                    "query": query,
                    "fields": ["breach_content^3", "breach_author^2", "breach_source"],
                    "type": "best_fields",
                    "fuzziness": "AUTO"
                }
            })

        # Source filter
        if sources:
            filter_clauses.append({"terms": {"breach_source.keyword": sources}})

        # Type filter
        if types:
            filter_clauses.append({"terms": {"breach_type": types}})

        # Author filter
        if authors:
            filter_clauses.append({"terms": {"breach_author": authors}})

        # Date range
        if date_from or date_to:
            range_query = {}
            if date_from:
                range_query["gte"] = date_from.isoformat()
            if date_to:
                range_query["lte"] = date_to.isoformat()
            filter_clauses.append({"range": {"date": range_query}})

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
            # Aggregations for facets
            "aggs": {
                "by_source": {
                    "terms": {"field": "breach_source.keyword", "size": 50}
                },
                "by_type": {
                    "terms": {"field": "breach_type", "size": 20}
                },
                "by_author": {
                    "terms": {"field": "breach_author", "size": 50}
                },
                "by_date": {
                    "date_histogram": {
                        "field": "date",
                        "calendar_interval": "day",
                        "min_doc_count": 1
                    }
                }
            }
        }

        try:
            response = self.es.search(
                index=self.index_name,
                body=search_body
            )

            # Parse results
            hits = response["hits"]
            total = hits["total"]["value"]
            breaches = [hit["_source"] for hit in hits["hits"]]

            # Parse aggregations
            aggs = response.get("aggregations", {})
            facets = {
                "sources": [
                    {"key": b["key"], "count": b["doc_count"]}
                    for b in aggs.get("by_source", {}).get("buckets", [])
                ],
                "types": [
                    {"key": b["key"], "count": b["doc_count"]}
                    for b in aggs.get("by_type", {}).get("buckets", [])
                ],
                "authors": [
                    {"key": b["key"], "count": b["doc_count"]}
                    for b in aggs.get("by_author", {}).get("buckets", [])
                ],
                "timeline": [
                    {"date": b["key_as_string"], "count": b["doc_count"]}
                    for b in aggs.get("by_date", {}).get("buckets", [])
                ]
            }

            return {
                "total": total,
                "breaches": breaches,
                "facets": facets,
                "took_ms": response["took"]
            }

        except Exception as e:
            logger.error(f"❌ Breach search error: {e}")
            return {
                "total": 0,
                "breaches": [],
                "facets": {},
                "took_ms": 0
            }

    def get_stats(self) -> Dict[str, Any]:
        """Get global breach statistics"""
        try:
            # Total count
            count_result = self.es.count(index=self.index_name)
            total = count_result["count"]

            # Today, this week, this month
            now = datetime.now(timezone.utc)
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            week_start = today_start - timedelta(days=7)
            month_start = today_start.replace(day=1)
            days_30_ago = today_start - timedelta(days=30)

            stats_query = {
                "size": 0,
                "aggs": {
                    "today": {
                        "filter": {
                            "range": {"date": {"gte": today_start.isoformat()}}
                        }
                    },
                    "this_week": {
                        "filter": {
                            "range": {"date": {"gte": week_start.isoformat()}}
                        }
                    },
                    "this_month": {
                        "filter": {
                            "range": {"date": {"gte": month_start.isoformat()}}
                        }
                    },
                    "by_type": {
                        "terms": {"field": "breach_type", "size": 20}
                    },
                    "top_sources": {
                        "terms": {"field": "breach_source.keyword", "size": 10, "order": {"_count": "desc"}}
                    },
                    "top_authors": {
                        "terms": {"field": "breach_author", "size": 10, "order": {"_count": "desc"}}
                    },
                    "timeline_30d": {
                        "filter": {
                            "range": {"date": {"gte": days_30_ago.isoformat()}}
                        },
                        "aggs": {
                            "daily_counts": {
                                "date_histogram": {
                                    "field": "date",
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

            response = self.es.search(index=self.index_name, body=stats_query)
            aggs = response["aggregations"]

            return {
                "total_breaches": total,
                "breaches_today": aggs["today"]["doc_count"],
                "breaches_this_week": aggs["this_week"]["doc_count"],
                "breaches_this_month": aggs["this_month"]["doc_count"],
                "breaches_by_type": {
                    b["key"]: b["doc_count"]
                    for b in aggs["by_type"]["buckets"]
                },
                "top_sources": [
                    {"name": b["key"], "count": b["doc_count"]}
                    for b in aggs["top_sources"]["buckets"]
                ],
                "top_authors": [
                    {"name": b["key"], "count": b["doc_count"]}
                    for b in aggs["top_authors"]["buckets"]
                ],
                "timeline": [
                    {"date": b["key_as_string"], "count": b["doc_count"]}
                    for b in aggs["timeline_30d"]["daily_counts"]["buckets"]
                ]
            }

        except Exception as e:
            logger.error(f"❌ Breach stats error: {e}")
            return {}
